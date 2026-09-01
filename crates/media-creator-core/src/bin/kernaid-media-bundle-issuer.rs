#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use kernaid_media_creator_core::{
    CATALOG_NAME, CATALOG_SCHEMA, QUALIFICATION_NAME, RELEASE_BUNDLE_MANIFEST_NAME,
    RELEASE_BUNDLE_SCHEMA, RELEASE_BUNDLE_SIGNING_DOMAIN, RETAIL_METADATA_NAME, RETAIL_NAME,
    authorize_release, authorize_release_bundle,
};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RETAIL_BYTES: u64 = 1_999_999_998;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const ED25519_SEED_BYTES: usize = 32;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedBundleManifest {
    schema: &'static str,
    artifact_version: String,
    files: BundleFiles,
    key_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleFiles {
    catalog_entry: FileDescriptor,
    qualification: FileDescriptor,
    retail_image: FileDescriptor,
    retail_metadata: FileDescriptor,
}

#[derive(Serialize)]
struct FileDescriptor {
    name: &'static str,
    bytes: u64,
    sha256: String,
}

enum Operation {
    GenerateKey {
        seed_output: PathBuf,
        public_output: PathBuf,
    },
    PublicKey {
        seed: PathBuf,
    },
    IssueBundle {
        seed: PathBuf,
        release_directory: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    match parse_arguments(env::args_os().skip(1))? {
        Operation::GenerateKey {
            seed_output,
            public_output,
        } => generate_key(&seed_output, &public_output),
        Operation::PublicKey { seed } => {
            let signing_key = read_signing_key(&seed)?;
            println!(
                "{}",
                URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
            );
            Ok(())
        }
        Operation::IssueBundle {
            seed,
            release_directory,
        } => issue_bundle(&seed, &release_directory),
    }
}

fn generate_key(seed_output: &Path, public_output: &Path) -> Result<(), &'static str> {
    if seed_output == public_output {
        return Err("seed and public-key outputs must be different");
    }
    require_absent(seed_output)?;
    require_absent(public_output)?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let seed = Zeroizing::new(URL_SAFE_NO_PAD.encode(signing_key.to_bytes()));
    let public = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    write_new(seed_output, seed.as_bytes(), 0o600)?;
    if let Err(error) = write_new(public_output, public.as_bytes(), 0o644) {
        let _ = fs::remove_file(seed_output);
        return Err(error);
    }
    Ok(())
}

fn issue_bundle(seed_path: &Path, release_directory: &Path) -> Result<(), &'static str> {
    require_directory(release_directory)?;
    let output = release_directory.join(RELEASE_BUNDLE_MANIFEST_NAME);
    require_absent(&output)?;

    let signing_key = read_signing_key(seed_path)?;
    let catalog_entry = read_bounded_regular(
        &release_directory.join(CATALOG_NAME),
        MAX_JSON_BYTES,
        "catalog entry",
    )?;
    let qualification = read_bounded_regular(
        &release_directory.join(QUALIFICATION_NAME),
        MAX_JSON_BYTES,
        "qualification manifest",
    )?;
    let retail_metadata = read_bounded_regular(
        &release_directory.join(RETAIL_METADATA_NAME),
        MAX_JSON_BYTES,
        "retail metadata",
    )?;
    let retail_descriptor = hash_bounded_regular(
        &release_directory.join(RETAIL_NAME),
        MAX_RETAIL_BYTES,
        RETAIL_NAME,
    )?;

    // A one-entry catalog is not a replacement trust anchor. It lets the
    // offline issuer reuse the consumer's exact cross-member validation before
    // signing; the Windows build still independently embeds the approved
    // catalog and public key.
    let catalog_value: Value =
        serde_json::from_slice(&catalog_entry).map_err(|_| "catalog entry JSON is invalid")?;
    let local_catalog = canonical_json(&json!({
        "catalogRevision": 1,
        "images": [catalog_value],
        "schema": CATALOG_SCHEMA
    }))?;
    let authorized = authorize_release(
        local_catalog.as_bytes(),
        &catalog_entry,
        &qualification,
        &retail_metadata,
    )
    .map_err(|_| "release members are not a coherent qualified release")?;
    if authorized.compressed_bytes() != retail_descriptor.bytes
        || authorized.compressed_sha256() != retail_descriptor.sha256
    {
        return Err("retail image differs from its qualification metadata");
    }

    let public_key = signing_key.verifying_key().to_bytes();
    let unsigned = UnsignedBundleManifest {
        schema: RELEASE_BUNDLE_SCHEMA,
        artifact_version: authorized.artifact_version().to_owned(),
        files: BundleFiles {
            catalog_entry: descriptor(CATALOG_NAME, &catalog_entry),
            qualification: descriptor(QUALIFICATION_NAME, &qualification),
            retail_image: retail_descriptor,
            retail_metadata: descriptor(RETAIL_METADATA_NAME, &retail_metadata),
        },
        key_id: format!("sha256:{}", sha256_hex(&public_key)),
    };
    let mut manifest = serde_json::to_value(unsigned).map_err(|_| "bundle could not be encoded")?;
    let unsigned_bytes = canonical_json(&manifest)?;
    let mut message = Vec::with_capacity(
        RELEASE_BUNDLE_SIGNING_DOMAIN
            .len()
            .saturating_add(unsigned_bytes.len()),
    );
    message.extend_from_slice(RELEASE_BUNDLE_SIGNING_DOMAIN);
    message.extend_from_slice(unsigned_bytes.as_bytes());
    manifest
        .as_object_mut()
        .ok_or("bundle root could not be encoded")?
        .insert(
            "signature".to_owned(),
            Value::String(URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes())),
        );
    let document = canonical_json(&manifest)?.into_bytes();

    authorize_release_bundle(
        local_catalog.as_bytes(),
        &document,
        &public_key,
        &catalog_entry,
        &qualification,
        &retail_metadata,
    )
    .map_err(|_| "internal bundle verification failed")?;
    write_new(&output, &document, 0o644)
}

fn descriptor(name: &'static str, bytes: &[u8]) -> FileDescriptor {
    FileDescriptor {
        name,
        bytes: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

fn hash_bounded_regular(
    path: &Path,
    maximum: u64,
    name: &'static str,
) -> Result<FileDescriptor, &'static str> {
    let (mut file, expected_bytes) = open_bounded_regular(path, maximum, "retail image")?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "could not read retail image")?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or("retail image size overflow")?;
        if total > maximum {
            return Err("retail image exceeds its size bound");
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected_bytes {
        return Err("retail image changed while it was being read");
    }
    Ok(FileDescriptor {
        name,
        bytes: total,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn read_bounded_regular(
    path: &Path,
    maximum: u64,
    label: &'static str,
) -> Result<Vec<u8>, &'static str> {
    let (mut file, expected_bytes) = open_bounded_regular(path, maximum, label)?;
    let capacity = usize::try_from(expected_bytes).map_err(|_| "input size is unsupported")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| "could not read release input")?;
    if bytes.len() as u64 != expected_bytes {
        return Err("release input changed while it was being read");
    }
    Ok(bytes)
}

fn open_bounded_regular(
    path: &Path,
    maximum: u64,
    label: &'static str,
) -> Result<(File, u64), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect release input")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(match label {
            "retail image" => "retail image must be a bounded regular non-symlink file",
            _ => "release JSON must be a bounded regular non-symlink file",
        });
    }
    let file = File::open(path).map_err(|_| "could not open release input")?;
    let opened = file
        .metadata()
        .map_err(|_| "could not inspect opened release input")?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err("release input changed before it was opened");
    }
    Ok((file, opened.len()))
}

fn read_signing_key(path: &Path) -> Result<SigningKey, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect signing seed")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("signing seed must be a regular non-symlink file");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("signing seed permissions must deny group and other access");
    }
    if metadata.len() == 0 || metadata.len() > 45 {
        return Err("signing seed is not canonical base64url");
    }

    let mut encoded =
        Zeroizing::new(fs::read_to_string(path).map_err(|_| "could not read signing seed")?);
    if encoded.ends_with('\n') {
        encoded.pop();
        if encoded.ends_with('\r') {
            encoded.pop();
        }
    }
    if encoded.len() != 43 {
        return Err("signing seed is not canonical base64url");
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| "signing seed is not canonical base64url")?,
    );
    if URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded.as_str() {
        return Err("signing seed is not canonical base64url");
    }
    let raw: [u8; ED25519_SEED_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| "signing seed has the wrong length")?;
    let bytes = Zeroizing::new(raw);
    Ok(SigningKey::from_bytes(&bytes))
}

fn canonical_json(value: &Value) -> Result<String, &'static str> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).map_err(|_| "bundle could not be encoded")
        }
        Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", items.join(",")))
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key).map_err(|_| "bundle could not be encoded")?,
                        canonical_json(&values[key])?
                    ))
                })
                .collect::<Result<Vec<_>, &'static str>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_directory(path: &Path) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect release directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("release directory must be a real non-symlink directory");
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), &'static str> {
    require_absent(path)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_directory(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .map_err(|_| "could not create output file")?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err("could not persist output file");
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "could not persist output directory")?;
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), &'static str> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err("output already exists"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("could not inspect output path"),
    }
}

fn parse_arguments(mut values: impl Iterator<Item = OsString>) -> Result<Operation, &'static str> {
    let command = values
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    let operation = match command.as_str() {
        "generate-key" => Operation::GenerateKey {
            seed_output: next_path(&mut values)?,
            public_output: next_path(&mut values)?,
        },
        "public-key" => Operation::PublicKey {
            seed: next_path(&mut values)?,
        },
        "issue-bundle" => Operation::IssueBundle {
            seed: next_path(&mut values)?,
            release_directory: next_path(&mut values)?,
        },
        _ => return Err(usage()),
    };
    if values.next().is_some() {
        return Err(usage());
    }
    Ok(operation)
}

fn next_path(values: &mut impl Iterator<Item = OsString>) -> Result<PathBuf, &'static str> {
    values.next().map(PathBuf::from).ok_or_else(usage)
}

const fn usage() -> &'static str {
    "Usage: kernaid-media-bundle-issuer generate-key <seed-output> <public-key-output> | public-key <seed> | issue-bundle <seed> <qualified-release-directory>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_media_creator_core::{
        ISO_NAME, QUALIFICATION_SCHEMA, RETAIL_SCHEMA, decode_release_bundle_trust_anchor,
    };
    use tempfile::tempdir;

    const RAW_NAME: &str = "KernAid-Rescue-amd64-retail.img";
    const RAW_BYTES: u64 = 32_000_000_000;
    const P3_START_BYTES: u64 = 17_179_869_184;
    const P3_BYTES: u64 = 8_589_934_592;
    const P3_ZERO_SHA256: &str = "ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25";

    fn write_qualified_fixture(directory: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let trusted =
            include_bytes!("../../../../tools/make-device/trusted-rescue-images.v2.json").to_vec();
        let catalog: Value = serde_json::from_slice(&trusted)?;
        let entry = catalog["images"][0].clone();
        let entry_bytes = serde_json::to_vec(&entry)?;
        let retail_image = b"qualified retail image fixture".repeat(4);
        let compressed_sha = sha256_hex(&retail_image);
        let raw_sha = "b".repeat(64);
        let metadata = json!({
            "compressed": {"bytes": retail_image.len(), "name": RETAIL_NAME, "sha256": compressed_sha},
            "isoPrefix": {"bytes": entry["bytes"], "sha256": entry["sha256"]},
            "p3": {"bytes": P3_BYTES, "sha256": P3_ZERO_SHA256, "startBytes": P3_START_BYTES, "zero": true},
            "raw": {"bytes": RAW_BYTES, "name": RAW_NAME, "sha256": raw_sha},
            "schema": RETAIL_SCHEMA,
            "tailZero": true
        });
        let metadata_bytes = serde_json::to_vec(&metadata)?;
        let qualification = json!({
            "artifactVersion": entry["artifactVersion"],
            "artifacts": {
                "catalogV2Entry": {"bytes": entry_bytes.len(), "name": CATALOG_NAME, "sha256": sha256_hex(&entry_bytes)},
                "codexSbomTranche": {"bytes": 1, "name": "KernAid-Rescue-amd64.codex.cdx.json", "sha256": "c".repeat(64)},
                "iso": {"bytes": entry["bytes"], "checksum": {"bytes": 1, "name": "KernAid-Rescue-amd64.iso.sha256", "sha256": "d".repeat(64)}, "name": ISO_NAME, "sha256": entry["sha256"]},
                "retailImage": {
                    "bytes": retail_image.len(),
                    "checksum": {"bytes": 1, "name": "KernAid-Rescue-amd64-retail.img.xz.sha256", "sha256": "e".repeat(64)},
                    "layout": metadata,
                    "metadata": {"bytes": metadata_bytes.len(), "name": RETAIL_METADATA_NAME, "sha256": sha256_hex(&metadata_bytes)},
                    "name": RETAIL_NAME,
                    "sha256": compressed_sha
                }
            },
            "evidence": {},
            "requiredJobs": ["build-and-smoke-test", "native-vault-prompt-bios", "vault-lifecycle-bios", "vault-lifecycle-uefi"],
            "schema": QUALIFICATION_SCHEMA,
            "source": {
                "commit": "0".repeat(40),
                "repository": "0xfunboy/KernAid",
                "workflow": ".github/workflows/rescue.yml",
                "workflowRunAttempt": 1,
                "workflowRunId": entry["qemuUsbBootAttestations"]["bios"]["workflowRunId"],
                "workflowRunUrl": entry["qemuUsbBootAttestations"]["bios"]["workflowRunUrl"]
            }
        });
        fs::write(directory.join(CATALOG_NAME), &entry_bytes)?;
        fs::write(
            directory.join(QUALIFICATION_NAME),
            serde_json::to_vec(&qualification)?,
        )?;
        fs::write(directory.join(RETAIL_METADATA_NAME), &metadata_bytes)?;
        fs::write(directory.join(RETAIL_NAME), retail_image)?;
        Ok(trusted)
    }

    #[test]
    fn issued_bundle_is_accepted_by_media_authorization_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let trusted = write_qualified_fixture(directory.path())?;
        let seed = directory.path().join("media.seed");
        let public = directory.path().join("media.public");
        generate_key(&seed, &public)?;
        issue_bundle(&seed, directory.path())?;

        let anchor_text = fs::read_to_string(public)?;
        let anchor = decode_release_bundle_trust_anchor(&anchor_text)?;
        let authorized = authorize_release_bundle(
            &trusted,
            &fs::read(directory.path().join(RELEASE_BUNDLE_MANIFEST_NAME))?,
            &anchor,
            &fs::read(directory.path().join(CATALOG_NAME))?,
            &fs::read(directory.path().join(QUALIFICATION_NAME))?,
            &fs::read(directory.path().join(RETAIL_METADATA_NAME))?,
        )?;
        assert!(authorized.artifact_version().starts_with("ci-"));
        #[cfg(unix)]
        assert_eq!(fs::metadata(seed)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
}
