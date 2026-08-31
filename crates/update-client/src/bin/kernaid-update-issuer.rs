#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use kernaid_update_client::{
    ArtifactDescriptor, ReleaseRing, Rollout, SignedUpdateManifest, UPDATE_MANIFEST_SCHEMA,
    UpdateArchitecture, UpdateManifestContent, UpdatePlatform,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const MAX_CONTENT_BYTES: u64 = 64 * 1024;
const ED25519_SEED_BYTES: usize = 32;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestInput {
    schema: String,
    sequence: u64,
    release_id: String,
    release_version: String,
    platform: UpdatePlatform,
    architecture: UpdateArchitecture,
    release_ring: ReleaseRing,
    rollout: Rollout,
    issued_at_unix: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
    artifact: ArtifactDescriptor,
    emergency_rollback: bool,
}

impl ManifestInput {
    fn into_content(self) -> Result<UpdateManifestContent, &'static str> {
        if self.schema != UPDATE_MANIFEST_SCHEMA {
            return Err("manifest content schema is invalid");
        }
        Ok(UpdateManifestContent {
            sequence: self.sequence,
            release_id: self.release_id,
            release_version: self.release_version,
            platform: self.platform,
            architecture: self.architecture,
            release_ring: self.release_ring,
            rollout: self.rollout,
            issued_at_unix: self.issued_at_unix,
            not_before_unix: self.not_before_unix,
            expires_at_unix: self.expires_at_unix,
            artifact: self.artifact,
            emergency_rollback: self.emergency_rollback,
        })
    }
}

enum Operation {
    GenerateKey {
        seed_output: PathBuf,
        public_output: PathBuf,
    },
    PublicKey {
        seed: PathBuf,
    },
    SignManifest {
        seed: PathBuf,
        content: PathBuf,
        output: PathBuf,
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
        Operation::SignManifest {
            seed,
            content,
            output,
        } => {
            let signing_key = read_signing_key(&seed)?;
            let content = read_canonical_content(&content)?.into_content()?;
            let signed = SignedUpdateManifest::sign(content, &signing_key)
                .map_err(|_| "manifest content was rejected")?;
            let document = signed
                .export_canonical()
                .map_err(|_| "signed manifest could not be encoded")?;
            write_new(&output, &document, 0o644)
        }
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

fn read_signing_key(path: &Path) -> Result<SigningKey, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect signing seed")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("signing seed must be a regular non-symlink file");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("signing seed permissions must deny group and other access");
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

fn read_canonical_content(path: &Path) -> Result<ManifestInput, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect content file")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CONTENT_BYTES
    {
        return Err("content file must be a bounded regular non-symlink file");
    }
    let document = fs::read(path).map_err(|_| "could not read content file")?;
    let content: ManifestInput =
        serde_json::from_slice(&document).map_err(|_| "content JSON is invalid")?;
    let canonical =
        serde_json::to_vec(&serde_json::to_value(&content).map_err(|_| "content JSON is invalid")?)
            .map_err(|_| "content JSON is invalid")?;
    if canonical != document {
        return Err("content JSON must be exact canonical JSON");
    }
    Ok(content)
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), &'static str> {
    require_absent(path)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| "could not inspect output parent")?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err("output parent must be a regular directory");
    }
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
        "sign-manifest" => Operation::SignManifest {
            seed: next_path(&mut values)?,
            content: next_path(&mut values)?,
            output: next_path(&mut values)?,
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
    "Usage: kernaid-update-issuer generate-key <seed-output> <public-key-output> | public-key <seed> | sign-manifest <seed> <canonical-content-json> <output>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_update_client::SignedUpdateManifest;
    use tempfile::tempdir;

    fn canonical_input() -> Vec<u8> {
        let input = ManifestInput {
            schema: UPDATE_MANIFEST_SCHEMA.to_owned(),
            sequence: 7,
            release_id: "kernaid-rescue-1.2.7".to_owned(),
            release_version: "1.2.7+build.4".to_owned(),
            platform: UpdatePlatform::Rescue,
            architecture: UpdateArchitecture::X86_64,
            release_ring: ReleaseRing::Stable,
            rollout: Rollout {
                basis_points: 10_000,
                seed: "stable-2026-08".to_owned(),
            },
            issued_at_unix: 1_800_000_000,
            not_before_unix: 1_800_000_100,
            expires_at_unix: 1_800_086_400,
            artifact: ArtifactDescriptor {
                url: "https://updates.kernaid.example/releases/1.2.7/image.raw".to_owned(),
                size_bytes: 4_096,
                sha256: "11".repeat(32),
            },
            emergency_rollback: false,
        };
        serde_json::to_vec(&serde_json::to_value(input).expect("input value"))
            .expect("canonical input")
    }

    #[test]
    fn offline_issuer_generates_and_signs_a_verifiable_manifest() {
        let directory = tempdir().expect("temporary directory");
        let seed = directory.path().join("update.seed");
        let public = directory.path().join("update.public");
        let content = directory.path().join("manifest-content.json");
        let output = directory.path().join("manifest.signed.json");
        generate_key(&seed, &public).expect("generate key");
        fs::write(&content, canonical_input()).expect("write content");

        let signing_key = read_signing_key(&seed).expect("read seed");
        let content = read_canonical_content(&content)
            .expect("read canonical content")
            .into_content()
            .expect("content schema");
        let signed = SignedUpdateManifest::sign(content, &signing_key).expect("sign manifest");
        let bytes = signed.export_canonical().expect("canonical manifest");
        write_new(&output, &bytes, 0o644).expect("write signed manifest");

        let verified = SignedUpdateManifest::import_and_verify(
            &fs::read(output).expect("read output"),
            &signing_key.verifying_key(),
        )
        .expect("verify signed manifest");
        assert_eq!(verified.sequence(), 7);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(seed)
                .expect("seed metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
