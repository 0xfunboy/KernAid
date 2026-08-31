#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use kernaid_entitlements::{
    EntitlementClaims, RevocationClaims, sign_entitlement, sign_revocations,
};
use rand_core::OsRng;
use serde::{Serialize, de::DeserializeOwned};
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

const MAX_CLAIMS_BYTES: u64 = 64 * 1024;
const ED25519_SEED_BYTES: usize = 32;

enum Operation {
    GenerateKey {
        seed_output: PathBuf,
        public_output: PathBuf,
    },
    PublicKey {
        seed: PathBuf,
    },
    SignEntitlement {
        seed: PathBuf,
        claims: PathBuf,
        output: PathBuf,
    },
    SignRevocations {
        seed: PathBuf,
        claims: PathBuf,
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
        Operation::SignEntitlement {
            seed,
            claims,
            output,
        } => {
            let signing_key = read_signing_key(&seed)?;
            let claims = read_canonical_claims::<EntitlementClaims>(&claims)?;
            let document = sign_entitlement(claims, &signing_key)
                .map_err(|_| "entitlement claims were rejected")?;
            write_new(&output, &document, 0o600)
        }
        Operation::SignRevocations {
            seed,
            claims,
            output,
        } => {
            let signing_key = read_signing_key(&seed)?;
            let claims = read_canonical_claims::<RevocationClaims>(&claims)?;
            let document = sign_revocations(claims, &signing_key)
                .map_err(|_| "revocation claims were rejected")?;
            write_new(&output, &document, 0o600)
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

fn read_canonical_claims<T>(path: &Path) -> Result<T, &'static str>
where
    T: DeserializeOwned + Serialize,
{
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect claims file")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CLAIMS_BYTES
    {
        return Err("claims file must be a bounded regular non-symlink file");
    }
    let document = fs::read(path).map_err(|_| "could not read claims file")?;
    let claims: T = serde_json::from_slice(&document).map_err(|_| "claims JSON is invalid")?;
    let canonical =
        serde_json::to_vec(&serde_json::to_value(&claims).map_err(|_| "claims JSON is invalid")?)
            .map_err(|_| "claims JSON is invalid")?;
    if canonical != document {
        return Err("claims JSON must be exact canonical JSON");
    }
    Ok(claims)
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
        "sign-entitlement" => Operation::SignEntitlement {
            seed: next_path(&mut values)?,
            claims: next_path(&mut values)?,
            output: next_path(&mut values)?,
        },
        "sign-revocations" => Operation::SignRevocations {
            seed: next_path(&mut values)?,
            claims: next_path(&mut values)?,
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
    "Usage: kernaid-entitlement-issuer generate-key <seed-output> <public-key-output> | public-key <seed> | sign-entitlement <seed> <canonical-claims-json> <output> | sign-revocations <seed> <canonical-claims-json> <output>"
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernaid_entitlements::{
        ENTITLEMENT_SCHEMA, EntitlementLimits, Feature, Plan, verify_entitlement,
    };
    use tempfile::tempdir;

    #[test]
    fn parser_accepts_only_exact_operations() {
        assert!(parse_arguments(["public-key", "seed"].into_iter().map(OsString::from)).is_ok());
        assert!(
            parse_arguments(
                ["sign-entitlement", "seed", "claims", "output"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_ok()
        );
        assert!(
            parse_arguments(
                ["sign-entitlement", "seed", "claims", "output", "extra"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
        assert!(parse_arguments(["unknown"].into_iter().map(OsString::from)).is_err());
    }

    #[test]
    fn offline_issuer_generates_and_signs_a_verifiable_document() {
        let directory = tempdir().expect("temporary directory");
        let seed = directory.path().join("issuer.seed");
        let public = directory.path().join("issuer.public");
        let claims_path = directory.path().join("claims.json");
        let output = directory.path().join("entitlement.json");
        generate_key(&seed, &public).expect("generate key");

        let claims = EntitlementClaims {
            schema: ENTITLEMENT_SCHEMA.to_owned(),
            entitlement_id: "ent_test_001".to_owned(),
            tenant_id: "tenant_test".to_owned(),
            sequence: 1,
            plan: Plan::Enterprise,
            features: vec![Feature::Audit, Feature::EnterpriseRepair, Feature::Fleet],
            device_ids: vec!["KA-0123456789abcdef01234567".to_owned()],
            limits: EntitlementLimits {
                max_tool_devices: 1,
                max_technicians: 2,
                max_managed_assets: 100,
            },
            issued_at_unix: 1_000,
            not_before_unix: 1_000,
            offline_lease_until_unix: 2_000,
            expires_at_unix: 3_000,
            grace_until_unix: 4_000,
        };
        let canonical = serde_json::to_vec(&serde_json::to_value(&claims).expect("claims value"))
            .expect("canonical claims");
        fs::write(&claims_path, canonical).expect("write claims");
        let signing_key = read_signing_key(&seed).expect("read seed");
        let parsed = read_canonical_claims::<EntitlementClaims>(&claims_path)
            .expect("read canonical claims");
        let signed = sign_entitlement(parsed, &signing_key).expect("sign entitlement");
        write_new(&output, &signed, 0o600).expect("write signed document");
        let document = fs::read(output).expect("read signed document");
        let verified = verify_entitlement(&document, &signing_key.verifying_key().to_bytes(), None)
            .expect("verify signed document");
        assert_eq!(verified.envelope.claims.entitlement_id, "ent_test_001");
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
