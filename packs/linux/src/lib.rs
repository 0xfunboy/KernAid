#![forbid(unsafe_code)]
//! Linux repair-pack primitives. Mutations in this crate are restricted to
//! explicitly marked disposable fixtures until the production broker exists.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const FIXTURE_MARKER: &str = "KERNAID_DISPOSABLE_FIXTURE_V1\n";
const BROKEN_ENTRY: &str = "UUID=missing-data /mnt/data ext4 defaults 0 2";
const REPAIRED_ENTRY: &str =
    "# KernAid disabled missing device: UUID=missing-data /mnt/data ext4 defaults 0 2";

#[derive(Debug, PartialEq, Eq)]
pub enum RepairError {
    NotDisposableFixture,
    UnsafePath,
    MissingEvidence,
    StaleTarget,
    ApprovalRequired,
    BackupInsideTarget,
    BackupExists,
    ResourceLocked,
    RepairNotApplicable,
    ValidationFailed,
    Io(String),
}

impl From<std::io::Error> for RepairError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstabPreview {
    pub target_fingerprint: String,
    pub before: String,
    pub after: String,
    pub backup_required: bool,
    pub validation: &'static str,
    pub rollback: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairReceipt {
    pub before_fingerprint: String,
    pub after_fingerprint: String,
    pub backup_path: PathBuf,
    pub backup_fingerprint: String,
    pub validation_passed: bool,
}

fn fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn canonical_fixture(root: &Path) -> Result<PathBuf, RepairError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RepairError::UnsafePath);
    }
    let root = fs::canonicalize(root)?;
    let marker = root.join(".kernaid-disposable-fixture");
    if fs::symlink_metadata(&marker)?.file_type().is_symlink()
        || fs::read_to_string(marker)? != FIXTURE_MARKER
    {
        return Err(RepairError::NotDisposableFixture);
    }
    Ok(root)
}

fn read_fstab(root: &Path) -> Result<Vec<u8>, RepairError> {
    let path = root.join("etc/fstab");
    if fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(RepairError::UnsafePath);
    }
    Ok(fs::read(path)?)
}

fn repaired(bytes: &[u8]) -> Result<Vec<u8>, RepairError> {
    let before = std::str::from_utf8(bytes).map_err(|_| RepairError::RepairNotApplicable)?;
    if !before.lines().any(|line| line == BROKEN_ENTRY) {
        return Err(RepairError::RepairNotApplicable);
    }
    Ok(before
        .lines()
        .map(|line| {
            if line == BROKEN_ENTRY {
                REPAIRED_ENTRY
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .add_trailing_newline())
}

trait TrailingNewline {
    fn add_trailing_newline(self) -> Vec<u8>;
}

impl TrailingNewline for String {
    fn add_trailing_newline(mut self) -> Vec<u8> {
        self.push('\n');
        self.into_bytes()
    }
}

pub fn preview_missing_fstab_device(
    root: &Path,
    evidence_ids: &[String],
) -> Result<FstabPreview, RepairError> {
    if evidence_ids.is_empty() {
        return Err(RepairError::MissingEvidence);
    }
    let root = canonical_fixture(root)?;
    let before = read_fstab(&root)?;
    let after = repaired(&before)?;
    Ok(FstabPreview {
        target_fingerprint: fingerprint(&before),
        before: String::from_utf8_lossy(&before).into_owned(),
        after: String::from_utf8_lossy(&after).into_owned(),
        backup_required: true,
        validation: "fstab parses and missing UUID entry is disabled",
        rollback: "restore byte-verified fstab backup",
    })
}

pub fn execute_missing_fstab_device_repair(
    root: &Path,
    backup_dir: &Path,
    expected_fingerprint: &str,
    evidence_ids: &[String],
    approval_id: &str,
) -> Result<RepairReceipt, RepairError> {
    if approval_id.trim().is_empty() {
        return Err(RepairError::ApprovalRequired);
    }
    let preview = preview_missing_fstab_device(root, evidence_ids)?;
    if preview.target_fingerprint != expected_fingerprint {
        return Err(RepairError::StaleTarget);
    }
    let root = canonical_fixture(root)?;
    let backup_dir = fs::canonicalize(backup_dir)?;
    if backup_dir.starts_with(&root) {
        return Err(RepairError::BackupInsideTarget);
    }
    let digest = expected_fingerprint
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64)
        .ok_or(RepairError::StaleTarget)?;
    let lock_path = backup_dir.join(".kernaid-fstab.lock");
    let _lock = FixtureLock::acquire(lock_path)?;
    let before = read_fstab(&root)?;
    if fingerprint(&before) != expected_fingerprint {
        return Err(RepairError::StaleTarget);
    }
    let after = repaired(&before)?;
    let backup_path = backup_dir.join(format!("fstab-{}.bak", &digest[..16]));
    let mut backup = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                RepairError::BackupExists
            } else {
                RepairError::Io(error.to_string())
            }
        })?;
    backup.write_all(&before)?;
    backup.sync_all()?;
    let backup_fingerprint = fingerprint(&fs::read(&backup_path)?);
    if backup_fingerprint != expected_fingerprint {
        return Err(RepairError::ValidationFailed);
    }

    let fstab = root.join("etc/fstab");
    let temporary = root.join("etc/.fstab.kernaid-new");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    output.write_all(&after)?;
    output.sync_all()?;
    fs::set_permissions(&temporary, fs::metadata(&fstab)?.permissions())?;
    fs::rename(&temporary, &fstab)?;
    let installed = read_fstab(&root)?;
    let validation_passed = installed == after
        && String::from_utf8_lossy(&installed)
            .lines()
            .any(|line| line == REPAIRED_ENTRY)
        && !String::from_utf8_lossy(&installed)
            .lines()
            .any(|line| line == BROKEN_ENTRY);
    if !validation_passed {
        return Err(RepairError::ValidationFailed);
    }
    Ok(RepairReceipt {
        before_fingerprint: expected_fingerprint.to_owned(),
        after_fingerprint: fingerprint(&installed),
        backup_path,
        backup_fingerprint,
        validation_passed,
    })
}

pub fn rollback_missing_fstab_device_repair(
    root: &Path,
    backup_path: &Path,
    expected_backup_fingerprint: &str,
    approval_id: &str,
) -> Result<String, RepairError> {
    if approval_id.trim().is_empty() {
        return Err(RepairError::ApprovalRequired);
    }
    let root = canonical_fixture(root)?;
    let backup_path = fs::canonicalize(backup_path)?;
    if backup_path.starts_with(&root)
        || fs::symlink_metadata(&backup_path)?.file_type().is_symlink()
    {
        return Err(RepairError::BackupInsideTarget);
    }
    let backup_dir = backup_path.parent().ok_or(RepairError::UnsafePath)?;
    let _lock = FixtureLock::acquire(backup_dir.join(".kernaid-fstab.lock"))?;
    let backup = fs::read(&backup_path)?;
    if fingerprint(&backup) != expected_backup_fingerprint {
        return Err(RepairError::ValidationFailed);
    }
    let temporary = root.join("etc/.fstab.kernaid-rollback");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    output.write_all(&backup)?;
    output.sync_all()?;
    fs::set_permissions(
        &temporary,
        fs::metadata(root.join("etc/fstab"))?.permissions(),
    )?;
    fs::rename(temporary, root.join("etc/fstab"))?;
    let restored = read_fstab(&root)?;
    if restored != backup {
        return Err(RepairError::ValidationFailed);
    }
    Ok(fingerprint(&restored))
}

struct FixtureLock(PathBuf);

impl FixtureLock {
    fn acquire(path: PathBuf) -> Result<Self, RepairError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    RepairError::ResourceLocked
                } else {
                    RepairError::Io(error.to_string())
                }
            })?;
        Ok(Self(path))
    }
}

impl Drop for FixtureLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TestTree {
        root: PathBuf,
    }
    impl TestTree {
        fn new(name: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "kernaid-{name}-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("target/etc")).expect("create target fixture");
            fs::create_dir_all(root.join("backup")).expect("create backup fixture");
            fs::write(
                root.join("target/.kernaid-disposable-fixture"),
                FIXTURE_MARKER,
            )
            .expect("write fixture marker");
            fs::write(
                root.join("target/etc/fstab"),
                format!("# test\n{BROKEN_ENTRY}\n"),
            )
            .expect("write fstab fixture");
            Self { root }
        }
        fn target(&self) -> PathBuf {
            self.root.join("target")
        }
        fn backup(&self) -> PathBuf {
            self.root.join("backup")
        }
    }
    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn repair_is_backed_up_validated_and_rollbackable() {
        let tree = TestTree::new("fstab-transaction");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let preview = preview_missing_fstab_device(&tree.target(), &evidence)
            .expect("preview fixture repair");
        let receipt = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            &preview.target_fingerprint,
            &evidence,
            "A-local",
        )
        .expect("execute fixture repair");
        assert!(receipt.validation_passed);
        assert_ne!(receipt.before_fingerprint, receipt.after_fingerprint);
        let restored = rollback_missing_fstab_device_repair(
            &tree.target(),
            &receipt.backup_path,
            &receipt.backup_fingerprint,
            "A-rollback",
        )
        .expect("rollback fixture repair");
        assert_eq!(restored, preview.target_fingerprint);
    }

    #[test]
    fn stale_fingerprint_is_rejected_before_backup_or_write() {
        let tree = TestTree::new("fstab-stale");
        let evidence = vec!["E-missing-uuid".to_owned()];
        let result = execute_missing_fstab_device_repair(
            &tree.target(),
            &tree.backup(),
            "sha256:stale",
            &evidence,
            "A-local",
        );
        assert_eq!(result, Err(RepairError::StaleTarget));
        assert_eq!(
            fs::read_dir(tree.backup())
                .expect("read backup directory")
                .count(),
            0
        );
    }

    #[test]
    fn unmarked_target_is_never_mutated() {
        let tree = TestTree::new("fstab-unmarked");
        fs::remove_file(tree.target().join(".kernaid-disposable-fixture")).expect("remove marker");
        let result = preview_missing_fstab_device(&tree.target(), &["E-1".to_owned()]);
        assert!(matches!(
            result,
            Err(RepairError::Io(_)) | Err(RepairError::NotDisposableFixture)
        ));
    }
}
