#![forbid(unsafe_code)]
#![cfg(all(target_os = "linux", feature = "experimental-vault-manager"))]

use rustix::{
    fd::OwnedFd,
    io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd},
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    process::{Command, Stdio},
};

#[test]
fn cloexec_passphrase_source_is_not_inherited_as_an_extra_descriptor() {
    const CHILD_FLAG: &str = "KERNAID_CLOEXEC_CHILD";
    if std::env::var_os(CHILD_FLAG).is_some() {
        let stdin_target = fs::read_link("/proc/self/fd/0").expect("child stdin target");
        for entry in fs::read_dir("/proc/self/fd").expect("child fd directory") {
            let entry = entry.expect("child fd entry");
            if entry.file_name() == OsStr::new("0") {
                continue;
            }
            if let Ok(target) = fs::read_link(entry.path()) {
                assert_ne!(
                    target, stdin_target,
                    "passphrase source fd leaked across exec"
                );
            }
        }
        return;
    }

    let source: OwnedFd = tempfile::tempfile().expect("passphrase source").into();
    let flags = fcntl_getfd(&source).expect("source descriptor flags");
    fcntl_setfd(&source, flags | FdFlags::CLOEXEC).expect("source CLOEXEC");
    let duplicate = fcntl_dupfd_cloexec(&source, 3).expect("CLOEXEC duplicate");
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("cloexec_passphrase_source_is_not_inherited_as_an_extra_descriptor")
        .arg("--nocapture")
        .env(CHILD_FLAG, "1")
        .stdin(Stdio::from(File::from(duplicate)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn inheritance probe");
    assert!(status.success());
}
