#![forbid(unsafe_code)]
#![cfg(all(target_os = "linux", feature = "experimental-vault-manager"))]

#[path = "../src/bounded_process.rs"]
mod bounded_process;

use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

const CRYPTSETUP_PATH: &str = "/usr/sbin/cryptsetup";
const BLKID_PATH: &str = "/usr/sbin/blkid";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_OUTPUT_LIMIT: usize = 4096;

fn capture_with_stdin(command: &mut Command, stdin: Stdio) -> Vec<u8> {
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = bounded_process::capture(command, COMMAND_TIMEOUT, COMMAND_OUTPUT_LIMIT)
        .expect("bounded stdin probe");
    assert!(output.status.success(), "external stdin probe failed");
    output.bytes
}

#[test]
fn cryptsetup_and_blkid_probe_an_inherited_child_procfd_after_path_swap() {
    // Every descriptor-bearing child uses the same bounded spawn gate as the
    // production worker, including its CLOEXEC handoff window.
    if !Path::new(CRYPTSETUP_PATH).is_file() || !Path::new(BLKID_PATH).is_file() {
        return;
    }

    let directory = tempfile::tempdir().expect("temporary LUKS procfd fixture");
    let named = directory.path().join("selected-device");
    let moved = directory.path().join("original-device");
    let replacement = directory.path().join("replacement-source");
    let key_path = directory.path().join("test-key");
    fs::write(&key_path, b"disposable-test-passphrase").expect("write disposable test key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("secure disposable test key");
    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&named)
        .expect("create disposable image");
    image
        .set_len(32 * 1024 * 1024)
        .expect("size disposable image");
    let mut format = Command::new(CRYPTSETUP_PATH);
    format
        .arg("luksFormat")
        .arg("--type")
        .arg("luks2")
        .arg("--batch-mode")
        .arg("--label")
        .arg("KERNAID_VAULT")
        .arg("--pbkdf")
        .arg("pbkdf2")
        .arg("--pbkdf-force-iterations")
        .arg("1000")
        .arg("--key-file")
        .arg(&key_path)
        .arg(&named)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status =
        bounded_process::wait(&mut format, COMMAND_TIMEOUT).expect("bounded cryptsetup format");
    assert!(
        status.success(),
        "cryptsetup could not format disposable fixture"
    );
    drop(image);
    let retained = File::open(&named).expect("retain formatted image descriptor");

    fs::rename(&named, &moved).expect("move formatted image");
    let blank = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&replacement)
        .expect("create blank replacement");
    blank
        .set_len(32 * 1024 * 1024)
        .expect("size blank replacement");
    fs::rename(&replacement, &named).expect("replace selected path");

    let mut is_luks = Command::new(CRYPTSETUP_PATH);
    let cryptsetup_descriptor = bounded_process::InheritedChildDescriptor::duplicate(&retained)
        .expect("cryptsetup child descriptor");
    is_luks
        .arg("isLuks")
        .arg("--type")
        .arg("luks2")
        .arg(cryptsetup_descriptor.path())
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status =
        bounded_process::wait_with_descriptor(&mut is_luks, COMMAND_TIMEOUT, cryptsetup_descriptor)
            .expect("bounded cryptsetup retained probe");
    assert!(status.success(), "cryptsetup rejected retained descriptor");

    let mut blkid = Command::new(BLKID_PATH);
    let blkid_stdin = bounded_process::duplicate_child_stdin(&retained).expect("blkid child stdin");
    blkid
        .arg("--probe")
        .arg("--cache-file")
        .arg("/dev/null")
        .arg("--no-encoding")
        .arg("--output")
        .arg("export")
        .arg("--match-tag")
        .arg("TYPE")
        .arg("--match-tag")
        .arg("VERSION")
        .arg("--match-tag")
        .arg("UUID")
        .arg("--match-tag")
        .arg("LABEL")
        .arg(bounded_process::CHILD_STDIN_PATH);
    let properties = capture_with_stdin(&mut blkid, blkid_stdin);
    assert!(
        properties
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"TYPE=crypto_LUKS")
    );
    assert!(
        properties
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"VERSION=2")
    );
    assert!(
        properties
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"LABEL=KERNAID_VAULT")
    );
    assert!(properties.split(|byte| *byte == b'\n').any(|line| {
        line.strip_prefix(b"UUID=").is_some_and(|value| {
            value.len() == 36
                && value.iter().all(|byte| {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) || *byte == b'-'
                })
        })
    }));

    let mut swapped = Command::new(CRYPTSETUP_PATH);
    swapped
        .arg("luksUUID")
        .arg("--type")
        .arg("luks2")
        .arg(&named)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let swapped = bounded_process::capture(&mut swapped, COMMAND_TIMEOUT, COMMAND_OUTPUT_LIMIT)
        .expect("bounded swapped-path probe");
    assert!(
        !swapped.status.success(),
        "cryptsetup unexpectedly accepted the swapped pathname"
    );
}
