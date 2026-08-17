#![cfg(target_os = "linux")]

#[path = "../src/bounded_process.rs"]
mod bounded_process;

use bounded_process::{BoundedProcessError, capture, wait};
use std::{
    fs,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn bounded_capture_kills_a_descendant_holding_stdout() {
    let fixture = tempfile::tempdir().expect("temporary process-group fixture");
    let pid_file = fixture.path().join("descendant.pid");
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("trap '' TERM; sleep 30 & printf '%s' \"$!\" >\"$1\"; printf ready")
        .arg("kernaid-process-group-test")
        .arg(&pid_file)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());

    let started = Instant::now();
    assert_eq!(
        capture(&mut command, Duration::from_millis(150), 4096).err(),
        Some(BoundedProcessError::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_secs(3));

    let descendant: i32 = fs::read_to_string(pid_file)
        .expect("descendant pid")
        .parse()
        .expect("numeric descendant pid");
    let descendant = rustix::process::Pid::from_raw(descendant).expect("positive pid");
    assert_eq!(
        rustix::process::test_kill_process(descendant).err(),
        Some(rustix::io::Errno::SRCH)
    );

    let mut captured_success = Command::new("/usr/bin/printf");
    captured_success
        .arg("bounded-output")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    let output = capture(&mut captured_success, Duration::from_secs(1), 64)
        .expect("bounded captured command");
    assert!(output.status.success());
    assert_eq!(output.bytes, b"bounded-output");
    assert!(!output.exceeded_limit);

    // Compile and exercise the same no-capture path used for cryptsetup open
    // and close; no unit-test process with vault locks is alive in this test
    // binary, so spawning cannot transiently inherit those descriptors.
    let mut success = Command::new("/bin/true");
    assert!(
        wait(&mut success, Duration::from_secs(1))
            .expect("bounded no-capture command")
            .success()
    );
}
