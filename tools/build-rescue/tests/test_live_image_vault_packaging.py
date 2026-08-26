from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
LIVE_ROOT = REPO_DIR / "rescue/live-build/config/includes.chroot"
SYSTEMD = LIVE_ROOT / "etc/systemd/system"
VAULT_SERVICE = SYSTEMD / "kernaid-rescue-vaultd.service"
VAULT_SOCKET = SYSTEMD / "kernaid-rescue-vaultd.socket"
READY_SERVICE = SYSTEMD / "kernaid-ready.service"
SYSUSERS = LIVE_ROOT / "etc/sysusers.d/kernaid.conf"
TMPFILES = LIVE_ROOT / "usr/lib/tmpfiles.d/kernaid.conf"
SYSCTL = LIVE_ROOT / "etc/sysctl.d/99-kernaid-rescue-core.conf"
COREDUMP = LIVE_ROOT / "etc/systemd/coredump.conf.d/99-kernaid-rescue.conf"
READY_CHECK = LIVE_ROOT / "usr/lib/kernaid/ready-check"
SAFETY_HOOK = (
    REPO_DIR / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
)
PACKAGE_LIST = REPO_DIR / "rescue/live-build/config/package-lists/kernaid.list.chroot"
BUILD_SCRIPT = REPO_DIR / "tools/build-rescue/build.sh"
WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"
BINARY_VERIFIER = REPO_DIR / "tools/build-rescue/verify-shipping-binary.py"
DAEMON_SERVER = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/server.rs"
DAEMON_RUNTIME = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/runtime.rs"
COMPANION = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/companion.rs"
PROBE_HELPER = REPO_DIR / "tools/build-rescue/provider-lease-probe.py"
PROBE_MARKER = "/run/kernaid-rescue-vault/provider-lease-probe-validated-v1"
LIFECYCLE_MARKER = "/run/kernaid-rescue-vault/lifecycle-active-v1"
PROBE_UNITS = (
    "kernaid-provider-executor-status-probe.socket",
    "kernaid-provider-executor-status-probe@.service",
    "kernaid-provider-lease-probe.socket",
    "kernaid-provider-lease-probe@.service",
    "kernaid-provider-lease-kill-vaultd.socket",
    "kernaid-provider-lease-kill-vaultd@.service",
)

DEFAULT_LIVE_GROUPS = (
    "audio,cdrom,dip,floppy,video,plugdev,netdev,powerdev,scanner,bluetooth"
)

VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "kernaid_shipping_binary_verifier", BINARY_VERIFIER
)
assert VERIFIER_SPEC is not None and VERIFIER_SPEC.loader is not None
binary_verifier = importlib.util.module_from_spec(VERIFIER_SPEC)
sys.modules[VERIFIER_SPEC.name] = binary_verifier
VERIFIER_SPEC.loader.exec_module(binary_verifier)

VALID_READELF = """
Elf file type is DYN (Position-Independent Executable file)
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED) Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED) Shared library: [libm.so.6]
"""


def unit_sections(path: Path) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        if current is None or "=" not in line:
            raise AssertionError(f"invalid unit line in {path}: {raw_line!r}")
        key, value = line.split("=", maxsplit=1)
        if key in current:
            raise AssertionError(f"duplicate unit key in {path}: {key}")
        current[key] = value
    return sections


def active_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class VaultSystemdPackagingTests(unittest.TestCase):
    def test_seqpacket_listener_is_systemd_257_compatible_and_ancillary_safe(self) -> None:
        sections = unit_sections(VAULT_SOCKET)
        socket = sections["Socket"]
        self.assertEqual(
            socket,
            {
                "ListenSequentialPacket": "/run/kernaid-rescue-vault.sock",
                "Accept": "no",
                "Backlog": "8",
                "FlushPending": "yes",
                "SocketMode": "0660",
                "SocketUser": "root",
                "SocketGroup": "kernaid-vault",
                "RemoveOnStop": "yes",
                "PassCredentials": "no",
                "PassSecurity": "no",
                "PassPacketInfo": "no",
                "Timestamping": "off",
            },
        )
        text = VAULT_SOCKET.read_text(encoding="utf-8")
        self.assertIn("systemd 257 predates the PassPIDFD directive", text)
        self.assertFalse(
            any(line.lstrip().startswith("PassPIDFD=") for line in text.splitlines())
        )
        self.assertNotIn("AcceptFileDescriptors=", text)
        self.assertEqual(
            sections["Unit"],
            {
                "Description": "KernAid Rescue vault lifecycle control socket",
                "Requires": "systemd-sysusers.service",
                "After": "systemd-sysusers.service",
                "ConditionKernelCommandLine": "boot=live",
            },
        )
        self.assertEqual(sections["Install"], {"WantedBy": "sockets.target"})

    def test_notify_service_owns_listener_runtime_and_worker_cgroup_contract(self) -> None:
        sections = unit_sections(VAULT_SERVICE)
        unit = sections["Unit"]
        service = sections["Service"]
        self.assertEqual(
            set(unit["Requires"].split()),
            {
                "kernaid-rescue-vaultd.socket",
                "kernaid-rescue-codex-mounter.socket",
                "live-config.service",
                "systemd-sysusers.service",
            },
        )
        self.assertIn("kernaid-rescue-vaultd.socket", unit["After"].split())
        self.assertIn("kernaid-rescue-codex-mounter.socket", unit["After"].split())
        self.assertIn("live-config.service", unit["After"].split())
        self.assertIn("systemd-sysusers.service", unit["After"].split())
        self.assertIn("systemd-sysctl.service", unit["After"].split())
        self.assertEqual(unit["Before"], "kernaid-ready.service")
        self.assertEqual(unit["ConditionKernelCommandLine"], "boot=live")
        self.assertEqual(unit["ConditionPathIsDirectory"], "/run/live/medium")
        expected = {
            "Type": "notify",
            "NotifyAccess": "main",
            "Sockets": "kernaid-rescue-vaultd.socket",
            "ExecStart": "/usr/lib/kernaid/kernaid-rescue-vaultd",
            "Restart": "no",
            "TimeoutStartSec": "620s",
            "TimeoutStopSec": "120s",
            "KillMode": "mixed",
            "SendSIGKILL": "yes",
            "StandardInput": "socket",
            "StandardOutput": "journal",
            "StandardError": "journal",
            "User": "root",
            "Group": "root",
            "UMask": "0077",
            "RuntimeDirectory": "kernaid-rescue-vault",
            "RuntimeDirectoryMode": "0700",
            "RuntimeDirectoryPreserve": "yes",
            "LimitCORE": "0",
            "LimitNOFILE": "128",
            "TasksMax": "64",
            "NoNewPrivileges": "yes",
            "PrivateMounts": "yes",
            "PrivateNetwork": "yes",
            "PrivateTmp": "yes",
            "PrivateDevices": "no",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "ProtectKernelLogs": "yes",
            "ProtectKernelModules": "yes",
            "ProtectKernelTunables": "yes",
            "ProtectClock": "yes",
            "ProtectHostname": "yes",
            "ProtectControlGroups": "no",
            "ReadWritePaths": "-/run/kernaid /run/lock -/run/cryptsetup",
            "CapabilityBoundingSet": "CAP_SYS_ADMIN CAP_KILL CAP_SETPCAP",
            "AmbientCapabilities": "",
            "RestrictAddressFamilies": "AF_UNIX",
            "RestrictRealtime": "yes",
            "LockPersonality": "yes",
            "MemoryDenyWriteExecute": "yes",
            "SystemCallArchitectures": "native",
            "Delegate": "pids",
            "DelegateSubgroup": "supervisor",
        }
        self.assertEqual(service, expected)
        self.assertNotIn("DynamicUser", service)
        self.assertNotIn("ExecStartPost", service)
        self.assertNotIn("NonBlocking", service)
        # systemd 257 implements RestrictSUIDSGID by denying every openat2(2)
        # call. The daemon's descriptor-bound path validation requires openat2,
        # so that directive must stay absent while the other sandbox gates stay
        # exact above.
        self.assertNotIn("RestrictSUIDSGID", service)
        self.assertEqual(sections["Install"], {"WantedBy": "multi-user.target"})

    def test_packaging_names_match_the_frozen_daemon_constants(self) -> None:
        server = DAEMON_SERVER.read_text(encoding="utf-8")
        companion = COMPANION.read_text(encoding="utf-8")
        runtime = DAEMON_RUNTIME.read_text(encoding="utf-8")
        self.assertIn(
            'const CONTROL_SOCKET_PATH: &str = "/run/kernaid-rescue-vault.sock";',
            server,
        )
        self.assertIn(
            'const CONTROL_SOCKET: &str = "/run/kernaid-rescue-vault.sock";',
            companion,
        )
        self.assertIn('const LISTENER_GROUP_NAME: &[u8] = b"kernaid-vault";', server)
        self.assertIn('const RUNTIME_ROOT_NAME: &str = "kernaid-rescue-vault";', runtime)

    def test_global_readiness_runs_after_failed_dependencies_to_report_not_ready(self) -> None:
        sections = unit_sections(READY_SERVICE)
        unit = sections["Unit"]
        self.assertEqual(
            set(unit["Wants"].split()),
            {
                "kernaid-ui.service",
                "kernaid-rescue-codex.socket",
                "kernaid-rescue-desk-shell.service",
                "kernaid-rescue-openai-egress.socket",
                "kernaid-rescue-vaultd.service",
            },
        )
        self.assertNotIn("Requires", unit)
        self.assertEqual(
            set(unit["After"].split()),
            {
                "multi-user.target",
                "kernaid-ui.service",
                "kernaid-rescue-codex.socket",
                "kernaid-rescue-desk-shell.service",
                "kernaid-rescue-openai-egress.socket",
                "kernaid-rescue-vaultd.service",
            },
        )
        self.assertEqual(
            sections["Service"]["ExecStart"],
            "/bin/sh /usr/lib/kernaid/ready-check",
        )
        self.assertIn(
            "printf '\\nKERNAID_RESCUE_NOT_READY: %s\\n' \"$*\" >/dev/ttyS0",
            READY_CHECK.read_text(encoding="utf-8"),
        )

    def test_vault_group_readiness_awk_is_portable_and_exact(self) -> None:
        program = (
            'NF == 4 && $1 == "kernaid-vault" { '
            'count = split($4, members, ","); '
            "for (member_index = 1; member_index <= count; member_index += 1) { "
            "seen[members[member_index]] += 1 } "
            'if (count == 3 && seen["kernaid"] == 1 '
            '&& seen["kernaid-openai"] == 1 '
            '&& seen["kernaid-application"] == 1) found = 1 '
            "} END { exit !found }"
        )
        self.assertIn(program, READY_CHECK.read_text(encoding="utf-8"))

        for members, expected in [
            ("kernaid,kernaid-openai,kernaid-application", 0),
            ("kernaid-application,kernaid,kernaid-openai", 0),
            ("kernaid,kernaid-openai", 1),
            ("kernaid,kernaid-openai,kernaid-openai", 1),
        ]:
            result = subprocess.run(
                ["/usr/bin/awk", "-F:", program],
                input=f"kernaid-vault:x:995:{members}\n",
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_vault_startup_status_is_fixed_bounded_and_stage_ordered(self) -> None:
        ready = READY_CHECK.read_text(encoding="utf-8")
        server = DAEMON_SERVER.read_text(encoding="utf-8")
        prefix = "KERNAID_RESCUE_VAULT_STARTUP_V1 stage="
        stages = (
            "identity",
            "listener",
            "runtime",
            "rng",
            "worker-cgroup",
            "worker-bootstrap",
            "worker-caps",
            "worker-probe",
            "caps-final",
            "ready",
        )

        self.assertIn(
            "/usr/bin/timeout --signal=TERM --kill-after=1s 5s \\\n"
            "            /usr/bin/systemctl show --property=StatusText --value \\\n"
            "            kernaid-rescue-vaultd.service 2>/dev/null \\\n"
            "            | /usr/bin/head -c 65",
            ready,
        )
        self.assertIn(
            '"$(printf \'\\n.\')")\n'
            '            fail "vault lifecycle daemon startup stage is unavailable"',
            ready,
        )
        for stage in stages:
            self.assertIn(
                f'"$(printf \'{prefix}{stage}\\n.\')")',
                ready,
            )
            self.assertIn(
                f'fail "vault lifecycle daemon last reported startup stage {stage}"',
                ready,
            )
            self.assertIn(
                f'b"STATUS={prefix}{stage}"',
                server,
            )
        self.assertIn(
            'fail "vault lifecycle daemon startup stage is unavailable"',
            ready,
        )
        self.assertNotRegex(
            ready,
            r'fail\s+"vault lifecycle daemon (?:startup|last reported)[^"\n]*\$',
        )

        run_start = server.index("pub(super) fn run(companion_uid:")
        worker_start = server.index("\nfn start_worker(", run_start)
        run_source = server[run_start:worker_start]
        run_order = (
            "enforce_process_privacy()",
            "SystemdNotifier::from_environment()?",
            "spawn_signal_waiter(signal_set, stop.clone())?",
            "note_startup_stage(StartupStage::Identity)",
            "validated_peer_allowlist(companion_uid)?",
            "note_startup_stage(StartupStage::Listener)",
            "take_listener()?",
            "note_startup_stage(StartupStage::Runtime)",
            "DaemonRuntime::open()?",
            "note_startup_stage(StartupStage::Rng)",
            "state_version_seed()?",
            "start_worker(",
            "startup_stage_can_advance(disposition, startup_fault)",
            "note_startup_stage(StartupStage::CapsFinal)",
            "let capabilities_ready =",
            "note_startup_stage(StartupStage::Ready)",
            "startup_readiness(",
        )
        positions = [run_source.index(fragment) for fragment in run_order]
        self.assertEqual(positions, sorted(positions))

        worker_end = server.index("\nfn cancel_startup_worker(", worker_start)
        worker_source = server[worker_start:worker_end]
        for stage, phase in (
            ("WorkerCgroup", "WorkerCgroup::prepare()"),
            ("WorkerBootstrap", "WorkerHandle::spawn("),
            ("WorkerCaps", "runtime::narrow_supervisor_capabilities()"),
            ("WorkerProbe", "worker.transact_cancellable("),
        ):
            self.assertLess(
                worker_source.index(f"note_startup_stage(StartupStage::{stage})"),
                worker_source.index(phase),
            )
        self.assertIn("notifier: &SystemdNotifier", worker_source)
        self.assertIn(
            "if startup_stage_can_advance {\n"
            "        notifier.note_startup_stage(StartupStage::CapsFinal);\n"
            "    }",
            run_source,
        )
        self.assertIn(
            "if startup_stage_can_advance {\n"
            "        notifier.note_startup_stage(StartupStage::Ready);\n"
            "    }",
            run_source,
        )

    def test_runtime_ownership_does_not_tmpfiles_manage_the_fault_marker(self) -> None:
        self.assertEqual(
            active_lines(TMPFILES),
            [
                "d /run/kernaid 0700 root root -",
                "d /run/kernaid-rescue-ui-session 0700 kernaid-rescue-ui kernaid-rescue-ui -",
                "d /run/kernaid-rescue-ui-session/home 0700 kernaid-rescue-ui kernaid-rescue-ui -",
            ],
        )
        text = TMPFILES.read_text(encoding="utf-8")
        self.assertNotIn("kernaid-rescue-vault", text)
        self.assertNotIn("lifecycle-active-v1", text)

    def test_qemu_lease_probe_is_runtime_credential_only_and_marker_separated(self) -> None:
        ready = READY_CHECK.read_text(encoding="utf-8")
        hook = SAFETY_HOOK.read_text(encoding="utf-8")
        build = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(PROBE_HELPER.is_file())
        self.assertEqual(list(LIVE_ROOT.rglob(PROBE_HELPER.name)), [])
        self.assertNotIn(PROBE_HELPER.name, build)
        self.assertIn(PROBE_MARKER, ready)
        self.assertNotIn(LIFECYCLE_MARKER, ready)
        self.assertNotIn(PROBE_MARKER, TMPFILES.read_text(encoding="utf-8"))
        self.assertNotIn(LIFECYCLE_MARKER, TMPFILES.read_text(encoding="utf-8"))
        for name in PROBE_UNITS:
            unit = SYSTEMD / name
            self.assertTrue(unit.is_file())
            self.assertIn(f"/etc/systemd/system/{name}", hook)
            self.assertNotIn(f"systemctl enable {name}", hook)
            self.assertNotIn("[Install]", unit.read_text(encoding="utf-8"))
        kill = (SYSTEMD / "kernaid-provider-lease-kill-vaultd@.service").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"ConditionPathExists={LIFECYCLE_MARKER}", kill)
        self.assertIn(f"ConditionPathExists={PROBE_MARKER}", kill)
        self.assertNotEqual(PROBE_MARKER, LIFECYCLE_MARKER)


class VaultLivePolicyTests(unittest.TestCase):
    def test_core_dump_policy_is_global_and_fail_closed(self) -> None:
        self.assertEqual(
            active_lines(SYSCTL),
            [
                "kernel.core_pattern =",
                "kernel.core_uses_pid = 0",
                "kernel.printk = 5 4 1 7",
            ],
        )
        self.assertEqual(
            active_lines(COREDUMP),
            ["[Coredump]", "Storage=none", "ProcessSizeMax=0"],
        )
        ready = READY_CHECK.read_text(encoding="utf-8")
        self.assertIn("/proc/sys/kernel/core_pattern", ready)
        self.assertIn("/proc/sys/kernel/core_uses_pid", ready)
        self.assertIn("/proc/sys/kernel/printk", ready)
        expected_printk_gate = (
            'printk_policy="$(\n'
            "    /usr/bin/head -c 65 /proc/sys/kernel/printk || exit 1\n"
            "    printf '.'\n"
            ')" || fail "kernel console policy is unavailable"\n'
            'test "$printk_policy" = "$(printf \'5\\t4\\t1\\t7\\n.\')" \\\n'
            '    || fail "kernel console policy is unsafe"'
        )
        self.assertIn(
            expected_printk_gate,
            ready,
        )
        self.assertNotRegex(
            ready,
            r"(?m)^\s*read\b[^\n]*<\s*/proc/sys/kernel/printk(?:\s|$)",
        )
        self.assertIn("/proc/swaps", ready)
        self.assertIn(
            "--value kernaid-rescue-vaultd.service)", ready
        )
        self.assertIn(
            "--value kernaid-rescue-vaultd.socket)", ready
        )
        self.assertIn("--property=SubState", ready)
        self.assertIn('case "$vault_socket_substate" in', ready)
        self.assertIn("listening|running) ;;", ready)
        self.assertNotIn('= "listening"', ready)
        self.assertIn("test -S /run/kernaid-rescue-vault.sock", ready)
        self.assertIn("0:${vault_group_id}:660:1", ready)

    def test_exact_live_uid_group_and_subordinate_id_policy_is_wired(self) -> None:
        self.assertIn("g kernaid-vault - -", active_lines(SYSUSERS))
        build = BUILD_SCRIPT.read_text(encoding="utf-8")
        match = re.search(r'--bootappend-live "([^"]+)"', build)
        self.assertIsNotNone(match)
        bootappend = match.group(1) if match else ""
        self.assertEqual(
            bootappend.split().count("live-config.nox11autologin"), 1
        )
        self.assertIn(
            f"live-config.user-default-groups={DEFAULT_LIVE_GROUPS},kernaid-vault",
            bootappend,
        )
        self.assertIn("systemd.swap=0", bootappend.split())
        self.assertEqual(bootappend.split().count("quiet"), 1)
        self.assertEqual(bootappend.split().count("loglevel=5"), 1)
        self.assertLess(
            bootappend.split().index("quiet"),
            bootappend.split().index("loglevel=5"),
        )
        self.assertFalse(
            any(
                token.startswith("loglevel=") and token != "loglevel=5"
                for token in bootappend.split()
            )
        )
        self.assertNotIn("swap=true", bootappend.split())

        hook = SAFETY_HOOK.read_text(encoding="utf-8")
        self.assertIn("/usr/lib/kernaid/kernaid-rescue-vaultd", hook)
        self.assertIn("/usr/bin/kernaid-rescue-vaultctl", hook)
        self.assertIn("/etc/systemd/system/kernaid-rescue-vaultd.service", hook)
        self.assertIn("/usr/lib/tmpfiles.d/kernaid.conf", hook)
        self.assertIn("chmod 0755", hook)
        self.assertIn("chmod 0644", hook)
        self.assertIn("for key in SUB_UID_COUNT SUB_GID_COUNT", hook)
        self.assertIn("/usr/bin/newuidmap /usr/bin/newgidmap", hook)
        self.assertIn("chmod u-s,g-s", hook)
        self.assertIn("systemctl mask swap.target", hook)
        self.assertIn("systemctl enable kernaid-rescue-vaultd.socket", hook)
        self.assertIn("systemctl enable kernaid-rescue-vaultd.service", hook)

        ready = READY_CHECK.read_text(encoding="utf-8")
        self.assertIn('id -u kernaid 2>/dev/null)" = "1000"', ready)
        self.assertIn("grep -Fxq kernaid-vault", ready)
        self.assertIn("/etc/subuid /etc/subgid", ready)
        self.assertIn("[ -u \"$helper\" ] || [ -g \"$helper\" ]", ready)
        self.assertNotIn("uidmap", active_lines(PACKAGE_LIST))
        self.assertIn("user-setup", active_lines(PACKAGE_LIST))

    def test_build_stages_only_release_rescue_binaries_as_root_0755(self) -> None:
        build = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("KERNAID_RESCUE_VAULTD_BINARY", build)
        self.assertIn("KERNAID_RESCUE_VAULTCTL_BINARY", build)
        self.assertIn("KERNAID_LINUX_HARDWARE_INVENTORY_BINARY", build)
        self.assertIn(
            "config/includes.chroot/usr/lib/kernaid/kernaid-rescue-vaultd", build
        )
        self.assertIn(
            "config/includes.chroot/usr/bin/kernaid-rescue-vaultctl", build
        )
        self.assertIn(
            "config/includes.chroot/usr/lib/kernaid/kernaid-rescue-openai-executor",
            build,
        )
        self.assertIn(
            "config/includes.chroot/usr/lib/kernaid/kernaid-linux-hardware-inventory",
            build,
        )
        self.assertIn("KERNAID_RESCUE_DESK_SHELL_BINARY", build)
        self.assertIn(
            "config/includes.chroot/usr/bin/kernaid-rescue-desk-shell", build
        )
        self.assertIn("validate_amd64_elf", build)
        self.assertGreaterEqual(build.count("install -o root -g root -m 0755"), 2)
        self.assertIn("trap cleanup_staged_binaries EXIT", build)
        self.assertIn('rmdir -- "$vaultctl_destination_dir"', build)
        self.assertEqual(build.count("verify-shipping-binary.py"), 8)
        self.assertIn("--profile tauri-webkit", build)
        self.assertNotIn("cargo build", build)

    def test_shipping_binary_dependency_parser_is_closed_and_rejects_runpath(self) -> None:
        self.assertEqual(
            binary_verifier.parse_readelf_output(VALID_READELF),
            frozenset({"libc.so.6", "libgcc_s.so.1", "libm.so.6"}),
        )
        with self.assertRaises(binary_verifier.VerificationError):
            binary_verifier.parse_readelf_output(
                VALID_READELF
                + " 0x0000000000000001 (NEEDED) Shared library: [libssl.so.3]\n"
            )
        with self.assertRaises(binary_verifier.VerificationError):
            binary_verifier.parse_readelf_output(
                VALID_READELF
                + " 0x000000000000001d (RUNPATH) Library runpath: [/workspace]\n"
            )

        verifier = BINARY_VERIFIER.read_text(encoding="utf-8")
        self.assertIn('/usr/bin/x86_64-linux-gnu-readelf', verifier)
        self.assertIn("MAX_BINARY_BYTES", verifier)
        self.assertIn("MAX_TOOL_OUTPUT_BYTES", verifier)
        self.assertIn("TOOL_TIMEOUT_SECONDS", verifier)
        self.assertNotIn("ldd", verifier)

    def test_workflow_builds_and_supplies_all_shipping_binaries(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('- "crates/protocol/**"', workflow)
        self.assertIn("--bin kernaid-rescue-vaultd", workflow)
        self.assertIn("--bin kernaid-rescue-vaultctl", workflow)
        self.assertIn("--bin kernaid-rescue-codex-mounter", workflow)
        self.assertIn("--bin kernaid-rescue-openai-executor", workflow)
        self.assertIn("--bin kernaid-linux-hardware-inventory", workflow)
        self.assertIn("--bin kernaid-rescue-desk-shell", workflow)
        self.assertIn("-p kernaid-rescue-desk-shell", workflow)
        self.assertIn(
            "KERNAID_RESCUE_VAULTD_BINARY=/workspace/target/release/kernaid-rescue-vaultd",
            workflow,
        )
        self.assertIn(
            "KERNAID_RESCUE_VAULTCTL_BINARY=/workspace/target/release/kernaid-rescue-vaultctl",
            workflow,
        )
        self.assertIn(
            "KERNAID_RESCUE_OPENAI_EXECUTOR_BINARY=/workspace/target/release/kernaid-rescue-openai-executor",
            workflow,
        )
        self.assertIn(
            "KERNAID_LINUX_HARDWARE_INVENTORY_BINARY=/workspace/target/release/kernaid-linux-hardware-inventory",
            workflow,
        )
        self.assertIn(
            "KERNAID_RESCUE_DESK_SHELL_BINARY=/workspace/target/release/kernaid-rescue-desk-shell",
            workflow,
        )
        self.assertIn("apt-get install -y binutils live-build", workflow)
        self.assertIn("Verify the in-guest Rescue binary ABI", workflow)
        self.assertIn(
            "sudo /usr/bin/mktemp -d /root/kernaid-rescue-shipping-preflight.XXXXXXXX",
            workflow,
        )
        self.assertNotIn("$RUNNER_TEMP/kernaid-rescue-shipping-preflight", workflow)
        self.assertIn("sudo install -o root -g root -m 0755", workflow)
        self.assertEqual(workflow.count("verify-shipping-binary.py"), 8)
        self.assertIn("--profile tauri-webkit", workflow)
        self.assertIn("qemu-vault-lifecycle-smoke.sh", workflow)


if __name__ == "__main__":
    unittest.main()
