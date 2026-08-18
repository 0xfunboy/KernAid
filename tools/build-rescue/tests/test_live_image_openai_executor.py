from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
LIVE_ROOT = REPO_DIR / "rescue/live-build/config/includes.chroot"
SYSTEMD = LIVE_ROOT / "etc/systemd/system"
EXECUTOR_SOCKET = SYSTEMD / "kernaid-rescue-openai-executor.socket"
EXECUTOR_SERVICE = SYSTEMD / "kernaid-rescue-openai-executor@.service"
EGRESS_SOCKET = SYSTEMD / "kernaid-rescue-openai-egress.socket"
EGRESS_SERVICE = SYSTEMD / "kernaid-rescue-openai-egress.service"
VAULT_SERVICE = SYSTEMD / "kernaid-rescue-vaultd.service"
UI_SERVICE = SYSTEMD / "kernaid-ui.service"
RESCUE_SERVER = LIVE_ROOT / "usr/lib/kernaid/rescue_server.py"
SYSUSERS = LIVE_ROOT / "etc/sysusers.d/kernaid.conf"
HOOK = REPO_DIR / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
BUILD = REPO_DIR / "tools/build-rescue/build.sh"
WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"
VAULT_WORKFLOW = REPO_DIR / ".github/workflows/vault.yml"
EXECUTOR_SOURCE = REPO_DIR / "crates/rescue-openai-executor/src/linux.rs"
VAULT_WIRE_SOURCE = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/internal_wire.rs"
VAULT_WORKER_SOURCE = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/worker.rs"
VAULT_RUNTIME_SOURCE = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/runtime.rs"
VAULT_SERVER_SOURCE = REPO_DIR / "crates/rescue-secrets/src/rescue_daemon/server.rs"
READY_CHECK = LIVE_ROOT / "usr/lib/kernaid/ready-check"
PROBE_HELPER = REPO_DIR / "tools/build-rescue/provider-lease-probe.py"
LEASE_PROBE_SOCKET = SYSTEMD / "kernaid-provider-lease-probe.socket"
LEASE_PROBE_SERVICE = SYSTEMD / "kernaid-provider-lease-probe@.service"
LEASE_KILL_SOCKET = SYSTEMD / "kernaid-provider-lease-kill-vaultd.socket"
LEASE_KILL_SERVICE = SYSTEMD / "kernaid-provider-lease-kill-vaultd@.service"
STATUS_PROBE_SOCKET = SYSTEMD / "kernaid-provider-executor-status-probe.socket"
STATUS_PROBE_SERVICE = SYSTEMD / "kernaid-provider-executor-status-probe@.service"
PROBE_SIZE = 15508
PROBE_SHA256 = "23470d54d04fd4d025988e9fabf7401b12c9157c6d58162295c01817c103a08f"
PROBE_RAW = "/sys/firmware/qemu_fw_cfg/by_name/opt/io.systemd.credentials/provider-lease-probe/raw"
PROBE_MARKER = "/run/kernaid-rescue-vault/provider-lease-probe-validated-v1"


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


def section_lines(path: Path, section: str) -> list[str]:
    result: list[str] = []
    active = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == f"[{section}]"
        elif active and line and not line.startswith(("#", ";")):
            result.append(line)
    return result


class RescueOpenAiExecutorPackagingTests(unittest.TestCase):
    def test_ui_relay_is_fixed_framed_root_authenticated_and_credential_blind(
        self,
    ) -> None:
        source = RESCUE_SERVER.read_text(encoding="utf-8")
        for value in (
            'PROVIDER_SOCKET = "/run/kernaid-rescue-openai.sock"',
            "PROVIDER_REQUEST_DEADLINE_SECONDS = 142",
            "PROVIDER_SOCKET_TIMEOUT_SECONDS = 140",
            "MAX_PROVIDER_REQUEST_FRAME_BYTES = 96 * 1024",
            "MAX_PROVIDER_RESPONSE_FRAME_BYTES = 64 * 1024",
            "PROVIDER_RELAY_LOCK.acquire(blocking=False)",
            "socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC",
            "socket.SO_PEERCRED",
            "connection.send(frame)",
            "MAX_PROVIDER_RESPONSE_FRAME_BYTES + 1, 0",
            "socket.MSG_TRUNC | socket.MSG_CTRUNC",
            '"/api/rescue/provider/openai"',
            'self.headers.get_all("Content-Length", [])',
            'self.headers.get_all("Transfer-Encoding")',
            '"Content-Encoding"',
        ):
            self.assertIn(value, source)
        relay_start = source.index("def _validate_root_provider_peer(")
        relay_end = source.index("def _remaining_seconds(", relay_start)
        relay = source[relay_start:relay_end]
        for forbidden in (
            "kernaid-rescue-vault",
            "api_key",
            "Authorization",
            "Bearer",
            "json.loads",
            "subprocess",
        ):
            self.assertNotIn(forbidden, relay)
        self.assertLess(
            source.index("connection.send(frame)"),
            source.index("connection.recvmsg(", relay_start),
        )

    def test_seqpacket_socket_is_bounded_and_ui_only(self) -> None:
        sections = unit_sections(EXECUTOR_SOCKET)
        self.assertEqual(
            sections["Socket"],
            {
                "ListenSequentialPacket": "/run/kernaid-rescue-openai.sock",
                "Accept": "yes",
                "MaxConnections": "4",
                "Backlog": "4",
                "SocketMode": "0660",
                "SocketUser": "root",
                "SocketGroup": "kernaid-provider-client",
                "RemoveOnStop": "yes",
                "PassCredentials": "no",
                "PassSecurity": "no",
                "PassPacketInfo": "no",
                "Timestamping": "off",
            },
        )
        self.assertEqual(
            sections["Unit"],
            {
                "Description": "KernAid Rescue OpenAI application socket",
                "Requires": "systemd-sysusers.service",
                "After": "systemd-sysusers.service",
                "Before": "kernaid-ui.service",
                "ConditionKernelCommandLine": "boot=live",
            },
        )
        self.assertEqual(sections["Install"], {"WantedBy": "sockets.target"})

        ui = unit_sections(UI_SERVICE)
        groups = ui["Service"]["SupplementaryGroups"].split()
        self.assertIn("kernaid-provider-client", groups)
        self.assertNotIn("kernaid-vault", groups)
        self.assertNotIn("kernaid-openai", groups)
        self.assertIn("kernaid-rescue-openai-executor.socket", ui["Unit"]["Requires"])

    def test_per_connection_service_has_no_network_caps_logs_or_writable_surface(self) -> None:
        sections = unit_sections(EXECUTOR_SERVICE)
        unit = sections["Unit"]
        service = sections["Service"]
        self.assertIn("kernaid-rescue-openai-executor.socket", unit["Requires"])
        self.assertIn("kernaid-rescue-openai-egress.socket", unit["Requires"])
        self.assertIn("kernaid-rescue-vaultd.socket", unit["Requires"])
        self.assertEqual(unit["BindsTo"], "kernaid-rescue-vaultd.service")
        self.assertIn("kernaid-rescue-vaultd.service", unit["After"].split())
        self.assertEqual(unit["CollectMode"], "inactive-or-failed")
        self.assertEqual(
            service,
            {
                "Type": "simple",
                "ExecStart": "/usr/lib/kernaid/kernaid-rescue-openai-executor",
                "RuntimeMaxSec": "145s",
                "TimeoutStartSec": "5s",
                "TimeoutStopSec": "10s",
                "Restart": "no",
                "StandardInput": "socket",
                "StandardOutput": "null",
                "StandardError": "null",
                "User": "kernaid-openai",
                "Group": "kernaid-openai",
                "SupplementaryGroups": "kernaid-vault",
                "UMask": "0077",
                "LimitCORE": "0",
                "LimitNOFILE": "16",
                "TasksMax": "1",
                "Delegate": "pids",
                "DelegateSubgroup": "agent",
                "KillMode": "control-group",
                "SendSIGKILL": "yes",
                "NoNewPrivileges": "yes",
                "PrivateMounts": "yes",
                "PrivateNetwork": "yes",
                "PrivateTmp": "yes",
                "PrivateDevices": "yes",
                "PrivateIPC": "yes",
                "ProtectSystem": "strict",
                "ProtectHome": "yes",
                "ProtectControlGroups": "yes",
                "ProtectKernelLogs": "yes",
                "ProtectKernelModules": "yes",
                "ProtectKernelTunables": "yes",
                "ProtectClock": "yes",
                "ProtectHostname": "yes",
                "ProtectProc": "invisible",
                "ProcSubset": "pid",
                "DevicePolicy": "closed",
                "CapabilityBoundingSet": "",
                "AmbientCapabilities": "",
                "RestrictAddressFamilies": "AF_UNIX",
                "RestrictNamespaces": "yes",
                "RestrictRealtime": "yes",
                "RestrictSUIDSGID": "yes",
                "LockPersonality": "yes",
                "MemoryDenyWriteExecute": "yes",
                "SystemCallArchitectures": "native",
                "KeyringMode": "private",
                "RemoveIPC": "yes",
            },
        )
        for forbidden in (
            "Environment",
            "EnvironmentFile",
            "ReadWritePaths",
            "WorkingDirectory",
            "RootDirectory",
        ):
            self.assertNotIn(forbidden, service)
        self.assertEqual(service["CapabilityBoundingSet"], "")
        self.assertEqual(service["AmbientCapabilities"], "")

    def test_secret_blind_fixed_egress_proxy_is_socket_activated_and_bounded(self) -> None:
        socket_sections = unit_sections(EGRESS_SOCKET)
        self.assertEqual(
            socket_sections["Socket"],
            {
                "ListenStream": "/run/kernaid-rescue-openai-egress.sock",
                "Accept": "no",
                "Backlog": "1",
                "FlushPending": "yes",
                "SocketMode": "0660",
                "SocketUser": "root",
                "SocketGroup": "kernaid-openai",
                "RemoveOnStop": "yes",
                "PassCredentials": "no",
                "PassSecurity": "no",
                "PassPacketInfo": "no",
                "Timestamping": "off",
            },
        )
        self.assertEqual(socket_sections["Install"], {"WantedBy": "sockets.target"})

        sections = unit_sections(EGRESS_SERVICE)
        self.assertEqual(
            sections["Unit"],
            {
                "Description": "KernAid Rescue OpenAI fixed TLS egress proxy",
                "Requires": "kernaid-rescue-openai-egress.socket systemd-sysusers.service",
                "After": "kernaid-rescue-openai-egress.socket network-online.target systemd-sysusers.service",
                "Wants": "network-online.target",
                "CollectMode": "inactive-or-failed",
                "ConditionKernelCommandLine": "boot=live",
                "ConditionPathIsDirectory": "/run/live/medium",
            },
        )
        self.assertEqual(
            sections["Service"],
            {
                "Type": "notify",
                "Sockets": "kernaid-rescue-openai-egress.socket",
                "ExecStart": "/usr/lib/systemd/systemd-socket-proxyd --connections-max=1 --exit-idle-time=10s api.openai.com:443",
                "TimeoutStartSec": "15s",
                "TimeoutStopSec": "10s",
                "Restart": "no",
                "StandardInput": "null",
                "StandardOutput": "null",
                "StandardError": "null",
                "User": "kernaid-openai-egress",
                "Group": "kernaid-openai-egress",
                "SupplementaryGroups": "",
                "UMask": "0077",
                "LimitCORE": "0",
                "LimitNOFILE": "32",
                "TasksMax": "3",
                "MemoryMax": "64M",
                "MemorySwapMax": "0",
                "KillMode": "control-group",
                "SendSIGKILL": "yes",
                "NoNewPrivileges": "yes",
                "PrivateMounts": "yes",
                "PrivateNetwork": "no",
                "PrivateTmp": "yes",
                "PrivateDevices": "yes",
                "PrivateIPC": "yes",
                "ProtectSystem": "strict",
                "ProtectHome": "yes",
                "ProtectControlGroups": "yes",
                "ProtectKernelLogs": "yes",
                "ProtectKernelModules": "yes",
                "ProtectKernelTunables": "yes",
                "ProtectClock": "yes",
                "ProtectHostname": "yes",
                "ProtectProc": "invisible",
                "ProcSubset": "pid",
                "DevicePolicy": "closed",
                "CapabilityBoundingSet": "",
                "AmbientCapabilities": "",
                "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
                "RestrictNamespaces": "yes",
                "RestrictRealtime": "yes",
                "RestrictSUIDSGID": "yes",
                "LockPersonality": "yes",
                "MemoryDenyWriteExecute": "yes",
                "SystemCallArchitectures": "native",
                "KeyringMode": "private",
                "RemoveIPC": "yes",
            },
        )
        text = EGRESS_SERVICE.read_text(encoding="utf-8")
        self.assertNotIn("RuntimeMaxSec", sections["Service"])
        self.assertIn("fixed value 1 can admit at most two connections", text)
        self.assertIn("not the\n# credential boundary", text)
        for forbidden in ("Environment", "EnvironmentFile", "SupplementaryGroups=kernaid"):
            self.assertNotIn(forbidden, text)

    def test_sysusers_assigns_dynamic_agent_and_separates_ui_from_vault(self) -> None:
        lines = active_lines(SYSUSERS)
        self.assertIn("g kernaid-provider-client - -", lines)
        self.assertIn(
            'u kernaid-openai - "KernAid Rescue OpenAI executor" /nonexistent /usr/sbin/nologin',
            lines,
        )
        self.assertIn(
            'u kernaid-openai-egress - "KernAid Rescue OpenAI TLS egress proxy" /nonexistent /usr/sbin/nologin',
            lines,
        )
        self.assertIn("m kernaid-openai kernaid-vault", lines)
        self.assertFalse(any(line.startswith("u kernaid-openai ") and " - " not in line for line in lines))
        self.assertFalse(any(line.startswith("m kernaid-openai-egress ") for line in lines))

        vault = unit_sections(VAULT_SERVICE)["Service"]
        self.assertNotIn("kernaid-provider-client", vault.get("SupplementaryGroups", ""))

        ready = READY_CHECK.read_text(encoding="utf-8")
        self.assertIn("getent passwd kernaid-openai", ready)
        self.assertIn("getent passwd kernaid-openai-egress", ready)
        self.assertIn("getent group kernaid-openai", ready)
        self.assertIn('$4 == ""', ready)
        self.assertIn('count == 1 && !bad', ready)
        self.assertIn("live user unexpectedly has OpenAI egress access", ready)
        self.assertIn('$3 == $4 && $3 != 0 && $3 != 1000', ready)
        self.assertIn('$6 == "/nonexistent"', ready)
        self.assertIn('$7 == "/usr/sbin/nologin"', ready)
        self.assertIn("OpenAI Agent unexpectedly has provider-client access", ready)
        self.assertIn("live user unexpectedly has provider-client access", ready)
        self.assertIn("'^(kernaid|kernaid-openai|kernaid-openai-egress):'", ready)

    def test_ready_gate_requires_exact_provider_socket_without_sending_a_request(self) -> None:
        ready = READY_CHECK.read_text(encoding="utf-8")
        self.assertIn(
            "--value kernaid-rescue-openai-executor.socket)", ready
        )
        self.assertIn(
            "--property=SubState --value kernaid-rescue-openai-executor.socket)",
            ready,
        )
        self.assertIn('case "$provider_socket_substate" in', ready)
        self.assertIn("getent group kernaid-provider-client", ready)
        self.assertIn("test -S /run/kernaid-rescue-openai.sock", ready)
        self.assertIn("0:${provider_group_id}:660:1", ready)
        self.assertIn("--value kernaid-rescue-openai-egress.socket)", ready)
        self.assertIn('case "$egress_socket_substate" in', ready)
        self.assertIn("test -S /run/kernaid-rescue-openai-egress.sock", ready)
        self.assertIn("0:${openai_group_id}:660:1", ready)
        self.assertNotIn("provider.openai.diagnose", ready)
        self.assertNotIn("provider.status", ready)

    def test_qemu_provider_bridge_is_pinned_gated_and_absent_from_the_image(self) -> None:
        helper = PROBE_HELPER.read_bytes()
        self.assertEqual(len(helper), PROBE_SIZE)
        self.assertEqual(hashlib.sha256(helper).hexdigest(), PROBE_SHA256)
        self.assertEqual(list(LIVE_ROOT.rglob(PROBE_HELPER.name)), [])
        self.assertNotIn(PROBE_HELPER.name, BUILD.read_text(encoding="utf-8"))

        ready = READY_CHECK.read_text(encoding="utf-8")
        for value in (
            PROBE_RAW,
            "/run/credentials/@system/provider-lease-probe",
            PROBE_MARKER,
            f"EXPECTED_SIZE = {PROBE_SIZE}",
            f'EXPECTED_SHA256 = "{PROBE_SHA256}"',
            "raw != imported",
            "stat.S_IMODE(after.st_mode) & 0o222",
            "(before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)",
            "kernaid-provider-executor-status-probe.socket",
            "kernaid-provider-lease-probe.socket",
            "kernaid-provider-lease-kill-vaultd.socket",
        ):
            self.assertIn(value, ready)
        self.assertLess(
            ready.index("raw != imported"),
            ready.index("    create_or_validate_marker(sys.argv[3])"),
        )
        self.assertIn('provider_probe_enabled=0', ready)
        self.assertIn('if [ "$raw_present" != "$system_present" ]', ready)
        self.assertIn("QEMU-only provider probe socket exists on a normal boot", ready)

        units = (
            LEASE_PROBE_SOCKET,
            LEASE_PROBE_SERVICE,
            LEASE_KILL_SOCKET,
            LEASE_KILL_SERVICE,
            STATUS_PROBE_SOCKET,
            STATUS_PROBE_SERVICE,
        )
        for path in units:
            text = path.read_text(encoding="utf-8")
            unit = section_lines(path, "Unit")
            self.assertIn("ConditionCredential=provider-lease-probe", unit)
            self.assertIn(
                "ConditionPathExists=/run/credentials/@system/provider-lease-probe",
                unit,
            )
            self.assertIn(f"ConditionPathExists={PROBE_RAW}", unit)
            self.assertIn(f"ConditionPathExists={PROBE_MARKER}", unit)
            self.assertNotIn("[Install]", text)
            self.assertNotIn(f"systemctl enable {path.name}", HOOK.read_text(encoding="utf-8"))
            self.assertIn(f"/etc/systemd/system/{path.name}", HOOK.read_text(encoding="utf-8"))

        for path in (LEASE_PROBE_SERVICE, LEASE_KILL_SERVICE, STATUS_PROBE_SERVICE):
            service = "\n".join(section_lines(path, "Service"))
            self.assertIn("LoadCredential=provider-lease-probe", service)
            self.assertIn(str(PROBE_SIZE), service)
            self.assertIn(PROBE_SHA256, service)
            self.assertIn("${CREDENTIALS_DIRECTORY}/provider-lease-probe", service)

    def test_qemu_provider_bridge_units_keep_roles_and_kill_surface_exact(self) -> None:
        expected_sockets = {
            STATUS_PROBE_SOCKET: (
                "/run/kernaid-provider-executor-status-probe.sock",
                "kernaid-vault",
            ),
            LEASE_PROBE_SOCKET: ("/run/kernaid-provider-lease-probe.sock", "kernaid-vault"),
            LEASE_KILL_SOCKET: (
                "/run/kernaid-provider-lease-kill-vaultd.sock",
                "kernaid-openai",
            ),
        }
        for path, (listen_path, group) in expected_sockets.items():
            socket_section = dict(
                line.split("=", maxsplit=1) for line in section_lines(path, "Socket")
            )
            expected = {
                "ListenStream": listen_path,
                "Accept": "yes",
                "MaxConnections": "1",
                "Backlog": "1",
                "SocketMode": "0660",
                "SocketUser": "root",
                "SocketGroup": group,
                "RemoveOnStop": "yes",
                "PassCredentials": "no",
                "PassSecurity": "no",
                "PassPacketInfo": "no",
                "Timestamping": "off",
            }
            if path == LEASE_KILL_SOCKET:
                expected["TriggerLimitIntervalSec"] = "5min"
                expected["TriggerLimitBurst"] = "1"
            self.assertEqual(socket_section, expected)

        lease = dict(
            line.split("=", maxsplit=1)
            for line in section_lines(LEASE_PROBE_SERVICE, "Service")
        )
        self.assertEqual(lease["User"], "kernaid-openai")
        self.assertEqual(lease["Group"], "kernaid-openai")
        self.assertEqual(lease["SupplementaryGroups"], "kernaid-vault")
        self.assertEqual(lease["TasksMax"], "1")
        self.assertEqual(lease["Delegate"], "pids")
        self.assertEqual(lease["DelegateSubgroup"], "agent")
        self.assertEqual(lease["ProtectControlGroups"], "yes")
        self.assertEqual(lease["PrivateNetwork"], "yes")
        self.assertEqual(lease["RestrictAddressFamilies"], "AF_UNIX")
        self.assertEqual(lease["CapabilityBoundingSet"], "")
        self.assertEqual(lease["AmbientCapabilities"], "")
        self.assertEqual(lease["InaccessiblePaths"], "/run/kernaid-rescue-openai-egress.sock")

        status = dict(
            line.split("=", maxsplit=1)
            for line in section_lines(STATUS_PROBE_SERVICE, "Service")
        )
        self.assertEqual(status["DynamicUser"], "yes")
        self.assertEqual(status["SupplementaryGroups"], "kernaid-provider-client")
        self.assertNotIn("User", status)
        self.assertNotIn("Group", status)
        self.assertEqual(status["TasksMax"], "1")
        self.assertEqual(status["PrivateNetwork"], "yes")
        self.assertEqual(status["RestrictAddressFamilies"], "AF_UNIX")
        self.assertEqual(status["CapabilityBoundingSet"], "")
        self.assertEqual(status["AmbientCapabilities"], "")
        self.assertNotIn("Delegate", status)
        self.assertNotIn("DelegateSubgroup", status)
        self.assertEqual(
            status["InaccessiblePaths"],
            "/run/kernaid-rescue-openai-egress.sock /run/kernaid-rescue-vault.sock",
        )

        kill = dict(
            line.split("=", maxsplit=1)
            for line in section_lines(LEASE_KILL_SERVICE, "Service")
        )
        self.assertEqual(
            kill["ExecStart"],
            "/usr/bin/systemctl --no-ask-password --no-pager kill --signal=KILL --kill-whom=main kernaid-rescue-vaultd.service",
        )
        self.assertEqual(kill["StandardInput"], "null")
        self.assertEqual(kill["StandardOutput"], "null")
        self.assertEqual(kill["StandardError"], "null")
        self.assertEqual(kill["SupplementaryGroups"], "")
        self.assertEqual(kill["CapabilityBoundingSet"], "")
        self.assertEqual(kill["AmbientCapabilities"], "")
        self.assertNotIn("Delegate", kill)
        self.assertNotIn("DelegateSubgroup", kill)
        self.assertIn(
            "ConditionPathExists=/run/kernaid-rescue-vault/lifecycle-active-v1",
            section_lines(LEASE_KILL_SERVICE, "Unit"),
        )

    def test_qemu_provider_helper_has_closed_commands_and_never_reads_the_key_pipe(self) -> None:
        source = PROBE_HELPER.read_text(encoding="utf-8")
        for value in (
            'NORMAL_COMMAND = b"NORMAL\\n"',
            'HOLD_COMMAND = b"HOLD\\n"',
            'STATUS_COMMAND = b"STATUS\\n"',
            "KERNAID_PROVIDER_LEASE_PROBE_NORMAL_V1 borrowed=true unread=true",
            "KERNAID_PROVIDER_LEASE_PROBE_HOLD_V1 borrowed=true unread=true",
            "KERNAID_PROVIDER_EXECUTOR_STATUS_PROBE_V1 status=true shipping=true",
            'VAULT_SOCKET = "/run/kernaid-rescue-vault.sock"',
            'PROVIDER_SOCKET = "/run/kernaid-rescue-openai.sock"',
            'KILL_SOCKET = "/run/kernaid-provider-lease-kill-vaultd.sock"',
            "socket.SOCK_SEQPACKET",
            "socket.SCM_RIGHTS",
            "PIPEFS_MAGIC",
            "FIONREAD",
            "select.POLLHUP",
            "time.sleep(15.0)",
        ):
            self.assertIn(value, source)
        self.assertNotIn("os.read(", source)
        self.assertNotIn("print(", source)
        self.assertNotIn("subprocess", source)
        status_branch = source.index("if command == STATUS_COMMAND:")
        direct_vault = source.index("state_version = _observe_unlocked()", status_branch)
        self.assertLess(status_branch, direct_vault)

    def test_binary_staging_hook_and_workflow_are_coordinated(self) -> None:
        hook = HOOK.read_text(encoding="utf-8")
        build = BUILD.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for text in (hook, build, workflow):
            self.assertIn("kernaid-rescue-openai-executor", text)
        self.assertIn("systemctl enable kernaid-rescue-openai-executor.socket", hook)
        self.assertIn("systemctl enable kernaid-rescue-openai-egress.socket", hook)
        self.assertIn("/usr/lib/systemd/systemd-socket-proxyd", hook)
        self.assertIn("KERNAID_RESCUE_OPENAI_EXECUTOR_BINARY", build)
        self.assertIn('- "crates/rescue-openai-executor/**"', workflow)
        self.assertIn('- "crates/rescue-openai-provider/**"', workflow)
        self.assertIn(
            "cargo clippy --locked -p kernaid-rescue-openai-executor --all-targets -- -D warnings",
            workflow,
        )
        self.assertIn("cargo test --locked -p kernaid-rescue-openai-executor", workflow)

        vault_workflow = VAULT_WORKFLOW.read_text(encoding="utf-8")
        for dependency in (
            '"packages/schemas/rescue-openai-request.schema.json"',
            '"packages/schemas/rescue-openai-response.schema.json"',
            '"packages/schemas/fixtures/rescue-openai/**"',
            '"rust-toolchain.toml"',
        ):
            self.assertIn(dependency, vault_workflow)

    def test_executor_source_has_one_fixed_borrow_and_no_configurable_network_surface(self) -> None:
        source = EXECUTOR_SOURCE.read_text(encoding="utf-8")
        self.assertIn("ClientRequestPayload::ProviderStatus", source)
        self.assertIn("ClientRequestPayload::VaultStatus", source)
        self.assertIn("ClientRequestPayload::ProviderOpenAiBorrow", source)
        self.assertIn('const OPENAI_HOST: &str = "api.openai.com";', source)
        self.assertIn('const EGRESS_SOCKET_PATH: &str = "/run/kernaid-rescue-openai-egress.sock";', source)
        self.assertIn(
            'b"POST /v1/responses HTTP/1.1\\r\\nHost: api.openai.com\\r\\nAuthorization: Bearer ',
            source,
        )
        self.assertIn("ProviderErrorCode::CredentialUnavailable", source)
        self.assertIn("DumpableBehavior::NotDumpable", source)
        for forbidden in (
            "ProviderCodexHomeLease",
            "std::env",
            "println!",
            "eprintln!",
            "TcpStream",
            "UdpSocket",
        ):
            self.assertNotIn(forbidden, source)

    def test_key_borrow_pipe_and_exact_agent_lease_are_reachable_but_closed(self) -> None:
        wire = VAULT_WIRE_SOURCE.read_text(encoding="utf-8")
        worker = VAULT_WORKER_SOURCE.read_text(encoding="utf-8")
        runtime = VAULT_RUNTIME_SOURCE.read_text(encoding="utf-8")
        server = VAULT_SERVER_SOURCE.read_text(encoding="utf-8")
        self.assertIn('b"KRVWC002"', wire)
        self.assertIn('b"KRVWR002"', wire)
        self.assertIn("ProviderOpenAiBorrow", wire)
        self.assertIn("validate_internal_output_pipe", worker)
        self.assertIn("with_openai_api_key", worker)
        self.assertIn("pub(super) fn borrow_openai", runtime)
        self.assertIn("ioctl_fionread", runtime)

        allowlist_start = server.index("fn external_operation_is_enabled(")
        allowlist_end = server.index("fn status_version_is_accepted(", allowlist_start)
        self.assertIn("ProviderOpenAiBorrow", server[allowlist_start:allowlist_end])
        dispatch_start = server.index("fn handle_connected_request(")
        dispatch_end = server.index("fn handle_request(", dispatch_start)
        self.assertIn("ProviderOpenAiBorrow", server[dispatch_start:dispatch_end])
        self.assertIn("PeerPidfd", server)
        production_server = server[: server.index("\n#[cfg(test)]\nmod tests")]
        self.assertNotIn("pidfd_open", production_server)
        self.assertIn("provider_lease", server)
        for value in (
            "ProcessScope::CgroupTree",
            "ProviderProcessBoundary",
            "PROVIDER_UNIT_ROOT_AGENT_CONTROLS",
            "PROVIDER_SUBGROUP_AGENT_CONTROLS",
            'validate_provider_root_control_file(&kill, &root, 0o200)',
            'open_cgroup_file(&root, "cgroup.kill", OFlags::WRONLY)',
            "PollFlags::PRI | PollFlags::ERR",
            "garbage_collection_evidence_is_terminal",
            "retained_events_nodev",
            "retained_kill_nodev",
            "lease_release_evidence_is_complete",
        ):
            self.assertIn(value, server + runtime)
        self.assertNotIn(
            "validate_cgroup_directory(&root, Some(&parent))", runtime
        )

        service = unit_sections(EXECUTOR_SERVICE)["Service"]
        self.assertEqual(service["PrivateNetwork"], "yes")
        self.assertEqual(service["RestrictAddressFamilies"], "AF_UNIX")


if __name__ == "__main__":
    unittest.main()
