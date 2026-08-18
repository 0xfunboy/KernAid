from __future__ import annotations

import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
LIVE_ROOT = REPO_DIR / "rescue/live-build/config/includes.chroot"
SYSTEMD = LIVE_ROOT / "etc/systemd/system"
EXECUTOR_SOCKET = SYSTEMD / "kernaid-rescue-openai-executor.socket"
EXECUTOR_SERVICE = SYSTEMD / "kernaid-rescue-openai-executor@.service"
VAULT_SERVICE = SYSTEMD / "kernaid-rescue-vaultd.service"
UI_SERVICE = SYSTEMD / "kernaid-ui.service"
SYSUSERS = LIVE_ROOT / "etc/sysusers.d/kernaid.conf"
HOOK = REPO_DIR / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
BUILD = REPO_DIR / "tools/build-rescue/build.sh"
WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"
VAULT_WORKFLOW = REPO_DIR / ".github/workflows/vault.yml"
EXECUTOR_SOURCE = REPO_DIR / "crates/rescue-openai-executor/src/linux.rs"
READY_CHECK = LIVE_ROOT / "usr/lib/kernaid/ready-check"


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


class RescueOpenAiExecutorPackagingTests(unittest.TestCase):
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
        self.assertIn("kernaid-rescue-openai-executor.socket", ui["Unit"]["Requires"])

    def test_per_connection_service_has_no_network_caps_logs_or_writable_surface(self) -> None:
        sections = unit_sections(EXECUTOR_SERVICE)
        unit = sections["Unit"]
        service = sections["Service"]
        self.assertIn("kernaid-rescue-openai-executor.socket", unit["Requires"])
        self.assertIn("kernaid-rescue-vaultd.socket", unit["Requires"])
        self.assertEqual(unit["CollectMode"], "inactive-or-failed")
        self.assertEqual(
            service,
            {
                "Type": "simple",
                "ExecStart": "/usr/lib/kernaid/kernaid-rescue-openai-executor",
                "RuntimeMaxSec": "5s",
                "TimeoutStartSec": "5s",
                "TimeoutStopSec": "1s",
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

    def test_sysusers_assigns_dynamic_agent_and_separates_ui_from_vault(self) -> None:
        lines = active_lines(SYSUSERS)
        self.assertIn("g kernaid-provider-client - -", lines)
        self.assertIn(
            'u kernaid-openai - "KernAid Rescue OpenAI executor" /nonexistent /usr/sbin/nologin',
            lines,
        )
        self.assertIn("m kernaid-openai kernaid-vault", lines)
        self.assertFalse(any(line.startswith("u kernaid-openai ") and " - " not in line for line in lines))

        vault = unit_sections(VAULT_SERVICE)["Service"]
        self.assertNotIn("kernaid-provider-client", vault.get("SupplementaryGroups", ""))

        ready = READY_CHECK.read_text(encoding="utf-8")
        self.assertIn("getent passwd kernaid-openai", ready)
        self.assertIn('$3 == $4 && $3 != 0 && $3 != 1000', ready)
        self.assertIn('$6 == "/nonexistent"', ready)
        self.assertIn('$7 == "/usr/sbin/nologin"', ready)
        self.assertIn("OpenAI Agent unexpectedly has provider-client access", ready)
        self.assertIn("live user unexpectedly has provider-client access", ready)
        self.assertIn("'^(kernaid|kernaid-openai):'", ready)

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
        self.assertNotIn("provider.openai.diagnose", ready)
        self.assertNotIn("provider.status", ready)

    def test_binary_staging_hook_and_workflow_are_coordinated(self) -> None:
        hook = HOOK.read_text(encoding="utf-8")
        build = BUILD.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for text in (hook, build, workflow):
            self.assertIn("kernaid-rescue-openai-executor", text)
        self.assertIn("systemctl enable kernaid-rescue-openai-executor.socket", hook)
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

    def test_executor_source_has_no_key_borrow_network_environment_or_output_path(self) -> None:
        source = EXECUTOR_SOURCE.read_text(encoding="utf-8")
        self.assertIn("ClientRequestPayload::ProviderStatus", source)
        self.assertIn("ClientRequestPayload::VaultStatus", source)
        self.assertIn("ProviderErrorCode::CredentialUnavailable", source)
        self.assertIn("DumpableBehavior::NotDumpable", source)
        for forbidden in (
            "ProviderOpenAiBorrow",
            "ProviderCodexHomeLease",
            "std::env",
            "println!",
            "eprintln!",
            "TcpStream",
            "UdpSocket",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
