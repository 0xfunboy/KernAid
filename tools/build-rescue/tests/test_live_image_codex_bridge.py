from __future__ import annotations

import configparser
import json
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
LIVE = REPO / "rescue/live-build/config/includes.chroot"
SYSTEMD = LIVE / "etc/systemd/system"
SOCKET = SYSTEMD / "kernaid-rescue-codex.socket"
SERVICE = SYSTEMD / "kernaid-rescue-codex@.service"
MOUNTER_SOCKET = SYSTEMD / "kernaid-rescue-codex-mounter.socket"
MOUNTER_SERVICE = SYSTEMD / "kernaid-rescue-codex-mounter@.service"
SYSUSERS = LIVE / "etc/sysusers.d/kernaid.conf"
READY = LIVE / "usr/lib/kernaid/ready-check"
HOOK = REPO / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
BUILD = REPO / "tools/build-rescue/build.sh"
WORKFLOW = REPO / ".github/workflows/rescue.yml"
BRIDGE = REPO / "crates/rescue-codex-bridge/src/linux.rs"
WRITER = REPO / "tools/make-device/make_device_v2.py"
LOCK = REPO / "rescue/codex/codex-cli.lock.json"


def unit(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(path.read_text(encoding="utf-8"))
    return parser


class ShippingCodexBridgeTests(unittest.TestCase):
    def test_socket_exposes_only_the_live_user_client_group(self) -> None:
        sections = unit(SOCKET)
        self.assertEqual(
            dict(sections["Socket"]),
            {
                "ListenSequentialPacket": "/run/kernaid-rescue-codex.sock",
                "Accept": "yes",
                "MaxConnections": "1",
                "Backlog": "1",
                "SocketMode": "0660",
                "SocketUser": "root",
                "SocketGroup": "kernaid-codex-client",
                "RemoveOnStop": "yes",
                "PassCredentials": "no",
                "PassSecurity": "no",
                "PassPacketInfo": "no",
                "Timestamping": "off",
            },
        )
        self.assertEqual(sections["Install"]["WantedBy"], "sockets.target")

    def test_instance_is_unprivileged_revocable_and_device_closed(self) -> None:
        sections = unit(SERVICE)
        service = sections["Service"]
        self.assertEqual(service["ExecStart"], "/usr/lib/kernaid/kernaid-rescue-codex")
        self.assertEqual(service["User"], "kernaid-codex")
        self.assertEqual(service["Group"], "kernaid-codex")
        self.assertEqual(service["SupplementaryGroups"], "kernaid-vault")
        self.assertEqual(service["StandardInput"], "socket")
        self.assertEqual(service["StandardOutput"], "null")
        self.assertEqual(service["StandardError"], "null")
        self.assertEqual(service["RuntimeMaxSec"], "1020s")
        self.assertEqual(service["Delegate"], "pids")
        self.assertEqual(service["DelegateSubgroup"], "agent")
        self.assertEqual(service["KillMode"], "control-group")
        self.assertEqual(service["NoNewPrivileges"], "yes")
        self.assertEqual(service["DevicePolicy"], "closed")
        self.assertEqual(service["CapabilityBoundingSet"], "")
        self.assertEqual(service["AmbientCapabilities"], "")
        self.assertEqual(
            service["TemporaryFileSystem"],
            "/run/kernaid-codex-home:rw,nosuid,nodev,noexec,nosymfollow,size=4k,mode=000,uid=0,gid=0",
        )
        self.assertEqual(service["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6")
        self.assertNotIn("RestrictSUIDSGID", service)
        self.assertEqual(sections["Unit"]["BindsTo"], "kernaid-rescue-vaultd.service")

    def test_mount_broker_is_root_only_one_shot_and_capability_narrowed(self) -> None:
        socket = unit(MOUNTER_SOCKET)["Socket"]
        self.assertEqual(
            dict(socket),
            {
                "ListenSequentialPacket": "/run/kernaid-rescue-codex-mounter.sock",
                "Accept": "yes",
                "MaxConnections": "1",
                "Backlog": "1",
                "SocketMode": "0600",
                "SocketUser": "root",
                "SocketGroup": "root",
                "RemoveOnStop": "yes",
                "PassCredentials": "no",
                "PassSecurity": "no",
                "PassPacketInfo": "no",
                "Timestamping": "off",
            },
        )
        service = unit(MOUNTER_SERVICE)["Service"]
        self.assertEqual(
            service["ExecStart"], "/usr/lib/kernaid/kernaid-rescue-codex-mounter"
        )
        self.assertEqual(service["User"], "root")
        self.assertEqual(service["Group"], "root")
        self.assertEqual(service["StandardInput"], "socket")
        self.assertEqual(
            service["CapabilityBoundingSet"],
            "CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETPCAP",
        )
        self.assertEqual(service["AmbientCapabilities"], "")
        self.assertEqual(service["RestrictNamespaces"], "mnt")
        self.assertEqual(service["TasksMax"], "1")
        self.assertEqual(service["ProtectProc"], "invisible")
        self.assertNotIn("ProcSubset", service)
        self.assertNotIn("PrivatePIDs", service)
        self.assertNotIn("RestrictSUIDSGID", service)

    def test_identity_and_readiness_are_exact(self) -> None:
        sysusers = SYSUSERS.read_text(encoding="utf-8")
        self.assertIn("g kernaid-codex 973 -", sysusers)
        self.assertIn(
            'u kernaid-codex 973:973 "KernAid Rescue Codex executor" /nonexistent /usr/sbin/nologin',
            sysusers,
        )
        ready = READY.read_text(encoding="utf-8")
        for value in (
            'test "$codex_identity" = "973:973"',
            "Codex Agent numeric identity collides with another account",
            "Codex Agent has a persistent privileged group membership",
            "/run/kernaid-rescue-codex.sock",
            "258278208",
            "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40",
        ):
            self.assertIn(value, ready)

    def test_protocol_is_auth_only_and_never_opens_auth_json(self) -> None:
        source = BRIDGE.read_text(encoding="utf-8")
        for argv in (
            '&["login", "--device-auth"]',
            '&["login", "status"]',
            '&["logout"]',
        ):
            self.assertIn(argv, source)
        self.assertIn('"auth.json"', source)
        self.assertIn("validate_metadata_only_file", source)
        self.assertIn("ProviderCodexHomeLease", source)
        self.assertIn("env_clear()", source)
        self.assertIn('.env("TMPDIR", "/")', source)
        self.assertIn("MAX_CLI_OUTPUT_BYTES", source)
        for forbidden in (
            "provider.openai.diagnose",
            "broker repair",
            "Command::new(\"sh\")",
            "Command::new(\"bash\")",
        ):
            self.assertNotIn(forbidden, source)

    def test_writer_provisions_one_exclusive_file_store_home(self) -> None:
        writer = WRITER.read_text(encoding="utf-8")
        self.assertIn('CODEX_HOME_NAME = ".kernaid-codex-home-v1"', writer)
        self.assertIn("CODEX_HOME_UID = 973", writer)
        self.assertIn("CODEX_HOME_GID = 973", writer)
        self.assertIn("CODEX_CONFIG = b'cli_auth_credentials_store = \"file\"\\n'", writer)
        self.assertIn("set(os.listdir(codex_home_fd)) != {CODEX_CONFIG_NAME}", writer)

    def test_build_fetches_verifies_stages_and_publishes_the_pinned_cli(self) -> None:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(lock["upstream"]["version"], "0.147.0")
        self.assertEqual(lock["artifact"]["binary"]["installPath"], "/usr/lib/kernaid/codex")
        build = BUILD.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        hook = HOOK.read_text(encoding="utf-8")
        self.assertIn("verify_binary(descriptor, lock, require_root=True)", build)
        self.assertIn('install -o root -g root -m 0755 "$codex_cli_binary"', build)
        self.assertIn("fetch-codex-cli.py --lock rescue/codex/codex-cli.lock.json", workflow)
        self.assertIn("experimental-codex-home-lease", workflow)
        self.assertIn("generate-rescue-sbom.py", workflow)
        self.assertIn("KernAid-Rescue-amd64.codex.cdx.json", workflow)
        self.assertIn("systemctl enable kernaid-rescue-codex.socket", hook)
        self.assertIn("systemctl enable kernaid-rescue-codex-mounter.socket", hook)
        self.assertIn("KERNAID_RESCUE_CODEX_MOUNTER_BINARY", build)
        self.assertIn("--bin kernaid-rescue-codex-mounter", workflow)
        self.assertIn("/usr/lib/kernaid/codex", hook)


if __name__ == "__main__":
    unittest.main()
