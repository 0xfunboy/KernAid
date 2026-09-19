from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]
STAGE = REPO / "tools/build-rescue/stage-assistant.sh"
HOOK = REPO / "rescue/live-build/config/hooks/live/0090-kernaid-assistant.hook.chroot"


class AssistantStagingPermissionsTests(unittest.TestCase):
    def test_chroot_preflight_rejects_owner_only_assets_without_reading_credentials(self) -> None:
        source = HOOK.read_text().split("# BEGIN public assistant asset permissions\n", 1)[1]
        source = source.split("# END public assistant asset permissions", 1)[0]
        self.assertNotIn("gemrouter.key", source)
        with tempfile.TemporaryDirectory(prefix="kernaid-stage-preflight-") as temporary:
            root = Path(temporary)
            assistant = root / "opt/kernaid/assistant"
            modules = assistant / "node_modules/.pnpm"
            modules.mkdir(parents=True)
            search = root / "opt/kernaid/searxng-source"
            search.mkdir()
            directories = [root / "opt", root / "opt/kernaid", assistant,
                           assistant / "node_modules", modules, search]
            for directory in directories:
                directory.chmod(0o755)
            for name in ("server.mjs", "runtime.mjs", "gemrouter-transport.mjs", "defaults.json", "node"):
                asset = assistant / name
                asset.touch(mode=0o644)
                asset.chmod(0o755 if name == "node" else 0o644)
            command = source.replace('"/opt', f'"{root}/opt')

            def preflight() -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(["sh", "-c", command], capture_output=True, check=False)

            self.assertEqual(preflight().returncode, 0)
            for directory in directories:
                with self.subTest(directory=directory.relative_to(root)):
                    directory.chmod(0o700)
                    self.assertNotEqual(preflight().returncode, 0)
                    directory.chmod(0o755)
            (assistant / "runtime.mjs").chmod(0o600)
            self.assertNotEqual(preflight().returncode, 0)
            (assistant / "runtime.mjs").chmod(0o644)
            (assistant / "node").chmod(0o744)
            self.assertNotEqual(preflight().returncode, 0)

    def test_private_caller_mask_does_not_hide_public_runtime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kernaid-stage-permissions-") as temporary:
            root = Path(temporary)
            script = root / "tools/build-rescue/stage-assistant.sh"
            script.parent.mkdir(parents=True)
            shutil.copyfile(STAGE, script)
            image = root / "rescue/live-build/config/includes.chroot"
            (image / "etc/kernaid-assistant").mkdir(parents=True)
            source_dropin = root / "services/rescue-assistant/private-credential.conf"
            source_dropin.parent.mkdir(parents=True)
            shutil.copyfile(
                REPO / "services/rescue-assistant/private-credential.conf", source_dropin
            )
            # A non-secret fixture exercises install permissions only. No real
            # provider credential, dependency download, or network is involved.
            key = root / "private-input"
            key.write_bytes(b"non-secret-permission-fixture\n")
            key.chmod(0o600)
            commands = root / "commands"
            commands.mkdir()
            stubs = {
                "node": '#!/bin/sh\nif [ "${1:-}" = "--version" ]; then echo v24.18.0; fi\n',
                "pnpm": """#!/usr/bin/python3
from pathlib import Path
import sys
destination = Path(sys.argv[-1])
(destination / "node_modules").mkdir(parents=True)
(destination / "server.mjs").write_text("// public runtime fixture\\n")
""",
                "git": """#!/usr/bin/python3
from pathlib import Path
import sys
if sys.argv[1] == "clone":
    destination = Path(sys.argv[4])
    destination.mkdir(parents=True)
    (destination / "setup.py").write_text("# public source fixture\\n")
""",
            }
            for name, source in stubs.items():
                command = commands / name
                command.write_text(source)
                command.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{commands}:/usr/bin:/bin",
                "GITHUB_ACTIONS": "true",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REF": "refs/heads/main",
                "KERNAID_PRIVATE_TESTING": "1",
                "KERNAID_PRIVATE_GEMROUTER_KEY_FILE": str(key),
            }
            result = subprocess.run(
                [
                    "bash", "-c",
                    'umask 077; bash "$1" || exit; test "$(umask)" = 0077',
                    "stage-test", str(script),
                ],
                env=environment, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            for relative in (
                "opt", "opt/kernaid", "opt/kernaid/assistant",
                "opt/kernaid/assistant/node_modules", "opt/kernaid/searxng-source",
            ):
                with self.subTest(directory=relative):
                    self.assertEqual(stat.S_IMODE((image / relative).stat().st_mode), 0o755)
            for relative in (
                "opt/kernaid/assistant/server.mjs", "opt/kernaid/searxng-source/setup.py",
            ):
                with self.subTest(public_file=relative):
                    self.assertEqual(stat.S_IMODE((image / relative).stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            staged_key = image / "etc/kernaid-assistant/gemrouter.key"
            self.assertEqual(stat.S_IMODE(staged_key.stat().st_mode), 0o600)
            staged_dropin = image / "etc/systemd/system/kernaid-assistant.service.d/50-private-credential.conf"
            self.assertEqual(stat.S_IMODE(staged_dropin.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
