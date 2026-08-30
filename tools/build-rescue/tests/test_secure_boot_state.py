from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = (
    REPO
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/secure_boot_state.py"
)
READY_CHECK = (
    REPO
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
)

SPEC = importlib.util.spec_from_file_location("kernaid_secure_boot_state", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Secure Boot state probe could not be loaded")
secure_boot_state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secure_boot_state)


class SecureBootStateTests(unittest.TestCase):
    @staticmethod
    def write_variable(root: Path, name: str, guid: str, value: int) -> None:
        (root / f"{name}-{guid}").write_bytes(struct.pack("<I", 6) + bytes((value,)))

    def state(self, *, secure: int = 1, setup: int = 0, mok: int | None = None) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_variable(
                root,
                "SecureBoot",
                secure_boot_state.EFI_GLOBAL_VARIABLE_GUID,
                secure,
            )
            self.write_variable(
                root,
                "SetupMode",
                secure_boot_state.EFI_GLOBAL_VARIABLE_GUID,
                setup,
            )
            if mok is not None:
                self.write_variable(
                    root,
                    "MokSBStateRT",
                    secure_boot_state.SHIM_LOCK_GUID,
                    mok,
                )
            previous = secure_boot_state.EFIVARS_DIRECTORY
            secure_boot_state.EFIVARS_DIRECTORY = root
            try:
                return secure_boot_state.attest()
            finally:
                secure_boot_state.EFIVARS_DIRECTORY = previous

    def test_attests_only_enforcing_firmware_and_shim_state(self) -> None:
        self.assertEqual(self.state(), secure_boot_state.ATTESTATION)
        self.assertEqual(self.state(mok=0), secure_boot_state.ATTESTATION)
        for options in ({"secure": 0}, {"setup": 1}, {"mok": 1}):
            with self.subTest(options=options):
                with self.assertRaises(secure_boot_state.SecureBootStateError):
                    self.state(**options)

    def test_rejects_missing_or_malformed_firmware_variables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_variable(
                root,
                "SecureBoot",
                secure_boot_state.EFI_GLOBAL_VARIABLE_GUID,
                1,
            )
            previous = secure_boot_state.EFIVARS_DIRECTORY
            secure_boot_state.EFIVARS_DIRECTORY = root
            try:
                with self.assertRaises(secure_boot_state.SecureBootStateError):
                    secure_boot_state.attest()
                setup = root / (
                    "SetupMode-" + secure_boot_state.EFI_GLOBAL_VARIABLE_GUID
                )
                setup.write_bytes(b"malformed")
                with self.assertRaises(secure_boot_state.SecureBootStateError):
                    secure_boot_state.attest()
            finally:
                secure_boot_state.EFIVARS_DIRECTORY = previous

    def test_ready_check_emits_the_allowlisted_marker_before_general_ready(self) -> None:
        source = READY_CHECK.read_text(encoding="utf-8")
        marker = secure_boot_state.ATTESTATION
        self.assertIn("opt/kernaid-secure-boot-probe/raw", source)
        self.assertIn("/usr/lib/kernaid/secure_boot_state.py", source)
        self.assertEqual(source.count(f'"{marker}"'), 1)
        self.assertLess(
            source.index('printf \'\\n%s\\n\' "$secure_boot_attestation"'),
            source.index("echo KERNAID_RESCUE_READY"),
        )


if __name__ == "__main__":
    unittest.main()
