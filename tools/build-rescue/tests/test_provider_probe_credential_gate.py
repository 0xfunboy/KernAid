import ast
import hashlib
import os
import stat
import types
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
READY_CHECK = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
)


def load_production_pinned_read() -> tuple[dict[str, object], str]:
    ready = READY_CHECK.read_text(encoding="utf-8")
    start_marker = (
        'python3 - "$provider_probe_raw" "$provider_probe_system" '
        '"$provider_probe_marker" <<\'PY\'\n'
    )
    source = ready.split(start_marker, maxsplit=1)[1].split("\nPY\n", maxsplit=1)[0]
    parsed = ast.parse(source, filename=str(READY_CHECK))
    selected = []
    for node in parsed.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id in {"EXPECTED_SIZE", "EXPECTED_SHA256", "MARKER"}
            for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "pinned_read":
            selected.append(node)
    namespace: dict[str, object] = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(READY_CHECK), "exec"), namespace)
    return namespace, source


class FakeOs:
    O_RDONLY = os.O_RDONLY
    O_CLOEXEC = os.O_CLOEXEC
    O_NOFOLLOW = os.O_NOFOLLOW

    def __init__(
        self,
        data: bytes,
        *,
        stat_size: int,
        mode: int = stat.S_IFREG | 0o400,
        nlink: int = 1,
    ) -> None:
        self.data = data
        self.offset = 0
        self.closed = False
        self.metadata = types.SimpleNamespace(
            st_dev=7,
            st_ino=11,
            st_mode=mode,
            st_uid=0,
            st_gid=0,
            st_nlink=nlink,
            st_size=stat_size,
        )

    def lstat(self, _path: str) -> object:
        return self.metadata

    def open(self, _path: str, flags: int) -> int:
        expected = self.O_RDONLY | self.O_CLOEXEC | self.O_NOFOLLOW
        if flags != expected:
            raise AssertionError("production gate used unexpected open flags")
        return 19

    def fstat(self, descriptor: int) -> object:
        if descriptor != 19:
            raise AssertionError("production gate used unexpected descriptor")
        return self.metadata

    def read(self, descriptor: int, count: int) -> bytes:
        if descriptor != 19 or count <= 0:
            raise AssertionError("production gate issued an invalid read")
        block = self.data[self.offset : self.offset + count]
        self.offset += len(block)
        return block

    def close(self, descriptor: int) -> None:
        if descriptor != 19:
            raise AssertionError("production gate closed an unexpected descriptor")
        self.closed = True


class ProviderProbeCredentialGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace, self.source = load_production_pinned_read()
        self.expected_size = int(self.namespace["EXPECTED_SIZE"])
        self.data = bytes((index % 251) + 1 for index in range(self.expected_size))
        self.namespace["EXPECTED_SHA256"] = hashlib.sha256(self.data).hexdigest()

    def run_gate(
        self,
        *,
        expected_stat_size: int,
        stat_size: int,
        data: bytes | None = None,
        mode: int = stat.S_IFREG | 0o400,
        nlink: int = 1,
    ) -> tuple[bytes, FakeOs]:
        fake = FakeOs(
            self.data if data is None else data,
            stat_size=stat_size,
            mode=mode,
            nlink=nlink,
        )
        self.namespace["os"] = fake
        pinned_read = self.namespace["pinned_read"]
        result = pinned_read("/fixed-test-path", expected_stat_size=expected_stat_size)
        return result, fake

    def test_sysfs_raw_size_zero_and_imported_regular_size_are_distinct(self) -> None:
        raw, raw_os = self.run_gate(expected_stat_size=0, stat_size=0)
        imported, imported_os = self.run_gate(
            expected_stat_size=self.expected_size,
            stat_size=self.expected_size,
        )
        self.assertEqual(raw, self.data)
        self.assertEqual(imported, self.data)
        self.assertTrue(raw_os.closed)
        self.assertTrue(imported_os.closed)

    def test_metadata_content_and_bound_regressions_fail_closed(self) -> None:
        cases = (
            {"expected_stat_size": 0, "stat_size": 1},
            {"expected_stat_size": self.expected_size, "stat_size": 0},
            {
                "expected_stat_size": 0,
                "stat_size": 0,
                "data": self.data + b"X",
            },
            {
                "expected_stat_size": 0,
                "stat_size": 0,
                "data": self.data[:-1] + b"X",
            },
            {
                "expected_stat_size": 0,
                "stat_size": 0,
                "mode": stat.S_IFREG | 0o600,
            },
            {"expected_stat_size": 0, "stat_size": 0, "nlink": 2},
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.run_gate(**case)

    def test_production_calls_pin_each_metadata_shape_explicitly(self) -> None:
        self.assertIn(
            "raw = pinned_read(sys.argv[1], expected_stat_size=0)", self.source
        )
        self.assertIn(
            "imported = pinned_read(sys.argv[2], expected_stat_size=EXPECTED_SIZE)",
            self.source,
        )
        self.assertIn("after.st_size != expected_stat_size", self.source)
        self.assertNotIn("after.st_size != EXPECTED_SIZE", self.source)


if __name__ == "__main__":
    unittest.main()
