from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]
SERVER = (
    REPO
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/rescue_server.py"
)
HANDOFF = SERVER.with_name("repair_target_handoff.py")
RENDERER = SERVER.with_name("render_rescue_server.py")
VERIFIER = REPO / "tools/build-rescue/verify-repair-surface.py"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RepairSurfaceSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.renderer = load_module("kernaid_rescue_server_renderer", RENDERER)
        cls.verifier = load_module("kernaid_repair_surface_verifier", VERIFIER)
        cls.template = SERVER.read_text(encoding="utf-8")
        cls.handoff_template = HANDOFF.read_text(encoding="utf-8")

    def test_server_renderer_removes_candidate_from_stable_only(self) -> None:
        stable = self.renderer.render_source(self.template, False)
        candidate = self.renderer.render_source(self.template, True)
        for token in self.verifier.SERVER_DIAGNOSIS_TOKENS:
            self.assertIn(token.decode("ascii"), stable)
            self.assertIn(token.decode("ascii"), candidate)
        for token in self.verifier.SERVER_REPAIR_TOKENS:
            decoded = token.decode("ascii")
            self.assertNotIn(decoded, stable)
            self.assertIn(decoded, candidate)
        self.assertNotIn(self.renderer.BEGIN, stable)
        self.assertNotIn(self.renderer.END, stable)
        self.assertNotIn(self.renderer.BEGIN, candidate)
        self.assertNotIn(self.renderer.END, candidate)

    def test_verifier_accepts_only_matching_rendered_server_and_desk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode, include_candidate in (("stable", False), ("candidate", True)):
                profile = root / mode
                desk = profile / "desk"
                desk.mkdir(parents=True)
                desk_payload = b" ".join(self.verifier.DESK_DIAGNOSIS_TOKENS)
                if include_candidate:
                    desk_payload += b" " + b" ".join(
                        self.verifier.DESK_REPAIR_TOKENS
                    )
                (desk / "index.html").write_bytes(b"<html></html>")
                (desk / "bundle.js").write_bytes(desk_payload)
                server = profile / "rescue_server.py"
                server.write_text(
                    self.renderer.render_source(self.template, include_candidate),
                    encoding="utf-8",
                )
                handoff = profile / "repair_target_handoff.py"
                handoff.write_text(
                    self.renderer.render_source(
                        self.handoff_template, include_candidate, 21
                    ),
                    encoding="utf-8",
                )
                vaultd = profile / "kernaid-rescue-vaultd"
                vaultd_payload = b"stable-vault"
                if include_candidate:
                    vaultd_payload += b" " + b" ".join(
                        self.verifier.VAULT_WRITE_TOKENS
                    )
                vaultd.write_bytes(vaultd_payload)
                self.verifier.verify_desk(desk, mode)
                self.verifier.verify_server(server, mode)
                self.verifier.verify_handoff(handoff, mode)
                self.verifier.verify_vaultd(vaultd, mode)
                other = "candidate" if mode == "stable" else "stable"
                with self.assertRaises(ValueError):
                    self.verifier.verify_desk(desk, other)
                with self.assertRaises(ValueError):
                    self.verifier.verify_server(server, other)
                with self.assertRaises(ValueError):
                    self.verifier.verify_handoff(handoff, other)
                with self.assertRaises(ValueError):
                    self.verifier.verify_vaultd(vaultd, other)

    def test_vite_and_workflows_bind_candidate_at_build_time(self) -> None:
        main = (REPO / "apps/desk/src/main.tsx").read_text(encoding="utf-8")
        vite = (REPO / "apps/desk/vite.config.ts").read_text(encoding="utf-8")
        stable_workflow = (REPO / ".github/workflows/rescue.yml").read_text(
            encoding="utf-8"
        )
        candidate_workflow = (
            REPO / ".github/workflows/rescue-repair-candidate.yml"
        ).read_text(encoding="utf-8")
        desktop_workflow = (REPO / ".github/workflows/desktop.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('from "./rescue-repair-entry"', main)
        self.assertNotIn('from "./rescue-repair-panel"', main)
        self.assertIn("rescue-repair-entry.candidate.tsx", vite)
        self.assertIn("KERNAID_REPAIR_CANDIDATE", vite)
        self.assertIn("process.env.KERNAID_REPAIR_CANDIDATE", vite)
        self.assertNotIn("loadEnv", vite)
        self.assertNotIn(
            "KERNAID_REPAIR_CANDIDATE=1 pnpm --filter @kernaid/desk build",
            stable_workflow,
        )
        self.assertIn(
            "KERNAID_REPAIR_CANDIDATE=1 pnpm --filter @kernaid/desk build",
            candidate_workflow,
        )
        self.assertIn('KERNAID_REPAIR_CANDIDATE: "0"', desktop_workflow)
        self.assertIn("verify-stable-dist.mjs", desktop_workflow)
        self.assertIn("python3 -B -m unittest", stable_workflow)
        self.assertIn("python3 -B -m unittest", candidate_workflow)
        self.assertIn("--mode stable --iso KernAid-Rescue-amd64.iso", stable_workflow)
        self.assertIn(
            "--mode candidate --iso "
            "KernAid-Rescue-amd64-repair-candidate.iso",
            candidate_workflow,
        )

    def test_xorriso_tolerates_sparse_vault_partition_before_opening_iso(self) -> None:
        source = VERIFIER.read_text(encoding="utf-8")
        command = source[source.index('                _tool("xorriso"),') :]
        self.assertLess(command.index('"-return_with"'), command.index('"-indev"'))


if __name__ == "__main__":
    unittest.main()
