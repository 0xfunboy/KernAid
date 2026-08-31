from __future__ import annotations

import re
import struct
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
LIVE_BUILD = REPO_DIR / "rescue/live-build"
INCLUDES = LIVE_BUILD / "config/includes.chroot"
BRANDING = LIVE_BUILD / "branding"
THEME = INCLUDES / "usr/share/plymouth/themes/kernaid"
BUILD_SCRIPT = REPO_DIR / "tools/build-rescue/build.sh"
SAFETY_HOOK = LIVE_BUILD / "config/hooks/live/0100-kernaid-safety.hook.chroot"
BINARY_HOOK = LIVE_BUILD / "config/hooks/live/0200-kernaid-autoboot.hook.binary"
PACKAGE_LIST = LIVE_BUILD / "config/package-lists/kernaid.list.chroot"
FIRSTBOOT = INCLUDES / "etc/systemd/system/kernaid-rescue-firstboot.service"
INDEX = REPO_DIR / "apps/desk/index.html"
BOOT_CSS = REPO_DIR / "apps/desk/src/boot-splash.css"
RESCUE_SHELL = REPO_DIR / "apps/desk/src-tauri-rescue/src/main.rs"
RESCUE_SERVER = INCLUDES / "usr/lib/kernaid/rescue_server.py"
FIRSTBOOT_SOURCE = REPO_DIR / "crates/rescue-secrets/src/firstboot.rs"


def png_dimensions(path: Path) -> tuple[int, int]:
    payload = path.read_bytes()
    if payload[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR":
        raise AssertionError(f"invalid PNG header: {path}")
    return struct.unpack(">II", payload[16:24])


class RescueBootBrandingTests(unittest.TestCase):
    def test_bootloader_artwork_and_visible_copy_are_product_only(self) -> None:
        source = (BRANDING / "kernaid-boot.svg").read_text(encoding="utf-8")
        self.assertIn("INSPECT / DIAGNOSE / REPORT", source)
        self.assertIn("READ-ONLY DIAGNOSIS BY DEFAULT", source)
        self.assertNotRegex(
            source, re.compile(r"\b(?:debian|recover|repair)\b", re.I)
        )

        bios = BRANDING / "kernaid-boot-bios.png"
        uefi = BRANDING / "kernaid-boot-uefi.png"
        self.assertEqual(png_dimensions(bios), (640, 480))
        self.assertEqual(png_dimensions(uefi), (800, 600))

        hook = BINARY_HOOK.read_text(encoding="utf-8")
        self.assertIn(
            'install -m 0644 "$branding_dir/kernaid-boot-bios.png" '
            "binary/isolinux/splash.png",
            hook,
        )
        self.assertIn(
            'install -m 0644 "$branding_dir/kernaid-boot-uefi.png" '
            "binary/boot/grub/splash.png",
            hook,
        )
        for label in (
            "KernAid Rescue",
            "Start KernAid Rescue",
            "KernAid Rescue - Compatibility graphics",
        ):
            self.assertIn(label, hook)

    def test_plymouth_theme_is_pinned_and_firstboot_reclaims_tty1(self) -> None:
        packages = {
            line.strip()
            for line in PACKAGE_LIST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertIn("plymouth", packages)
        self.assertIn("plymouth-themes", packages)

        self.assertEqual(
            (INCLUDES / "etc/plymouth/plymouthd.conf").read_text(
                encoding="utf-8"
            ),
            "[Daemon]\nTheme=kernaid\nShowDelay=0\nDeviceTimeout=8\n",
        )
        descriptor = (THEME / "kernaid.plymouth").read_text(encoding="utf-8")
        script = (THEME / "kernaid.script").read_text(encoding="utf-8")
        self.assertIn("ModuleName=script", descriptor)
        self.assertIn(
            "ScriptFile=/usr/share/plymouth/themes/kernaid/kernaid.script",
            descriptor,
        )
        self.assertIn('Image("kernaid-splash.png")', script)
        self.assertEqual(
            (THEME / "kernaid-splash.png").read_bytes(),
            (BRANDING / "kernaid-boot-uefi.png").read_bytes(),
        )

        hook = SAFETY_HOOK.read_text(encoding="utf-8")
        set_theme = "/usr/sbin/plymouth-set-default-theme kernaid"
        rebuild = "/usr/sbin/update-initramfs -u -k all"
        self.assertIn('test ! -L "$branding_file"', hook)
        self.assertIn('chown root:root /etc/plymouth "$plymouth_theme_dir"', hook)
        self.assertIn('chmod 0755 /etc/plymouth "$plymouth_theme_dir"', hook)
        self.assertIn(set_theme, hook)
        self.assertIn(rebuild, hook)
        self.assertLess(hook.index(set_theme), hook.index(rebuild))

        build = BUILD_SCRIPT.read_text(encoding="utf-8")
        bootappend = re.search(
            r'^bootappend_live="([^"]+)"$', build, re.MULTILINE
        )
        self.assertIsNotNone(bootappend)
        tokens = bootappend.group(1).split() if bootappend else []
        # The bootloader and Desk shell own the two branded visual stages.
        # Starting Plymouth in the initramfs would retain tty1 ahead of the
        # mandatory first-boot Vault prompt.
        self.assertNotIn("splash", tokens)
        self.assertNotIn("plymouth.ignore-serial-consoles", tokens)

        unit = FIRSTBOOT.read_text(encoding="utf-8")
        self.assertNotIn("ExecStartPre=", unit)
        self.assertIn("TTYPath=/dev/tty1", unit)
        before = next(line for line in unit.splitlines() if line.startswith("Before="))
        before_targets = before.removeprefix("Before=").split()
        self.assertNotIn("plymouth-quit.service", before_targets)
        self.assertNotIn("plymouth-quit-wait.service", before_targets)

        firstboot = FIRSTBOOT_SOURCE.read_text(encoding="utf-8")
        preflight = "let preflight = run_rescue_firstboot_preflight()?;"
        dismiss = "dismiss_boot_splash()?;"
        activate = "activate_firstboot_console()?;"
        prompt = "read_firstboot_passphrase_pair()"
        self.assertLess(firstboot.index(preflight), firstboot.index(dismiss))
        self.assertLess(firstboot.index(dismiss), firstboot.index(activate))
        self.assertLess(firstboot.index(activate), firstboot.index(prompt))
        self.assertIn('const PLYMOUTH_PATH: &str = "/usr/bin/plymouth";', firstboot)
        self.assertIn('const CHVT_PATH: &str = "/usr/bin/chvt";', firstboot)
        self.assertIn(
            'const CHVT_TTY1_ARGUMENTS: &[&str] = &["1"];',
            firstboot,
        )
        self.assertIn(
            'const PLYMOUTH_PING_ARGUMENTS: &[&str] = &["--ping"];',
            firstboot,
        )
        self.assertIn("bounded_process::wait", firstboot)
        self.assertIn("if ping_status.success()", firstboot)
        self.assertNotIn('Command::new("/bin/sh")', firstboot)

    def test_console_identification_is_english_kernaid_copy(self) -> None:
        issue = (INCLUDES / "etc/issue").read_text(encoding="utf-8")
        issue_net = (INCLUDES / "etc/issue.net").read_text(encoding="utf-8")
        for copy in (issue, issue_net):
            self.assertIn("KernAid Rescue", copy)
            self.assertNotRegex(copy, re.compile(r"\bdebian\b", re.I))
        self.assertIn("read-only by default", issue.lower())

    def test_pre_react_splash_is_external_csp_safe_and_dark_from_window(self) -> None:
        index = INDEX.read_text(encoding="utf-8")
        css = BOOT_CSS.read_text(encoding="utf-8")
        self.assertIn(
            '<link rel="stylesheet" href="/src/boot-splash.css" />', index
        )
        self.assertIn('class="boot-splash"', index)
        self.assertIn('<meta name="kernaid-bundle" content="desk-v1" />', index)
        self.assertIn("SECURE SYSTEM WORKSPACE", index)
        self.assertIn("Preparing KernAid", index)
        self.assertNotIn("RESCUE ENVIRONMENT", index)
        self.assertIn("READ-ONLY DIAGNOSIS BY DEFAULT", index)
        self.assertNotRegex(index, re.compile(r"<style\b|\bstyle\s*=", re.I))
        scripts = re.findall(r"<script\b([^>]*)>", index, re.I)
        self.assertTrue(scripts)
        self.assertTrue(
            all(re.search(r"\bsrc=", attributes) for attributes in scripts)
        )
        self.assertIn(".boot-splash", css)
        self.assertIn("background: #0d1110", css)

        server = RESCUE_SERVER.read_text(encoding="utf-8")
        self.assertIn('"style-src \'self\'; "', server)
        shell = RESCUE_SHELL.read_text(encoding="utf-8")
        self.assertIn("RESCUE_UI_BUNDLE_MARKER", shell)
        self.assertIn("body.contains(RESCUE_UI_BUNDLE_MARKER)", shell)
        self.assertNotIn('body.contains("<div id=\\"root\\"></div>")', shell)
        self.assertIn(".background_color(Color(13, 17, 16, 255))", shell)


if __name__ == "__main__":
    unittest.main()
