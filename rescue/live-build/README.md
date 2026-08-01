# Rescue image

This Debian 13 (`trixie`) live-build profile creates an amd64 hybrid ISO for legacy BIOS and UEFI. It starts XFCE and opens the local KernAid Desk web bundle in Chromium app mode. Host storage automount is denied for the live user. Each QEMU smoke test attaches a disposable target disk and byte-hashes it before and after boot to prove zero target writes.

Build in a disposable Debian environment with `sudo just build-rescue`. The GitHub `rescue` workflow builds the image, waits for a serial readiness marker in QEMU BIOS and UEFI, verifies zero target writes, and uploads the ISO, SHA-256 checksum, QEMU logs, and derived catalog entry.

The generated image is an engineering preview. Secure Boot, encrypted persistence, Wi-Fi coverage, and physical-machine compatibility remain release gates.
