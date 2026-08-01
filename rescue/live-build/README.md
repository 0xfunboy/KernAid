# Rescue image

This Debian 13 (`trixie`) live-build profile creates an amd64 hybrid ISO for legacy BIOS and UEFI. It starts XFCE and opens the local KernAid Desk web bundle in Chromium app mode. Host storage automount is denied for the live user; no target disk is attached during the QEMU smoke test.

Build in a disposable Debian environment with `sudo just build-rescue`. The GitHub `rescue` workflow builds the image, waits for a serial readiness marker in QEMU BIOS, and uploads the ISO plus SHA-256 checksum.

The generated image is an engineering preview. Secure Boot, encrypted persistence, Wi-Fi coverage, and physical-machine compatibility remain release gates.
