# KernAid Fleet Resident for Linux

The Debian package installs the device-bound diagnostic Resident, typed
work-order worker, signed update stager and qualified UEFI A/B activator. It
does not enroll, enable a service, alter boot state or reboot during package
installation.

After installing the package, the enrolled desktop user runs:

```sh
kernaid-fleet-resident-setup \
  --endpoint https://fleet.example.com \
  --tenant tenant-id \
  --service-anchor ./fleet-service.pub \
  --entitlement-anchor ./entitlement-issuer.pub \
  --policy-anchor ./policy-issuer.pub \
  --update-anchor ./update-issuer.pub \
  --enrollment-token-file ./enrollment-token \
  --enable --enable-linger
```

The setup command accepts only an HTTPS origin, verifies canonical Ed25519
anchors, creates owner-only configuration/state, installs hardened user units
and optionally enables the diagnostic services. Enrollment consumes the
short-lived token. Update staging and boot activation always remain disabled
until their separate device qualification is complete.

The build workflow emits an amd64 `.deb` and adjacent SHA-256 file. Production
distribution still requires repository/package signing and qualification on
the supported Linux matrix.

Before upload, the native Linux job extracts that exact `.deb` into an isolated
temporary root, rejects maintainer scripts, symlinks and pre-enabled systemd
links, checks the packaged claim/result contract, and invokes `--once` with no
identity or anchors. The expected fail-closed result proves the one-shot entry
point without contacting Fleet; the job then removes the complete staging
root. See `deploy/fleet-resident-lifecycle/README.md` for the boundary.
