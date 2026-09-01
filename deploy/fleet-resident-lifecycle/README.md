# Native Fleet Resident lifecycle smoke

The three Fleet Resident workflows invoke `install-smoke.py` on their native
runner after assembling the existing development package. The check never
uses an enrollment token, device identity, private key or signature.

It verifies the packaged fixed claim/result routes and schemas, stages the
package outside production locations, exercises the one-shot command until it
fails closed at deliberately absent public anchors, proves startup remains
disabled by default, and removes every staging artifact. The Windows runner
also registers the packaged executable temporarily as an on-demand
`LocalService`, proves it stays stopped, and removes it through the product's
own uninstall command.

Run the repository-level static contract check with:

```sh
python3 deploy/fleet-resident-lifecycle/test_install_smoke.py
```

This is package lifecycle evidence, not production acceptance. It does not
replace code signing/notarization, real enrollment, signed claim/result
exchange, native secret-store acceptance or physical supported-device runs.
