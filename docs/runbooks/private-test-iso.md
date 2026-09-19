# Private testing ISO

The owner has approved the configured Gemrouter test credential for private
testing media. This is a standing build policy, not a per-build question.
The testing profile uses the production Pi harness, `gemini-3.8-flash`, the
`https://gemr.airewardrop.xyz/v1` base and explicit Gemini backend. Public
builds and source control remain credential-free.

## Build

From the canonical checkout, commit and push the intended source, then run:

```sh
gh workflow run rescue.yml --ref main -f private_testing=true
```

The workflow uses repository Actions secrets `KERNAID_TEST_GEMROUTER_KEY` and
`KERNAID_TEST_ISO_PASSPHRASE`. Missing configuration must fail before building.
The operator copies are kept outside Git under
`/home/funboy/.config/kernaid-assistant/`, with owner-only permissions.

Private testing retains the same diagnosis-only build, BIOS/UEFI Secure Boot
and USB-style two-boot checks. It does not run the separate persistence/native
Vault qualification jobs, generate trusted-catalog entries, or promote a
qualified release. Those gates remain independent and open.

The tested ISO and its checksum are bundled and encrypted with GPG AES-256
before artifact upload. No plaintext credential-containing image is uploaded
to the public repository's Actions artifacts. The public build path is
unchanged and does not read the test credential.

## Publish internally

1. Verify the run's source SHA, `private_testing` input and successful base
   build/boot jobs. Download only that run's encrypted private-testing bundle.
2. Decrypt locally using the operator's `test-iso-artifact.pass` file, supplied
   through a file descriptor, never an argument or log. Check the decrypted
   archive entries before extraction and verify its SHA-256 sidecar.
3. Keep the exact ISO and checksum in a new owner-only directory below
   `/home/funboy/KernAid-dist/private`; files must be mode `0600`.
4. Update only `diagnosticCandidate` in `site/content.json`: exact source/run,
   private-testing presentation filename, byte count, SHA-256, passing boot
   coverage and the persistence/repair exclusions. Leave stable metadata and
   trusted catalogs unchanged.
5. Point `KAID_DIAGNOSTIC_CANDIDATE_ISO_PATH` in the user site service to the
   new ISO, reload systemd and restart `kaid-site.service`.
6. Verify public requests cannot download it; after login, verify the candidate
   card and a bounded Range download from the pinned file descriptor.

The customer-facing testing entry is
`https://kaid.funboy.eu.cc/private/downloads/diagnostic-candidate-iso`;
its checksum is at the same route with `-checksum` appended. Authentication
is required. A private download is not a stable release or repair qualification.

## Physical check

Write the hybrid ISO to the selected disposable USB in raw/DD mode. On the
previously affected PC verify visible KernAid startup, network enumeration,
Ethernet/Wi-Fi or explicit offline continuation, an assistant response, target
selection and read-only diagnosis. Record the ISO digest and observed outcome.
Persistence, native Vault prompts and repairs are separate qualification work.
