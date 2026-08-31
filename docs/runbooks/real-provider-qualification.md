# Real provider and encrypted-persistence qualification

This runbook qualifies one exact KernAid Rescue candidate, account set, USB,
machine and network path. It does not create a general provider, hardware or
production support claim.

It exercises two independent paths:

- **OpenAI diagnosis** uses the technician's OpenAI Platform API key from the
  encrypted Rescue Vault and sends one bounded diagnosis from Desk.
- **ChatGPT/Codex authentication** uses the official Codex device-login flow
  and its isolated `CODEX_HOME` in the Vault. The Phase 0 bridge is
  authentication-only; it neither runs prompts nor supplies the OpenAI key.

Passing one path never substitutes for passing the other.

## Preconditions

- Independently verify the candidate's complete qualification workflow,
  manifest and image SHA-256, then record their non-secret identities.
- Use the same factory-new or disposable USB of at least 32 GB for both boots,
  a non-customer test machine and a safely selectable disposable target.
- Until separately qualified, disable Secure Boot. Prefer wired networking and
  obtain authorization to send the bounded previewed context.
- The technician supplies an authorized OpenAI Platform API key and an eligible
  ChatGPT account. Never record either secret, the Vault passphrase, account
  email or one-time device code.
- Enable `kernaid.native-prompt=vt-v1`. Use only the authorized live-console
  credential belonging to that exact image when a native TTY login is needed.

## Boot one: provision and authenticate

1. Boot the exact USB. On a zero-state medium, create the Vault passphrase at
   first boot and require the complete KernAid UI to paint.
2. Activate **Unlock Vault** (`Alt+U`), enter the passphrase only on the
   dedicated VT and require Desk to return and reload.
3. From a native console as the exact `kernaid` user, configure the independent
   OpenAI API profile:

   ```text
   kernaid-rescue-vaultctl openai-configure
   kernaid-rescue-vaultctl provider-status
   ```

   Enter the key only at the hidden TTY prompt and require OpenAI
   `configured`.
4. Exercise the separate Codex bridge:

   ```text
   kernaid-codex-auth status
   kernaid-codex-auth device-login
   kernaid-codex-auth status
   ```

   Open only the displayed `https://auth.openai.com/codex/device` URL on a
   trusted browser and authorize its one-time code. Require ChatGPT
   authentication. Never run `/usr/lib/kernaid/codex` directly or inspect or
   copy `auth.json`.
5. Preserve both provider states, close the Vault and shut down cleanly:

   ```text
   kernaid-rescue-vaultctl lock
   ```

## Boot two: persistence and live diagnosis

1. Boot the same USB and entry. Before unlock, require Desk to show a locked
   Vault and unavailable credential; neither provider state may be usable.
2. Use **Unlock Vault** again and require Desk to return and reload. Record only
   the non-secret `deviceId` and require it to match boot one.
3. From the native console, require both states to survive:

   ```text
   kernaid-rescue-vaultctl provider-status
   kernaid-codex-auth status
   ```

   The required results are OpenAI `configured` and Codex authenticated with
   ChatGPT.
4. In Desk, select only the disposable target, choose **OpenAI**, complete the
   read-only inspection, enter a non-sensitive objective, generate the
   authoritative context preview and explicitly confirm its digest. Require
   one successful proposal bound to the displayed evidence IDs. Offline
   fallback or a deterministic-only result does not prove live OpenAI TLS.
5. Retain only the signed report ID and preview digest. A report is valid
   evidence only if the Vault was unlocked before this Desk session initialized.

## Cleanup

Remove both profiles through their owning interfaces:

```text
kernaid-rescue-vaultctl openai-logout
kernaid-codex-auth logout
kernaid-rescue-vaultctl provider-status
kernaid-codex-auth status
kernaid-rescue-vaultctl lock
```

Enter `LOGOUT` when requested. Require OpenAI `unconfigured`, Codex
`signed-out` and a final locked Vault before shutdown.

## Result and evidence

Record only candidate/run/commit/manifest/image identities, bounded hardware
and network facts, the matching two-boot `deviceId`, closed provider states,
preview digest, evidence IDs, signed report ID, terminal diagnosis result,
logout results and final Vault state. Do not retain raw provider traffic,
credentials, device codes, account identifiers or screenshots of secret input.

The result is **pass** only when both paths survive the clean reboot, live
OpenAI diagnosis succeeds after explicit context confirmation, both logouts are
verified and no secret enters evidence. A missing safe target is **incomplete**.
Identity drift, state usable while locked, failed persistence,
unconfirmed/fallback diagnosis, failed logout or secret exposure is **fail**;
stop and retain only sanitized evidence.
