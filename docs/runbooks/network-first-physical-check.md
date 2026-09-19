# Network-first physical check

Use the latest **private testing ISO** from the diagnostic-candidate card,
not the older stable retail image. Record the ISO filename and SHA-256 before
writing it to the selected disposable USB. On Windows, write the hybrid ISO
in raw/DD mode; the owner's 128 GB test USB has sufficient capacity.

## One short pass

1. Boot the USB and confirm visible KernAid branding and the connection wizard.
2. Check that Ethernet/Wi-Fi adapters appear. Select the intended connection;
   for Wi-Fi, choose the network and enter its password in the network field.
3. Keep the preconfigured Gemrouter model and connect to the assistant. Ask
   a short question and confirm a reply. Ask for a public documentation link
   to exercise web search.
4. Continue to diagnosis, select the intended installed system and confirm
   that the next screen opens rather than leaving only the disk list visible.
5. Run a read-only inspection. If desired, review the summary shown by the
   assistant, approve sharing for that question and ask it to explain it.
6. Reboot once with networking unavailable and confirm that **Continue offline**
   still reaches target selection and local diagnosis.

Do not use this pass to qualify Vault persistence, native provisioning prompts
or repairs. Those are separate work items; this ISO's assistant is advisory.

## Report a failure

Send the ISO filename/hash, PC model, BIOS or UEFI boot mode, exact last visible
step and a photo of the screen. Report whether the pointer moves and whether
the UI reacts to keyboard input. Do not send passwords, provider credentials,
disk contents or unreviewed logs. A symptom without device evidence is not yet
a confirmed hardware, graphics or storage defect.
