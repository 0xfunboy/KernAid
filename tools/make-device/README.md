# KernAid make-device

`make-device-v2.py` è il writer trust-bound per una ISO KernAid Rescue
autorizzata dal catalogo v2. Verifica la copia e provisiona il vault cifrato su
un supporto USB factory-new selezionato esplicitamente. **Il prefisso lungo
quanto la ISO e la partizione vault vengono sovrascritti.** Non è uno strumento
di sanitizzazione dell'intero supporto. Il catalogo v2 distribuito, revisione 3,
autorizza una sola ISO internamente e virtualmente qualificata; ogni immagine
diversa viene rifiutata prima di aprire il target in scrittura. Questa
autorizzazione non costituisce qualifica di supporti o hardware fisici.

## Stato del trust catalog

Il catalogo storico `trusted-rescue-images.v1.json` autorizza la ISO
`ci-30698824356-1`, SHA-256
`11a0ade7e05a01a06cf72770403f8f9197a40608d5975635dd360cea4d307801`,
costruita e avviata con successo in QEMU BIOS e UEFI nel run GitHub Actions
`30698824356`, con prova byte-per-byte di zero scritture sul target. Ogni altra
immagine viene rifiutata fail-closed; non basta fornire un SHA-256 arbitrario
dalla riga di comando.

La voce v1 è storica e l'artefatto del workflow collegato non è più
scaricabile. Il catalogo v2 ha `catalogRevision: 3` e autorizza esclusivamente
`KernAid-Rescue-amd64.iso`, versione `ci-32951615549-1`, di
`1,221,148,672` byte e SHA-256
`ff1c2de71f69ad36f14e3a0f094b0f5be0af2547f84245a735ae9298e50b2d01`,
costruita dal commit `015ee8f767116d99ae46acb20c29e0951ca88bb2` nel run
GitHub Actions `32951615549`. Lo stesso artefatto ha superato le prove QEMU
BIOS/UEFI, USB two-boot, vault e lifecycle richieste, inclusa la persistenza e
l'export del report firmato, ed è l'unica voce v2 promossa. È una candidata
**internamente e virtualmente qualificata**, non una release di produzione né
una qualifica di boot fisico, firmware o Secure Boot.

Questa evidenza v1 avvia l'immagine come CD-ROM virtuale QEMU: non prova il boot
da USB né firmware o hardware fisici. Il writer v1, mantenuto soltanto per
verificabilità storica, copia e verifica il prefisso ISO ma non provisiona la
p3 persistente.

Ogni voce v1 lega esattamente:

- nome e versione dell'artefatto;
- SHA-256 e dimensione in byte;
- run GitHub Actions e SHA-256 dei log QEMU BIOS e UEFI passati.

Una voce v2 lega inoltre il manifest di layout e il profilo vault immutabili,
insieme alle attestazioni USB two-boot e vault BIOS/UEFI della stessa ISO.

Il catalogo è il trust anchor locale: programma, catalogo e tutta la loro
directory devono essere posseduti da `root` e non scrivibili da gruppo/altri.

Il writer v1 resta disponibile soltanto per verificabilità storica e non
provisiona la persistenza. `make-device-v2.py` non consulta mai il catalogo v1,
non effettua downgrade e, con il trust anchor corrente, accetta soltanto
l'esatta ISO autorizzata dalla revisione 3; ogni altra immagine viene rifiutata
prima di aprire il target in scrittura.

`trusted-rescue-images.v2.schema.json`, `catalog_v2.py` e
`catalog-entry-v2.py` definiscono il relativo contratto di trust. Una voce può
essere attivata soltanto dopo entrambe le prove BIOS/UEFI descritte sotto e una
revisione esplicita del catalogo. La fixture dello smoke loop privilegiato vive
soltanto in una directory temporanea root-owned e non promuove il catalogo
distribuito.

Ogni promozione v2 richiede, per la stessa ISO e lo stesso layout
immutabile, entrambe queste famiglie di prove indipendenti per BIOS e UEFI:

- due boot consecutivi della stessa immagine raw come `usb-storage`, con
  prefisso ISO, partizione p3 e target invariati e marker distinti per boot 1
  e boot 2;
- un vault realmente provisionato come LUKS2/ext4 `KERNAID_VAULT`, con UUID,
  binding autenticato journal-identità e identità stabili nei due boot,
  rifiuto della chiave errata e chiusura pulita verificata.

La riga di solo layout/boot `KERNAID_QEMU_USB_ATTESTATION_V1` non può essere
usata da sola per generare una voce trusted v2; anche i log CD-ROM v1 vengono
rifiutati. Lo smoke vault emette la distinta
`KERNAID_QEMU_USB_VAULT_ATTESTATION_V1` soltanto dopo avere verificato due
volte, tramite JSON LUKS2 e superblock ext4 binario, il profilo canonico
`vault-profile.v1.json`. Una modifica a KDF, offset, cipher, geometria,
feature, journal o policy ext4 interrompe lo smoke prima dell'attestazione.
Il parser fissa inoltre `journal_binding_before_sha256` e
`journal_binding_after_sha256` al digest SHA-256 canonico di
`device-identity-bound-v1`
(`4c535d9a1a37281ca7e25ba0f52ee44ebc893558326f74e4b36ac18a65c4d513`):
un valore arbitrario soltanto stabile, incluso il vecchio sentinel, è
rifiutato.
Nessun artefatto può essere promosso nel catalogo v2 finché entrambe le
famiglie di attestazioni non sono legate alla stessa revisione in una voce di
catalogo revisionata.

## Installazione operatore v2

Servono Linux FHS a 64 bit, `/usr/bin/python3` 3.10 o successivo, util-linux
recente (`lsblk`, `losetup`, `wipefs`), `udevadm` da systemd-udev e GNU `dd`.
L'interprete è fissato a `/usr/bin/python3 -I`; non usare una copia del tool da
una checkout scrivibile dall'utente.

Questa procedura è abilitata soltanto per l'esatta ISO autorizzata dalla
revisione 3 e resta limitata alla prima qualifica fisica controllata descritta
in `docs/CURRENT_STATUS.md`. Installare il bundle root-owned descritto nella
sezione **Writer USB v2 e vault cifrato** e usare esclusivamente l'immagine che
corrisponde per nome, dimensione, SHA-256 e layout al trust anchor installato.

Il target deve essere il path assoluto di un intero flash drive USB. È ammesso
un SSD USB portatile solo se firmware e udev lo espongono come rimovibile e
non rotazionale. Le etichette udev opzionali come `ID_DRIVE_THUMB` o
`ID_DRIVE_EXTERNAL` non sono richieste: fanno fede i controlli concordi di
`lsblk`, kernel e udev su disco intero, `RM=1`, `ROTA=0`, bus/subsystem USB,
seriale e `ID_PATH`. Un `ID_TYPE` presente e diverso da `disk` viene rifiutato.
I lettori SD/MMC/CF/MS riconosciuti dalle proprietà udev o dal modello vengono
rifiutati, ma udev non consente di distinguere in modo affidabile ogni lettore
USB generico. Per questo la conferma interattiva mostra vendor e modello e
obbliga l'operatore ad attestare fisicamente che il target è la chiavetta USB o
l'SSD portatile diretto che intende cancellare. Dischi interni, partizioni,
loop, device-mapper e md vengono rifiutati. Non usare glob né variabili
d'ambiente per il target.

Sono inoltre rifiutati root/boot/live source, mount o swap attivi, holder,
target read-only, supporti senza seriale/disk sequence, supporti troppo piccoli
e la chiavetta che contiene la ISO sorgente. Identità `lsblk`, udev, capacità,
read-only e disk sequence vengono controllate più volte e sull'FD esclusivo.

La sorgente deve corrispondere al catalogo e deve contenere MBR ibrido, ISO9660,
catalogo El Torito valido e immagini di boot BIOS+UEFI non vuote e bounded. La
copia usa un processo `dd` isolato e supervisionato, con conteggio esatto in
byte. Seguono `fsync`, `sync`, `BLKFLSBUF` e confronto byte-per-byte del prefisso.
SIGINT, SIGTERM, SIGHUP e SIGQUIT vengono differiti soltanto nella finestra di
creazione del processo, senza essere ereditati come bloccati da `dd`, e
arrestano il suo process group con deadline; dopo l'avvio di `dd` ogni errore è
sempre `FAILED: target
overwritten-or-partial`, anche se la verifica era già terminata.

Il target viene prima aperto con `O_EXCL` e ne vengono verificate identità,
capacità, stato read-only e disk sequence. Solo dopo, `wipefs --no-act` riceve
il descrittore esclusivo ereditato tramite `/proc/self/fd/N`: non riesamina il
path mutabile scelto dall'operatore. Una firma riconosciuta che ricade anche in
parte oltre la fine della ISO causa un rifiuto, senza cancellazione implicita.
Altri dati non riconosciuti nella coda possono rimanere recuperabili; il report
lo dichiara. Questo non è uno strumento di sanitizzazione.

Il report v1 dichiara anche che il vault persistente **non viene creato**: il
writer v1 non provisiona intenzionalmente la p3. Il writer v2 e il relativo
lifecycle sono implementati e il trust v2 è attivo soltanto per l'esatta
candidata della revisione 3; recovery autenticata e rollback restano gate
separati. Il report contiene la prova udev
verificata, incluso `ID_PATH`, ma dichiara esplicitamente di essere JSON locale
**non firmato e non autenticato**: non è una ricevuta crittografica.

Questa dichiarazione riguarda esclusivamente `make-device.py` v1. Il percorso
v2 crea e verifica il vault soltanto per un'immagine autorizzata dal catalogo
v2 distribuito.

## Writer USB v2 e vault cifrato (implementato, catalogo revisione 3)

Il catalogo distribuito contiene una sola voce promossa. Il launcher v2 accetta
quell'immagine soltanto su un supporto che espone almeno `32000000000` byte.
Scrive e verifica il prefisso ISO esatto, richiede che lo slot MBR 3 coincida
con il manifest installato e fa riesaminare la tabella al kernel. La p3 deve
essere:

- numero `3`, tipo MBR `0x83`;
- start LBA `33554432` (16 GiB);
- `16777216` settori da 512 byte (8 GiB);
- label LUKS2 e filesystem ext4 `KERNAID_VAULT`.

Path, major:minor, inode del nodo, parent sysfs, capacità, settore logico e
disk sequence del disco intero vengono legati e ricontrollati a ogni handoff.
Una geometria diversa, un nodo mutato, un mapper ambiguo o qualsiasi firma
riconosciuta nella p3/coda che entrerebbe in conflitto viene rifiutata senza
cancellazione o riparazione implicita.

La passphrase fisica viene letta due volte esclusivamente da `/dev/tty` con
echo disabilitato. Non esiste un argomento, variabile d'ambiente o file per
fornirla. `cryptsetup` la riceve tramite pipe ereditata e `/proc/self/fd/N`;
buffer e seed dell'identità vengono azzerati best-effort prima del rilascio.
Il solo smoke CI può usare un FD di pipe ereditato, ma esclusivamente insieme
al token che lega un `/dev/loopN` privato al backing inode. Con `CI` attivo un
supporto fisico è irraggiungibile.

La policy fisica v2 autorizza **soltanto supporti factory-new, mai usati per
dati**. Dopo la conferma distruttiva legata a path/seriale/modello/capacità,
l'operatore deve digitare una seconda frase esatta che attesta anche
path/seriale/disk sequence e questa condizione. È un'attestazione umana, non
una misura tecnica: il report conserva separatamente
`operatorFreshMediaAttestation: true` e
`technicalFreshnessVerified: false`. Il loop CI usa invece un valore test-only
tipizzato e non finge un'attestazione umana. `luksFormat` e `mkfs.ext4` non
sanitizzano ogni byte raw residuo: supporti già usati sono vietati e non esiste
ancora un comando di wipe, recovery o reprovisioning autenticato.

Il vault viene formattato LUKS2, aperto con un mapper generato localmente,
formattato ext4 e montato con policy hardened. Vengono creati il marker Rescue,
il lock, `/.kernaid-secure-state-v1/`, un seed Ed25519 iniziale nel formato
letto da `kernaid-rescue-secrets`, e
`/.kernaid-codex-home-v1/config.toml`. La home Codex è posseduta dall'identità
fissa 973:973, ha modo 0700 e forza esclusivamente il credential store ufficiale
su file; il config è 0600 e il writer rifiuta qualunque voce aggiuntiva durante
la verifica di provisioning. Nessuna credenziale o `auth.json` viene creata dal
writer. Il writer smonta e chiude, rifiuta una chiave errata, riapre con quella
corretta e verifica esattamente UUID LUKS/filesystem, label, marker, home Codex
senza credenziali e hash dell'envelope d'identità. Mapper e mount temporanei
sono sempre sottoposti a cleanup verificato.

Il profilo crittografico/filesystem non dipende dai default dell'host: cipher,
key size, settore, Argon2id, aree metadata/keyslot e data offset LUKS2, oltre a
geometria, feature mask, journal, reserved blocks e mount policy ext4, sono
pinning immutabili. Il loro documento canonico e SHA-256 sono legati al
manifest, al catalogo, alle attestazioni e al report. Prima di qualunque
inventario esterno o apertura del target, il writer lega l'identità di tutti i
binari root-owned, prova realmente lo stesso LUKS2 su un file anonimo e lo
stesso ext4 su un file sparse temporaneo, quindi verifica i metadati
machine-readable. Tool, versione o capability incompatibili causano un rifiuto
prima del primo byte sul supporto.

Dopo il primo tentativo di scrittura sul supporto, qualunque errore—including
provisioning, verifica, cleanup, segnale o output del report—termina con exit
code `4` e il messaggio `MEDIA PARTIAL / NON-BOOTABLE`. Il supporto non deve
essere avviato o riutilizzato. Il writer rifiuta una firma riconosciuta in
conflitto senza cancellarla: quindi un supporto v2 già provisionato, o un
parziale che contiene già LUKS in p3, viene rifiutato. Questo non consente però
di provare che un supporto senza firme riconosciute sia nuovo: un errore prima
della creazione della firma p3 può lasciare uno stato tecnicamente
indistinguibile da una coda blank/non riconosciuta. L'indicazione “non
riutilizzare” è pertanto una policy operativa conservativa, non una
classificazione autenticata del supporto. Retry, recovery e reprovisioning
autenticati non sono implementati; richiederanno un futuro flusso separato che
provi esattamente vault, passphrase, marker e identità KernAid. Non viene
cancellata alcuna firma implicitamente e non viene mai tentato un fallback al
writer/catalogo v1. Il report espone esplicitamente questi limiti.

Il bundle v2 richiede inoltre `cryptsetup` ed `e2fsprogs`. Va installato in una
directory root-owned non scrivibile da gruppo/altri insieme a una copia esatta
del manifest:

```text
sudo install -d -o root -g root -m 0755 /usr/local/libexec/kernaid/make-device-v2
sudo install -o root -g root -m 0755 \
  tools/make-device/make-device-v2.py \
  /usr/local/libexec/kernaid/make-device-v2/make-device-v2.py
sudo install -o root -g root -m 0644 \
  tools/make-device/make_device_v2.py \
  tools/make-device/make-device.py \
  tools/make-device/catalog_v2.py \
  tools/make-device/trusted-rescue-images.v2.json \
  /usr/local/libexec/kernaid/make-device-v2/
sudo install -o root -g root -m 0644 \
  rescue/image-layout/device-layout.v1.json \
  /usr/local/libexec/kernaid/make-device-v2/device-layout.v1.json
sudo install -o root -g root -m 0644 \
  rescue/image-layout/vault-profile.v1.json \
  /usr/local/libexec/kernaid/make-device-v2/vault-profile.v1.json
```

Il launcher verifica ownership e mode del bundle **prima** di importare il
core. Con la revisione 3 il comando seguente accetta soltanto l'ISO esatta
presente nel catalogo installato; nome, dimensione o SHA-256 differenti
falliscono chiuso prima di aprire il target:

```text
sudo /usr/local/libexec/kernaid/make-device-v2/make-device-v2.py \
  --iso /percorso/KernAid-Rescue-amd64.iso \
  --sha256 HASH_UFFICIALE_DA_64_CARATTERI \
  --device /dev/sdX
```

## Popolare il catalogo dopo CI

La pipeline Rescue calcola l'hash della stessa ISO avviata due volte come USB
virtuale in BIOS e UEFI. Ogni log lega ISO, layout immutabile, regioni
byte-identiche, marker ready distinti e il vault LUKS2/ext4 sopravvissuto ai due
boot. `catalog-entry-v2.py` verifica queste prove e calcola direttamente gli
hash dei log. Il job pubblica
`KernAid-Rescue-amd64.catalog-entry-v2.json` insieme a ISO e checksum; i log
sanitizzati sono pubblicati come artefatti evidence distinti dello stesso run.
Una promozione è consentita soltanto se termina con successo anche l'intero
workflow, inclusi entrambi i job privilegiati di lifecycle BIOS e UEFI. ID e
URL provengono da `GITHUB_RUN_ID` e dal contesto del run, non da una
dichiarazione manuale.

Per riprodurre localmente la derivazione su artefatti scaricati dallo stesso
run:

```text
tools/make-device/catalog-entry-v2.py \
  --iso /percorso/assoluto/KernAid-Rescue-amd64.iso \
  --sha256 SHA256_ISO \
  --layout-manifest rescue/image-layout/device-layout.v1.json \
  --artifact-version VERSIONE_RELEASE \
  --bios-run-id ID_RUN_BIOS \
  --bios-run-url https://github.com/0xfunboy/KernAid/actions/runs/ID_RUN_BIOS \
  --bios-log /percorso/assoluto/rescue-usb-smoke-bios.log \
  --uefi-run-id ID_RUN_UEFI \
  --uefi-run-url https://github.com/0xfunboy/KernAid/actions/runs/ID_RUN_UEFI \
  --uefi-log /percorso/assoluto/rescue-usb-smoke-uefi.log \
  > /tmp/kernaid-catalog-entry-v2.json
```

Revisionare la voce, inserirla nell'array `images`, incrementare
`catalogRevision`, rieseguire i test e commettere il catalogo insieme alla
release. `catalog-entry-v2.py` non modifica automaticamente il trust anchor.

## Test

I test unitari non usano block device reali:

```text
python3 -m unittest discover -s tools/make-device/tests -v
```

Il solo percorso che può fidarsi di una ISO artificiale richiede insieme un
loop appena creato, backing file privato sotto `/tmp`, token device+inode e token
fixture digest+size. È irraggiungibile per supporti fisici. Lo smoke privilegiato
crea e distrugge autonomamente il proprio loop:

```text
sudo tools/make-device/tests/loop-smoke.sh
```

Lo smoke v2 crea un backing **sparse** esattamente da 32.000.000.000 byte,
installa un bundle/fixture catalog-v2 temporaneo root-owned, scrive l'immagine,
provisiona e riapre LUKS2/ext4 e verifica che non restino mapper o mount:

```text
sudo tools/make-device/tests/loop-v2-smoke.sh
```

La fixture v2 è raggiungibile soltanto dal loop temporaneo e non costituisce
evidenza di release. Il workflow `make-device` installa cryptsetup/e2fsprogs,
esegue tutti i test unitari v1/v2 e poi entrambi gli smoke privilegiati.

Non esiste un'opzione `--yes` per i dispositivi fisici.
