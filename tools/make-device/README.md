# KernAid make-device

`make-device.py` scrive una ISO ufficiale KernAid Rescue su un solo supporto USB
selezionato esplicitamente. **Il prefisso lungo quanto la ISO viene
sovrascritto.** La coda non viene cancellata.

## Stato del trust catalog

Il catalogo ufficiale `trusted-rescue-images.v1.json` autorizza la ISO
`ci-30698824356-1`, SHA-256
`11a0ade7e05a01a06cf72770403f8f9197a40608d5975635dd360cea4d307801`,
costruita e avviata con successo in QEMU BIOS e UEFI nel run GitHub Actions
`30698824356`, con prova byte-per-byte di zero scritture sul target. Ogni altra
immagine viene rifiutata fail-closed; non basta fornire un SHA-256 arbitrario
dalla riga di comando.

Ogni voce lega esattamente:

- nome e versione dell'artefatto;
- SHA-256 e dimensione in byte;
- run GitHub Actions e SHA-256 dei log QEMU BIOS e UEFI passati.

Il catalogo è il trust anchor locale: programma, catalogo e tutta la loro
directory devono essere posseduti da `root` e non scrivibili da gruppo/altri.

Il writer installabile e il workflow di pubblicazione restano sulla versione
v1. I file `trusted-rescue-images.v2.json`,
`trusted-rescue-images.v2.schema.json`, `catalog_v2.py` e
`catalog-entry-v2.py` definiscono invece un contratto di trust futuro,
separato e inattivo: il catalogo v2 ha revisione zero e l'elenco immagini è
vuoto. Non è un catalogo alternativo da installare e non autorizza alcuna ISO.

Una futura promozione v2 richiederà, per la stessa ISO e lo stesso layout
immutabile, entrambe queste famiglie di prove indipendenti per BIOS e UEFI:

- due boot consecutivi della stessa immagine raw come `usb-storage`, con
  prefisso ISO, partizione p3 e target invariati e marker distinti per boot 1
  e boot 2;
- un vault realmente provisionato come LUKS2/ext4 `KERNAID_VAULT`, con UUID,
  sentinel e identità stabili nei due boot, rifiuto della chiave errata e
  chiusura pulita verificata.

Lo smoke USB attuale che verifica soltanto layout e boot non prova la
persistenza del vault. La sua riga `KERNAID_QEMU_USB_ATTESTATION_V1` non può
quindi essere usata da sola per generare una voce trusted v2; anche i log
CD-ROM v1 vengono rifiutati. Finché mancano entrambe le famiglie di
attestazioni, nessun artefatto può essere promosso nel catalogo v2.

## Installazione operatore

Servono Linux FHS a 64 bit, `/usr/bin/python3` 3.10 o successivo, util-linux
recente (`lsblk`, `losetup`, `wipefs`), `udevadm` da systemd-udev e GNU `dd`.
L'interprete è fissato a `/usr/bin/python3 -I`; non usare una copia del tool da
una checkout scrivibile dall'utente.

Installare la copia revisionata del tool e del catalogo ufficiale:

```text
sudo install -d -o root -g root -m 0755 /usr/local/libexec/kernaid/make-device
sudo install -o root -g root -m 0755 \
  tools/make-device/make-device.py \
  /usr/local/libexec/kernaid/make-device/make-device.py
sudo install -o root -g root -m 0644 \
  tools/make-device/trusted-rescue-images.v1.json \
  /usr/local/libexec/kernaid/make-device/trusted-rescue-images.v1.json
```

Uso:

```text
sudo /usr/local/libexec/kernaid/make-device/make-device.py \
  --iso /percorso/KernAid-Rescue-amd64.iso \
  --sha256 HASH_UFFICIALE_DA_64_CARATTERI \
  --device /dev/sdX
```

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

Il report dichiara anche che il vault persistente **non viene creato** finché
partizionamento, enrollment, crash recovery e rollback non saranno implementati
e provati in modo sicuro. Il report contiene la prova udev verificata, incluso
`ID_PATH`, ma dichiara esplicitamente di essere JSON locale **non firmato e non
autenticato**: non è una ricevuta crittografica.

## Popolare il catalogo dopo CI

La pipeline Rescue calcola l'hash della stessa ISO avviata da QEMU e fa
aggiungere a ciascun log una singola attestazione strutturata con firmware,
SHA-256 ISO, marker ready e hash del target prima/dopo identici. Soltanto dopo i
due smoke BIOS e UEFI, `catalog-entry.py` verifica quelle righe e calcola
direttamente gli hash dei log. Il job pubblica
`KernAid-Rescue-amd64.catalog-entry.json` insieme alla ISO, al checksum e agli
stessi log. ID e URL provengono da `GITHUB_RUN_ID` e dal contesto del run, non da
una dichiarazione manuale.

Per riprodurre localmente la derivazione su artefatti scaricati dallo stesso
run:

```text
tools/make-device/catalog-entry.py \
  --iso /percorso/assoluto/KernAid-Rescue-amd64.iso \
  --sha256 SHA256_ISO \
  --artifact-version VERSIONE_RELEASE \
  --bios-run-id ID_RUN_BIOS \
  --bios-run-url https://github.com/0xfunboy/KernAid/actions/runs/ID_RUN_BIOS \
  --bios-log /percorso/assoluto/rescue-smoke-bios.log \
  --uefi-run-id ID_RUN_UEFI \
  --uefi-run-url https://github.com/0xfunboy/KernAid/actions/runs/ID_RUN_UEFI \
  --uefi-log /percorso/assoluto/rescue-smoke-uefi.log \
  > /tmp/kernaid-catalog-entry.json
```

Revisionare la voce, inserirla nell'array `images`, incrementare
`catalogRevision`, rieseguire i test e commettere il catalogo insieme alla
release. `catalog-entry.py` non modifica automaticamente il trust anchor.

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

Non esiste un'opzione `--yes` per i dispositivi fisici.
