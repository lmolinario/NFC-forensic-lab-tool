# NFC Forensic Lab Tool

`nfc_lab_tool.py` is a forensic-oriented NFC/PCSC acquisition and triage tool developed for laboratory analysis of contactless cards.

The repository now also includes two Proxmark3 backends:

- `proxmark3_backend.py`: predefined read-only RFID/NFC identification profiles;
- `proxmark3_active_lab.py`: guarded active-laboratory assessment and user-memory write verification for owned or explicitly authorized tags.

## Core PC/SC features

- PC/SC reader selection;
- UID acquisition;
- ATR acquisition;
- ATR-based card family identification;
- generic NFC/Type-2 readable dump attempt;
- MIFARE Classic 1K identification;
- authorized MIFARE Classic 1K acquisition using provided keys;
- JSON dump generation;
- JSON analysis generation;
- Markdown report generation;
- SHA256 integrity hashes.

## Tested environment

- Kali Linux;
- pcscd;
- pcsc-tools;
- opensc;
- pyscard;
- Bit4id miniLector AIR NFC v3.

The Proxmark3 modules require a compatible RRG/Iceman `proxmark3` client and firmware. They accept an explicit client path and serial port, so they can be launched from a PyCharm run configuration.

## Safety and scope

The default PC/SC workflow and `proxmark3_backend.py` are designed for non-destructive forensic triage.

They do not:

- crack or recover keys;
- brute-force keys or passwords;
- bypass authentication;
- perform nested/hardnested attacks;
- clone or simulate credentials;
- modify the original card/tag.

`proxmark3_active_lab.py` permits narrowly scoped write operations only after all of the following checks:

- exact authorization phrase;
- exact expected UID match;
- exact expected original page/block contents;
- write restricted to user-memory areas;
- post-write read-back verification;
- optional automatic restoration and restoration verification;
- key/password redaction from saved transcripts and JSON.

The active module deliberately excludes arbitrary commands, UID rewriting, lock/configuration pages, MIFARE manufacturer blocks, sector trailers, key recovery, cloning and simulation.

Use only on cards/tags that you own or are explicitly authorized to analyze. Active write tests should be performed on disposable laboratory tags, not original evidentiary items.

## Install

System packages:

```bash
sudo apt update
sudo apt install pcscd pcsc-tools opensc
```

Python dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## PC/SC usage

Identify and triage a card:

```bash
python3 nfc_lab_tool.py --reader 1
```

Read only UID and ATR:

```bash
python3 nfc_lab_tool.py --reader 1 --uid-only
```

Analyze a previous JSON dump:

```bash
python3 nfc_lab_tool.py --analyze-file dumps/example_dump.json
```

### MIFARE Classic 1K authorized acquisition

Create a local key template:

```bash
python3 nfc_lab_tool.py --mfc-create-key-template keys/local_mfc_keys.json
```

Edit the keyfile locally and insert only authorized keys.

```bash
python3 nfc_lab_tool.py \
  --reader 1 \
  --mfc-dump-1k \
  --mfc-keyfile keys/local_mfc_keys.json
```

Or use a single authorized key:

```bash
python3 nfc_lab_tool.py \
  --reader 1 \
  --mfc-dump-1k \
  --mfc-key FFFFFFFFFFFF \
  --mfc-key-type A
```

## Proxmark3 setup on Kali

Check the executable and serial device:

```bash
which proxmark3
ls -l /dev/serial/by-id/ /dev/ttyACM* 2>/dev/null
proxmark3 /dev/ttyACM0 -c "hw version"
```

To grant serial-port access:

```bash
sudo usermod -aG dialout "$USER"
```

Log out and back in after changing group membership.

Optional PyCharm environment variables:

```text
PM3_CLIENT=/usr/local/bin/proxmark3
PM3_PORT=/dev/ttyACM0
```

## Proxmark3 read-only backend

List candidate serial ports:

```bash
python3 proxmark3_backend.py --list-ports
```

Preview the command profile:

```bash
python3 proxmark3_backend.py \
  --mode identify \
  --case-id CASE-2026-001 \
  --port /dev/ttyACM0 \
  --dry-run
```

Run HF/LF identification and save a transcript, JSON and SHA256 sidecars:

```bash
python3 proxmark3_backend.py \
  --mode identify \
  --case-id CASE-2026-001 \
  --port /dev/ttyACM0
```

Available profiles:

- `identify`: hardware information plus HF and LF searches;
- `hf`: hardware information plus HF search;
- `lf`: hardware information plus LF search;
- `hardware`: version, status and antenna tuning.

## Guarded active-laboratory assessment

The exact authorization phrase is:

```text
I-OWN-OR-AM-AUTHORIZED
```

Run an assessment that records identification and vulnerability indicators without key recovery or cloning:

```bash
python3 proxmark3_active_lab.py \
  --operation assess \
  --authorization I-OWN-OR-AM-AUTHORIZED \
  --expected-uid B27B5017 \
  --case-id LAB-001 \
  --port /dev/ttyACM0
```

## NTAG/Ultralight user-page write

Only pages `4-39` are accepted. The current page content must be provided through `--expected-before`.

Preview without executing:

```bash
python3 proxmark3_active_lab.py \
  --operation ntag-write-page \
  --authorization I-OWN-OR-AM-AUTHORIZED \
  --expected-uid 04A1B2C3D4E5F6 \
  --page 4 \
  --expected-before 00000000 \
  --new-data DEADBEEF \
  --port /dev/ttyACM0 \
  --dry-run
```

Write and verify:

```bash
python3 proxmark3_active_lab.py \
  --operation ntag-write-page \
  --authorization I-OWN-OR-AM-AUTHORIZED \
  --expected-uid 04A1B2C3D4E5F6 \
  --page 4 \
  --expected-before 00000000 \
  --new-data DEADBEEF \
  --port /dev/ttyACM0
```

For a password-protected laboratory tag, add a known authorized four-byte password:

```text
--password AABBCCDD
```

### Reversible NTAG writable probe

The probe writes the supplied temporary pattern, verifies it, restores `--expected-before`, and verifies the restoration:

```bash
python3 proxmark3_active_lab.py \
  --operation ntag-writable-probe \
  --authorization I-OWN-OR-AM-AUTHORIZED \
  --expected-uid 04A1B2C3D4E5F6 \
  --page 4 \
  --expected-before 00000000 \
  --new-data A55AA55A \
  --port /dev/ttyACM0
```

## MIFARE Classic data-block write

The module refuses block `0` and every sector trailer (`3, 7, 11, ... 63`). Only an explicitly supplied authorized key is used.

```bash
python3 proxmark3_active_lab.py \
  --operation mfc-write-block \
  --authorization I-OWN-OR-AM-AUTHORIZED \
  --expected-uid B27B5017 \
  --block 4 \
  --key FFFFFFFFFFFF \
  --key-type A \
  --expected-before 00000000000000000000000000000000 \
  --new-data 00112233445566778899AABBCCDDEEFF \
  --port /dev/ttyACM0
```

### Reversible MIFARE Classic writable probe

```bash
python3 proxmark3_active_lab.py \
  --operation mfc-writable-probe \
  --authorization I-OWN-OR-AM-AUTHORIZED \
  --expected-uid B27B5017 \
  --block 4 \
  --key FFFFFFFFFFFF \
  --key-type A \
  --expected-before 00000000000000000000000000000000 \
  --new-data A55AA55AA55AA55AA55AA55AA55AA55A \
  --port /dev/ttyACM0
```

## Evidence output

The Proxmark3 modules generate files under:

```text
dumps/proxmark3/
dumps/proxmark3-active/
```

Each operation creates:

- original-style console transcript;
- structured JSON metadata;
- `.sha256` sidecar for each output;
- timestamps, client path, serial port, commands and outcomes;
- redacted key/password material in active-operation evidence.

Do not treat terminal output or automated classification as sufficient attribution. Correlate UID, card technology and memory content with seizure context, issuer data, access-control databases and system logs.

## Tests

```bash
python -m py_compile proxmark3_backend.py proxmark3_active_lab.py
python -m unittest discover -s tests -v
```

GitHub Actions runs the same checks on the feature branch and pull requests.
