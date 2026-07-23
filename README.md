# NFC Forensic Lab Tool

`nfc_lab_tool.py` is a forensic-oriented NFC/PCSC acquisition and triage tool developed for laboratory analysis of contactless cards.

The repository now provides two complementary acquisition backends:

- **PC/SC backend:** Bit4id and other compatible readers through `pyscard`;
- **Proxmark3 backend:** read-only RFID/NFC identification through the RRG/Iceman client.

## PC/SC capabilities

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

## Proxmark3 read-only backend

`proxmark3_backend.py` adds non-destructive Proxmark3 identification while preserving the native client output.

It supports:

- Proxmark3 client and serial-port discovery;
- hardware, HF, LF and combined read-only profiles;
- strict allowlisting of non-destructive commands;
- raw transcript preservation;
- SHA256 transcript and manifest hashes;
- automated extraction of UID, ATQA, SAK and ATS when present;
- basic technology hints for triage;
- import from PyCharm or execution as a standalone CLI.

The backend intentionally does not expose write, clone, simulation, sniffing, brute-force, key-recovery, nested/hardnested or authentication-bypass operations.

## Tested environment

- Kali Linux;
- Python 3;
- pcscd;
- pcsc-tools;
- opensc;
- pyscard;
- Bit4id miniLector AIR NFC v3;
- RRG/Iceman Proxmark3 client.

## Safety and scope

This project is designed for non-destructive forensic triage.

It does not:

- crack or recover keys;
- brute-force credentials;
- bypass authentication;
- perform nested/hardnested attacks;
- clone cards;
- modify the original card or tag.

Use only on cards, tags and systems that you own or are explicitly authorized to analyze.

## Install PC/SC dependencies

```bash
sudo apt update
sudo apt install pcscd pcsc-tools opensc
```

Create the Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Basic PC/SC usage

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

## MIFARE Classic 1K authorized acquisition

Create a local key template:

```bash
python3 nfc_lab_tool.py --mfc-create-key-template keys/local_mfc_keys.json
```

Edit the key file locally and insert only keys that were lawfully provided or recovered in an explicitly authorized laboratory phase.

Run the acquisition:

```bash
python3 nfc_lab_tool.py \
  --reader 1 \
  --mfc-dump-1k \
  --mfc-keyfile keys/local_mfc_keys.json
```

Or use one authorized key:

```bash
python3 nfc_lab_tool.py \
  --reader 1 \
  --mfc-dump-1k \
  --mfc-key FFFFFFFFFFFF \
  --mfc-key-type A
```

## Proxmark3 setup on Kali

Verify that the RRG/Iceman client is installed and that the device appears as a serial port:

```bash
which proxmark3
ls -l /dev/ttyACM* /dev/ttyUSB* 2>/dev/null
```

To grant serial-port access to the current user:

```bash
sudo usermod -aG dialout "$USER"
```

Log out and back in after changing group membership.

List candidate ports:

```bash
python3 proxmark3_backend.py --list-ports
```

Run combined HF and LF read-only identification:

```bash
python3 proxmark3_backend.py \
  --port /dev/ttyACM0 \
  --profile both
```

HF-only identification:

```bash
python3 proxmark3_backend.py \
  --port /dev/ttyACM0 \
  --profile hf
```

LF-only identification:

```bash
python3 proxmark3_backend.py \
  --port /dev/ttyACM0 \
  --profile lf
```

Specify a non-standard client path:

```bash
python3 proxmark3_backend.py \
  --client /opt/proxmark3/client/proxmark3 \
  --port /dev/ttyACM0 \
  --profile hardware
```

Alternatively, configure the client path for PyCharm or the shell:

```bash
export PM3_CLIENT=/opt/proxmark3/client/proxmark3
```

Outputs are written by default to:

```text
dumps/proxmark3/
├── pm3_readonly_<timestamp>.txt
├── pm3_readonly_<timestamp>.txt.sha256
├── pm3_readonly_<timestamp>.json
└── pm3_readonly_<timestamp>.json.sha256
```

The raw transcript is the primary native output. Parsed fields are triage hints and must be manually verified.

## Importing the Proxmark3 backend in PyCharm

```python
from pathlib import Path

from proxmark3_backend import run_read_only_acquisition

result = run_read_only_acquisition(
    port="/dev/ttyACM0",
    profile="hf",
    output_dir=Path("dumps/proxmark3"),
)

print(result.parsed_identification)
print(result.transcript_sha256)
```

## Tests

Run the offline unit tests without connecting hardware:

```bash
python3 -m unittest discover -s tests -v
```

## Repository hygiene

Do not commit:

- real card dumps;
- real or recovered keys;
- case-specific acquisition reports;
- raw evidence transcripts;
- generated `.sha256` files;
- personally identifiable information obtained from cards or tags.
