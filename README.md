cat > README.md << 'EOF'
# NFC Forensic Lab Tool

`nfc_lab_tool.py` is a forensic-oriented NFC/PCSC acquisition and triage tool developed for laboratory analysis of contactless cards.

The tool supports:

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

## Tested Environment

- Kali Linux
- pcscd
- pcsc-tools
- opensc
- pyscard
- Bit4id miniLector AIR NFC v3

## Safety and Scope

This tool is designed for non-destructive forensic triage.

It does not:

- crack keys;
- brute-force keys;
- bypass authentication;
- perform nested/hardnested attacks;
- clone cards;
- modify the original card.

Use only on cards/tags that you own or are explicitly authorized to analyze.

## Install

System packages:

```bash
sudo apt update
sudo apt install pcscd pcsc-tools opensc

Python dependency:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Basic Usage

Identify and triage a card:

python3 nfc_lab_tool.py --reader 1

Read only UID and ATR:

python3 nfc_lab_tool.py --reader 1 --uid-only

Analyze a previous JSON dump:

python3 nfc_lab_tool.py --analyze-file dumps/example_dump.json
MIFARE Classic 1K Authorized Acquisition

Create a local key template:

python3 nfc_lab_tool.py --mfc-create-key-template keys/local_mfc_keys.json

Edit the keyfile locally and insert only authorized keys.

Run authorized acquisition:

python3 nfc_lab_tool.py \
  --reader 1 \
  --mfc-dump-1k \
  --mfc-keyfile keys/local_mfc_keys.json

Or use a single authorized key:

python3 nfc_lab_tool.py \
  --reader 1 \
  --mfc-dump-1k \
  --mfc-key FFFFFFFFFFFF \
  --mfc-key-type A
Repository Hygiene

Do not commit:

real card dumps;
real keys;
recovered key files;
case-specific reports;
.sha256 output files.

The .gitignore file is configured to exclude these artifacts.
# NFC-forensic-lab-tool
