# External Authorized Key Discovery Phase

The MIFARE Classic key discovery/recovery phase is considered an external, controlled and explicitly authorized laboratory phase.

The `nfc_lab_tool.py` script does not implement:

- brute force;
- cracking;
- nested attack;
- hardnested attack;
- authentication bypass;
- cloning;
- unauthorized key recovery.

The script accepts only keys already available, provided, or obtained during the authorized laboratory phase.

The output of the external phase should be converted into a local key database compatible with:

```json
{
  "source": "external_authorized_laboratory_key_recovery_or_key_provision_phase",
  "uid": "B2 7B 50 17",
  "keys": [
    {
      "sector": 0,
      "key_type": "A",
      "key": "FFFFFFFFFFFF"
    }
  ]
}

Sectors for which no valid key is available are reported as not acquired or authentication-protected. This does not imply absence of data.
EOFcat > docs/forensic_workflow.md << 'EOF'
# NFC Forensic Workflow

## Phase 1 - Identification

The tool connects to a PC/SC contactless reader and acquires:

- reader name;
- UID;
- ATR;
- ATR-based card profile.

For the tested laboratory card, the ATR identifies the card as:

- MIFARE Classic 1K;
- ISO 14443 Type A;
- 16 sectors;
- 4 blocks per sector;
- 16 bytes per block.

## Phase 2 - Generic NFC / Type-2 Triage

The tool attempts a non-destructive Type-2-style readable dump using PC/SC pseudo-APDUs.

If the card is MIFARE Classic 1K, Type-2 page reads are expected to fail or be unsupported. This must not be interpreted as an empty card.

## Phase 3 - Authorized MIFARE Classic Acquisition

If authorized keys are available, the tool can perform sector/block acquisition.

The tool:

- loads provided keys into reader volatile memory;
- authenticates sectors;
- reads blocks;
- classifies non-authenticated sectors as not acquired;
- saves JSON dump, JSON analysis, Markdown report and SHA256 hashes.

## Phase 4 - Analysis and Reporting

The tool performs automated triage:

- readable/unreadable areas;
- status words;
- ASCII strings;
- URLs;
- emails;
- sector summaries;
- hash computation;
- forensic limitations.
