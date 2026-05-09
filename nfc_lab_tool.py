#!/usr/bin/env python3
"""
NFC forensic acquisition and triage tool for PC/SC contactless readers.

Main forensic workflow:
1. Select PC/SC reader.
2. Connect to the card/tag.
3. Read UID and ATR.
4. Acquire a complete readable dump.
5. Save the dump to JSON.
6. Compute SHA256 hashes.
7. Analyze the acquired dump offline/non-destructively.

Important:
- This tool is designed for non-destructive forensic triage.
- It does not crack keys.
- It does not bypass authentication.
- It does not clone cards.
- It does not modify the original card.
- Use only on cards/tags that you own or are authorized to analyze.

Tested workflow:
- Kali Linux
- pcscd / pcsc-tools / opensc / pyscard
- Bit4id miniLector AIR NFC v3
"""

import argparse
import hashlib
import json
import re
import sys
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.System import readers


# =============================================================================
# Generic helpers
# =============================================================================

def hx(data):
    """
    Converts a list of integers / bytes into a space-separated HEX string.
    """

    if data is None:
        return None

    return " ".join(f"{b:02X}" for b in data)


def ascii_preview(data):
    """
    Converts bytes into a printable ASCII preview.
    Non-printable bytes are represented as dots.
    """

    if data is None:
        return None

    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def now_timestamp():
    """
    Returns a forensic-friendly timestamp.
    """

    return datetime.now().isoformat(timespec="seconds")


def ensure_parent_dir(filename):
    """
    Creates parent directory for output file if needed.
    """

    Path(filename).parent.mkdir(parents=True, exist_ok=True)


def sha256_file(filename):
    """
    Computes SHA256 of a file.
    """

    h = hashlib.sha256()

    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def sha256_bytes(data):
    """
    Computes SHA256 of raw bytes.
    """

    return hashlib.sha256(data).hexdigest() if data else None


def explain_status_word(sw):
    """
    Returns a cautious forensic explanation for a PC/SC status word.
    """

    meanings = {
        "9000": "Success",
        "6300": "Operation failed or authentication-related failure",
        "6385": "Read operation failed / command not allowed / unsupported for this card-reader context",
        "6700": "Wrong length",
        "6982": "Security status not satisfied",
        "6985": "Conditions of use not satisfied",
        "6986": "Command not allowed",
        "6A81": "Function not supported",
        "6A82": "File/object/page not found",
        "6A86": "Incorrect parameters P1/P2",
        "6B00": "Wrong parameters / invalid offset or page",
        "6D00": "Instruction code not supported",
        "6E00": "Class not supported",
    }

    return meanings.get(sw, "Unknown or card/reader-specific status word")



# =============================================================================
# Reader selection and connection
# =============================================================================

def connect_reader(reader_index=None):
    """
    Lists available PC/SC readers and connects to the selected one.

    If reader_index is None, the user is asked interactively.
    This is convenient when running the script from PyCharm.
    """

    available = readers()

    if not available:
        print("[ERROR] Nessun lettore PC/SC rilevato.")
        print("Suggerimento: sudo systemctl restart pcscd")
        sys.exit(1)

    print("\n[INFO] Lettori PC/SC disponibili:")
    for i, reader in enumerate(available):
        print(f"  {i}: {reader}")

    if reader_index is not None:
        if reader_index < 0 or reader_index >= len(available):
            print(f"[ERROR] Reader index {reader_index} non valido.")
            sys.exit(1)

        selected_index = reader_index

    else:
        print("\nSeleziona il lettore da usare.")
        print("Per NFC, scegli il lettore Bit4id miniLector AIR NFC v3.")

        while True:
            choice = input("Numero lettore: ").strip()

            if not choice.isdigit():
                print("[ERROR] Inserisci un numero valido.")
                continue

            selected_index = int(choice)

            if selected_index < 0 or selected_index >= len(available):
                print("[ERROR] Indice fuori intervallo.")
                continue

            break

    reader = available[selected_index]
    print(f"\n[INFO] Uso lettore: {reader}")

    connection = reader.createConnection()

    try:
        connection.connect()
    except NoCardException:
        print("[ERROR] Nessuna card/tag appoggiata sul lettore.")
        sys.exit(1)
    except CardConnectionException as e:
        print(f"[ERROR] Connessione alla card fallita: {e}")
        sys.exit(1)

    return reader, connection


def transmit(conn, apdu, verbose=False):
    """
    Sends an APDU to the selected PC/SC card connection.
    """

    if verbose:
        print("[TX]", hx(apdu))

    data, sw1, sw2 = conn.transmit(apdu)

    if verbose:
        if data:
            print("[RX]", hx(data), f"SW={sw1:02X}{sw2:02X}")
        else:
            print("[RX]", f"SW={sw1:02X}{sw2:02X}")

    return data, sw1, sw2


# =============================================================================
# Basic card identification
# =============================================================================

def get_atr(conn):
    """
    Gets card ATR from PC/SC connection.
    """

    try:
        return list(conn.getATR())
    except Exception:
        return None


def get_uid(conn):
    """
    Reads UID using the common PC/SC contactless pseudo-APDU:
    FF CA 00 00 00

    This works with many PC/SC contactless readers.
    """

    data, sw1, sw2 = transmit(conn, [0xFF, 0xCA, 0x00, 0x00, 0x00])

    if sw1 == 0x90 and sw2 == 0x00:
        return data

    print(f"[WARN] UID non leggibile con FF CA 00 00 00. SW={sw1:02X}{sw2:02X}")
    return None

# =============================================================================
# Card family identification
# =============================================================================

def compact_hex(data):
    """
    Converts bytes/list[int] into compact uppercase HEX without spaces.
    """

    if data is None:
        return ""

    return "".join(f"{b:02X}" for b in data)


def identify_card_family_from_atr(atr):
    """
    Identifies the likely card family from ATR.

    This does not replace a full protocol analysis, but it provides
    a strong forensic classification hint based on PC/SC ATR patterns.
    """

    atr_hex = hx(atr) if atr else None
    atr_compact = compact_hex(atr)

    profile = {
        "atr": atr_hex,
        "family": "Unknown contactless card",
        "technology": "Unknown",
        "memory_model": "Unknown",
        "recommended_acquisition": "generic_triage",
        "confidence": "low",
        "reasoning": [],
        "warnings": [],
    }

    if not atr:
        profile["reasoning"].append("ATR not available.")
        return profile

    # Pattern observed in pcsc_scan for this laboratory card:
    # MIFARE Classic 1K / ISO 14443 Type A Part 3
    #
    # ATR:
    # 3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A
    #
    # Relevant compact sequence:
    # A000000306030001
    if "A000000306030001" in atr_compact:
        profile.update({
            "family": "MIFARE Classic 1K",
            "technology": "ISO 14443 Type A",
            "memory_model": "16 sectors, 4 blocks per sector, 16 bytes per block",
            "recommended_acquisition": "mifare_classic_1k_sector_block_acquisition",
            "confidence": "high",
        })
        profile["reasoning"].extend([
            "ATR matches the PC/SC storage-card pattern identified by pcsc_scan as MIFARE Classic 1K.",
            "The card should be acquired using MIFARE Classic sector/block logic, not NFC Type-2 page reads.",
            "Authentication with valid sector keys is required to read protected data blocks."
        ])
        profile["warnings"].extend([
            "Do not classify the card as empty if Type-2 page reads fail.",
            "Do not use NTAG/Ultralight page-based interpretation for this card.",
            "Unreadable blocks should be reported as not acquired or authentication-required."
        ])
        return profile

    # Generic PC/SC storage-card RID hint.
    if "A000000306" in atr_compact:
        profile.update({
            "family": "PC/SC storage card / contactless memory card",
            "technology": "Likely ISO 14443 contactless",
            "memory_model": "Card-specific",
            "recommended_acquisition": "card_family_specific_acquisition",
            "confidence": "medium",
        })
        profile["reasoning"].append(
            "ATR contains the PC/SC storage-card RID A000000306, but the exact card type is not mapped in this script."
        )
        return profile

    profile["reasoning"].append(
        "ATR does not match any card-family pattern currently implemented."
    )

    return profile


def print_card_profile(profile):
    """
    Prints the identified card profile.
    """

    print("\n" + "=" * 78)
    print("CARD FAMILY IDENTIFICATION")
    print("=" * 78)
    print(f"Family: {profile.get('family')}")
    print(f"Technology: {profile.get('technology')}")
    print(f"Memory model: {profile.get('memory_model')}")
    print(f"Recommended acquisition: {profile.get('recommended_acquisition')}")
    print(f"Confidence: {profile.get('confidence')}")

    print("\nReasoning:")
    for item in profile.get("reasoning", []):
        print(f"  - {item}")

    if profile.get("warnings"):
        print("\nWarnings:")
        for item in profile.get("warnings", []):
            print(f"  - {item}")

    print("=" * 78 + "\n")



def capture_pcsc_scan_snapshot(timeout_seconds=4):
    """
    Captures a short pcsc_scan snapshot as forensic support evidence.

    pcsc_scan is normally interactive/continuous, so this function runs it
    for a few seconds and captures whatever it prints.
    """

    if shutil.which("pcsc_scan") is None:
        return {
            "available": False,
            "error": "pcsc_scan not found in PATH",
            "output": None,
        }

    try:
        result = subprocess.run(
            ["pcsc_scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
        )

        return {
            "available": True,
            "timeout": False,
            "output": result.stdout,
        }

    except subprocess.TimeoutExpired as e:
        output = e.stdout

        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")

        return {
            "available": True,
            "timeout": True,
            "output": output,
        }

    except Exception as e:
        return {
            "available": False,
            "error": str(e),
            "output": None,
        }
# =============================================================================
# Page/block reading
# =============================================================================

def read_page(conn, page):
    """
    Reads 4 bytes from a page/block using PC/SC pseudo-APDU:
    FF B0 00 <page> 04

    This is suitable for many NFC Type 2 / MIFARE Ultralight / NTAG-like tags.
    For protected/application cards, it may fail.
    """

    if page < 0 or page > 255:
        return None, 0x6B, 0x00

    apdu = [0xFF, 0xB0, 0x00, page, 0x04]
    data, sw1, sw2 = transmit(conn, apdu)

    if sw1 == 0x90 and sw2 == 0x00:
        return data, sw1, sw2

    return None, sw1, sw2


def read_initial_pages(conn):
    """
    Reads pages 0-3 first.
    These pages are useful for NFC Type 2 / NTAG / Ultralight triage.

    Page 3 often contains the Capability Container.
    """

    initial = {}

    for page in range(0, 4):
        data, sw1, sw2 = read_page(conn, page)

        initial[str(page)] = {
            "page": page,
            "readable": data is not None,
            "hex": hx(data) if data is not None else None,
            "ascii": ascii_preview(data) if data is not None else None,
            "sw": f"{sw1:02X}{sw2:02X}",
        }

    return initial


def detect_type2_capability_container_from_pages(pages):
    """
    Detects possible NFC Forum Type 2 Tag Capability Container.

    For many Type 2 tags, page 3 is:
    E1 xx yy zz

    E1 = magic number
    yy = data area size in blocks of 8 bytes
    zz = access conditions
    """

    page3 = pages.get("3")

    if not page3 or not page3.get("readable") or not page3.get("hex"):
        return {
            "present": False,
            "reason": "Page 3 not readable"
        }

    try:
        values = [int(x, 16) for x in page3["hex"].split()]
    except ValueError:
        return {
            "present": False,
            "reason": "Page 3 contains invalid HEX"
        }

    if len(values) < 4:
        return {
            "present": False,
            "reason": "Page 3 incomplete"
        }

    magic = values[0]
    version = values[1]
    memory_size_byte = values[2]
    access_byte = values[3]

    result = {
        "present": magic == 0xE1,
        "page_3_hex": hx(values),
        "magic": f"{magic:02X}",
        "version": f"{version:02X}",
        "memory_size_byte": f"{memory_size_byte:02X}",
        "access_byte": f"{access_byte:02X}",
        "data_area_bytes_estimated": memory_size_byte * 8,
        "data_area_pages_estimated": (memory_size_byte * 8 + 3) // 4,
    }

    if magic == 0xE1:
        # Data area starts after page 3, usually at page 4.
        # Logical NDEF area end = page 3 + data_area_pages.
        result["logical_start_page"] = 4
        result["logical_end_page_estimated"] = 3 + result["data_area_pages_estimated"]
        result["interpretation"] = "Possible NFC Forum Type 2 Tag / NTAG / MIFARE Ultralight-like tag"
    else:
        result["interpretation"] = "No standard NFC Type 2 Capability Container detected at page 3"

    return result


def dump_range(conn, start_page, end_page):
    """
    Dumps a fixed page range.
    """

    pages = {}

    for page in range(start_page, end_page + 1):
        data, sw1, sw2 = read_page(conn, page)

        page_entry = {
            "page": page,
            "readable": data is not None,
            "hex": hx(data) if data is not None else None,
            "ascii": ascii_preview(data) if data is not None else None,
            "sw": f"{sw1:02X}{sw2:02X}",
        }

        pages[str(page)] = page_entry

        if data is not None:
            print(f"[OK] Page {page:03d}: {hx(data)}  | {ascii_preview(data)}")
        else:
            print(f"[WARN] Page {page:03d}: non leggibile / non esistente  SW={sw1:02X}{sw2:02X}")

    return pages


def dump_until_failures(conn, start_page=0, max_pages=256, failure_threshold=8):
    """
    Dumps sequential pages until max_pages or until too many consecutive failures.

    This is useful when the card type is unknown.
    It does not bypass authentication and does not force protected areas.
    """

    pages = {}
    consecutive_failures = 0

    for page in range(start_page, max_pages):
        data, sw1, sw2 = read_page(conn, page)

        page_entry = {
            "page": page,
            "readable": data is not None,
            "hex": hx(data) if data is not None else None,
            "ascii": ascii_preview(data) if data is not None else None,
            "sw": f"{sw1:02X}{sw2:02X}",
        }

        pages[str(page)] = page_entry

        if data is not None:
            consecutive_failures = 0
            print(f"[OK] Page {page:03d}: {hx(data)}  | {ascii_preview(data)}")
        else:
            consecutive_failures += 1
            print(
                f"[WARN] Page {page:03d}: non leggibile / non esistente "
                f"SW={sw1:02X}{sw2:02X} "
                f"(fail consecutivi: {consecutive_failures})"
            )

        if consecutive_failures >= failure_threshold:
            print(
                f"[INFO] Stop: raggiunti {failure_threshold} fallimenti consecutivi. "
                "Probabile fine memoria leggibile o area non supportata."
            )
            break

    return pages


def merge_page_dumps(*dumps):
    """
    Merges multiple page dictionaries.
    Later dictionaries overwrite earlier ones.
    """

    merged = {}

    for dump in dumps:
        for key, value in dump.items():
            merged[key] = value

    return dict(sorted(merged.items(), key=lambda item: int(item[0])))


def complete_readable_dump(conn, max_pages=256, failure_threshold=8, forced_end_page=None):
    """
    Main acquisition function.

    It attempts a complete readable dump with this logic:

    1. Read pages 0-3.
    2. Try to detect NFC Forum Type 2 Capability Container.
    3. If Type 2 is detected:
       - dump from page 0 to the estimated logical end page.
    4. If Type 2 is not detected:
       - dump sequentially until max_pages or consecutive failure threshold.

    This is intentionally non-destructive.
    """

    print("\n" + "=" * 78)
    print("STARTING COMPLETE READABLE NFC DUMP")
    print("=" * 78)

    print("[INFO] Lettura preliminare pagine 0-3...")
    initial_pages = read_initial_pages(conn)

    for key in sorted(initial_pages.keys(), key=lambda x: int(x)):
        entry = initial_pages[key]
        if entry["readable"]:
            print(f"[OK] Page {int(key):03d}: {entry['hex']}  | {entry['ascii']}")
        else:
            print(f"[WARN] Page {int(key):03d}: non leggibile  SW={entry['sw']}")

    cc = detect_type2_capability_container_from_pages(initial_pages)

    print("\n[INFO] Capability Container / Type 2 detection:")
    print(json.dumps(cc, indent=2, ensure_ascii=False))

    if forced_end_page is not None:
        print(f"\n[INFO] Forced acquisition range: page 0 -> page {forced_end_page}")
        full_pages = dump_range(conn, 0, forced_end_page)
        method = "forced_range"

    elif cc.get("present"):
        logical_end = cc.get("logical_end_page_estimated", 39)

        # Safety cap.
        logical_end = min(logical_end, max_pages - 1)

        print(f"\n[INFO] NFC Type 2-like tag detected.")
        print(f"[INFO] Estimated logical dump range: page 0 -> page {logical_end}")

        full_pages = dump_range(conn, 0, logical_end)
        method = "type2_capability_container_estimated_range"

    else:
        print("\n[INFO] Type 2 Capability Container non rilevato.")
        print("[INFO] Procedo con dump sequenziale fino a fine area leggibile/protetta.")
        print(f"[INFO] max_pages={max_pages}, failure_threshold={failure_threshold}")

        sequential_pages = dump_until_failures(
            conn,
            start_page=0,
            max_pages=max_pages,
            failure_threshold=failure_threshold,
        )

        full_pages = merge_page_dumps(initial_pages, sequential_pages)
        method = "sequential_until_failures"

    readable_count = sum(1 for p in full_pages.values() if p["readable"])
    unreadable_count = sum(1 for p in full_pages.values() if not p["readable"])

    print("\n" + "=" * 78)
    print("DUMP ACQUISITION COMPLETED")
    print("=" * 78)
    print(f"Acquisition method: {method}")
    print(f"Pages acquired in report: {len(full_pages)}")
    print(f"Readable pages: {readable_count}")
    print(f"Unreadable pages: {unreadable_count}")
    print("=" * 78 + "\n")

    return {
        "method": method,
        "type2_capability_container": cc,
        "pages": full_pages,
        "summary": {
            "pages_total_in_report": len(full_pages),
            "readable_pages": readable_count,
            "unreadable_pages": unreadable_count,
        }
    }



# =============================================================================
# MIFARE Classic 1K authorized acquisition
# =============================================================================

def parse_mfc_key(key_hex):
    """
    Parses a 6-byte MIFARE Classic key from HEX.

    Accepted formats:
    - FFFFFFFFFFFF
    - FF FF FF FF FF FF
    - FF:FF:FF:FF:FF:FF
    - FF-FF-FF-FF-FF-FF
    """

    cleaned = (
        key_hex.replace(" ", "")
        .replace(":", "")
        .replace("-", "")
        .strip()
        .upper()
    )

    if len(cleaned) != 12:
        raise ValueError("La chiave MIFARE Classic deve essere lunga 6 byte / 12 caratteri HEX.")

    try:
        return [int(cleaned[i:i + 2], 16) for i in range(0, 12, 2)]
    except ValueError:
        raise ValueError("Formato chiave HEX non valido.")


def save_mfc_key_template(filename):
    """
    Creates a JSON template for externally obtained / laboratory-provided keys.

    This does not generate, recover, brute-force or crack keys.
    It only creates a structured file that can later be filled with authorized keys.
    """

    ensure_parent_dir(filename)

    template = {
        "source": "external_authorized_laboratory_key_recovery_or_key_provision_phase",
        "description": (
            "Fill this file only with keys that were lawfully provided or recovered "
            "during an explicitly authorized laboratory phase."
        ),
        "uid": "REPLACE_WITH_CARD_UID",
        "notes": [
            "This file is used only for authorized MIFARE Classic acquisition.",
            "The acquisition script does not perform brute force, cracking, nested attacks, hardnested attacks or cloning.",
            "Use sector='all' only when the same key is known to apply to every sector.",
            "Do not leave placeholder keys in this file."
        ],
        "keys": [
            {
                "sector": "all",
                "key_type": "A",
                "key": "REPLACE_WITH_12_HEX_CHARS",
                "comment": "Replace with an authorized key or remove this entry."
            },
            {
                "sector": 0,
                "key_type": "A",
                "key": "REPLACE_WITH_12_HEX_CHARS",
                "comment": "Example sector-specific entry. Replace or remove."
            }
        ]
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)

    print(f"[OK] Template chiavi MIFARE creato in: {filename}")

def load_mfc_key_database(filename):
    """
    Loads a MIFARE Classic key database from JSON.

    Expected format:
    {
      "source": "external_authorized_laboratory_key_recovery_or_key_provision_phase",
      "uid": "B2 7B 50 17",
      "keys": [
        {"sector": 0, "key_type": "A", "key": "FFFFFFFFFFFF"},
        {"sector": 1, "key_type": "B", "key": "A0A1A2A3A4A5"},
        {"sector": "all", "key_type": "A", "key": "FFFFFFFFFFFF"}
      ]
    }
    """

    with open(filename, "r", encoding="utf-8") as f:
        payload = json.load(f)

    entries = payload.get("keys", [])

    if not entries:
        raise ValueError("Il keyfile non contiene chiavi nella sezione 'keys'.")

    normalized = []

    for entry in entries:
        sector = entry.get("sector")
        key_type = str(entry.get("key_type", "A")).upper()
        key_hex = entry.get("key")

        if not key_hex:
            raise ValueError(f"Chiave mancante nell'entry: {entry}")

        if str(key_hex).startswith("REPLACE_WITH"):
            raise ValueError(
                "Il keyfile contiene ancora placeholder. "
                "Sostituisci REPLACE_WITH_12_HEX_CHARS con una chiave autorizzata."
            )

        if key_type not in {"A", "B"}:
            raise ValueError(f"Tipo chiave non valido: {key_type}. Usa A o B.")

        if isinstance(sector, str) and sector.lower() == "all":
            sector = "all"
        else:
            try:
                sector = int(sector)
            except Exception:
                raise ValueError(f"Settore non valido: {sector}")

            if sector < 0 or sector > 15:
                raise ValueError(f"Settore fuori range per MIFARE Classic 1K: {sector}")

        key_bytes = parse_mfc_key(key_hex)

        normalized.append({
            "sector": sector,
            "key_type": key_type,
            "key_hex": key_hex,
            "key_bytes": key_bytes,
            "comment": entry.get("comment")
        })

    return {
        "source": payload.get("source"),
        "uid": payload.get("uid"),
        "description": payload.get("description"),
        "entries": normalized,
        "raw_entry_count": len(entries),
    }

def build_mfc_key_database_from_single_key(key_hex, key_type="A"):
    """
    Builds an in-memory key database using one authorized key for all sectors.
    """

    key_type = key_type.upper()

    if key_type not in {"A", "B"}:
        raise ValueError("mfc_key_type deve essere A oppure B.")

    key_bytes = parse_mfc_key(key_hex)

    return {
        "source": "single_authorized_key_provided_by_user",
        "uid": None,
        "description": "Single key applied to all sectors for authorized acquisition.",
        "entries": [
            {
                "sector": "all",
                "key_type": key_type,
                "key_hex": key_hex,
                "key_bytes": key_bytes,
                "comment": "Single key provided through CLI"
            }
        ],
        "raw_entry_count": 1,
    }


def get_mfc_key_candidates_for_sector(key_database, sector):
    """
    Returns candidate keys for a given sector.

    Sector-specific keys are tried before global 'all' keys.
    """

    entries = key_database.get("entries", [])

    sector_specific = [
        e for e in entries
        if e.get("sector") == sector
    ]

    global_keys = [
        e for e in entries
        if e.get("sector") == "all"
    ]

    candidates = sector_specific + global_keys

    dedup = []
    seen = set()

    for item in candidates:
        fingerprint = (
            item["sector"],
            item["key_type"],
            "".join(f"{b:02X}" for b in item["key_bytes"])
        )

        if fingerprint in seen:
            continue

        seen.add(fingerprint)
        dedup.append(item)

    return dedup


def mfc_load_key(conn, key_bytes, key_slot=0):
    """
    Loads a MIFARE Classic key into reader volatile memory.

    PC/SC pseudo-APDU:
    FF 82 00 <key_slot> 06 <key>
    """

    apdu = [0xFF, 0x82, 0x00, key_slot, 0x06] + key_bytes
    data, sw1, sw2 = transmit(conn, apdu, verbose=False)

    return sw1 == 0x90 and sw2 == 0x00, sw1, sw2


def mfc_authenticate_block(conn, block_number, key_type="A", key_slot=0):
    """
    Authenticates a MIFARE Classic block.

    key_type:
    - A -> 0x60
    - B -> 0x61

    PC/SC pseudo-APDU:
    FF 86 00 00 05 01 00 <block> <key_type> <key_slot>
    """

    if key_type.upper() == "A":
        key_type_byte = 0x60
    elif key_type.upper() == "B":
        key_type_byte = 0x61
    else:
        raise ValueError("key_type deve essere 'A' oppure 'B'.")

    apdu = [
        0xFF, 0x86, 0x00, 0x00, 0x05,
        0x01, 0x00, block_number, key_type_byte, key_slot
    ]

    data, sw1, sw2 = transmit(conn, apdu, verbose=False)

    return sw1 == 0x90 and sw2 == 0x00, sw1, sw2


def mfc_read_block(conn, block_number):
    """
    Reads one MIFARE Classic block, 16 bytes.

    PC/SC pseudo-APDU:
    FF B0 00 <block> 10
    """

    apdu = [0xFF, 0xB0, 0x00, block_number, 0x10]
    data, sw1, sw2 = transmit(conn, apdu, verbose=False)

    if sw1 == 0x90 and sw2 == 0x00:
        return data, sw1, sw2

    return None, sw1, sw2


def mfc_sector_of_block(block_number):
    """
    MIFARE Classic 1K:
    - 16 sectors
    - 4 blocks per sector
    - 64 total blocks
    """

    return block_number // 4


def mfc_blocks_for_sector(sector):
    """
    Returns the 4 block numbers belonging to a MIFARE Classic 1K sector.
    """

    start = sector * 4
    return list(range(start, start + 4))


def mfc_is_trailer_block(block_number):
    """
    In MIFARE Classic 1K, the last block of each sector is the sector trailer:
    3, 7, 11, ..., 63.
    """

    return block_number % 4 == 3


def mfc_block_role(block_number):
    """
    Returns a simple role label for a MIFARE Classic block.
    """

    if block_number == 0:
        return "manufacturer_block"

    if mfc_is_trailer_block(block_number):
        return "sector_trailer"

    return "data_block"


def mfc_dump_classic_1k_authorized(conn, key_database, key_slot=0):
    """
    Acquires a MIFARE Classic 1K dump using authorized keys.

    This function:
    - uses only keys provided by key_database;
    - does not brute-force keys;
    - does not recover keys;
    - does not perform nested/hardnested attacks;
    - does not write to the card;
    - documents acquired and non-acquired sectors/blocks.
    """

    print("\n" + "=" * 78)
    print("STARTING MIFARE CLASSIC 1K AUTHORIZED ACQUISITION")
    print("=" * 78)
    print("[INFO] This module uses only provided/authorized keys.")
    print("[INFO] No brute force, cracking, key recovery or cloning is performed.")
    print("=" * 78 + "\n")

    blocks = {}
    sectors = {}

    total_readable_blocks = 0
    total_unreadable_blocks = 0
    authenticated_sectors = []
    non_authenticated_sectors = []

    for sector in range(16):
        sector_blocks = mfc_blocks_for_sector(sector)
        candidates = get_mfc_key_candidates_for_sector(key_database, sector)

        sector_info = {
            "sector": sector,
            "blocks": sector_blocks,
            "candidate_key_count": len(candidates),
            "authenticated": False,
            "auth_key_type_used": None,
            "auth_sw": None,
            "readable_blocks": [],
            "unreadable_blocks": [],
            "status": None,
        }

        print("\n" + "-" * 78)
        print(f"[INFO] Sector {sector:02d} - blocks {sector_blocks}")
        print(f"[INFO] Candidate keys available: {len(candidates)}")

        if not candidates:
            sector_info["status"] = "no_key_available"
            non_authenticated_sectors.append(sector)

            print(f"[WARN] Sector {sector:02d}: no authorized key available.")

            for block in sector_blocks:
                blocks[str(block)] = {
                    "sector": sector,
                    "block": block,
                    "role": mfc_block_role(block),
                    "is_sector_trailer": mfc_is_trailer_block(block),
                    "authenticated": False,
                    "readable": False,
                    "hex": None,
                    "ascii": None,
                    "auth_sw": None,
                    "read_sw": None,
                    "status": "not_attempted_no_key_available",
                }
                sector_info["unreadable_blocks"].append(block)
                total_unreadable_blocks += 1

            sectors[str(sector)] = sector_info
            continue

        chosen_key = None

        # Try candidate keys for the first block of the sector.
        for candidate in candidates:
            key_type = candidate["key_type"]
            key_bytes = candidate["key_bytes"]

            loaded, load_sw1, load_sw2 = mfc_load_key(
                conn=conn,
                key_bytes=key_bytes,
                key_slot=key_slot
            )

            if not loaded:
                print(
                    f"[WARN] Sector {sector:02d}: key load failed "
                    f"for Key {key_type}, SW={load_sw1:02X}{load_sw2:02X}"
                )
                continue

            auth_ok, auth_sw1, auth_sw2 = mfc_authenticate_block(
                conn=conn,
                block_number=sector_blocks[0],
                key_type=key_type,
                key_slot=key_slot
            )

            if auth_ok:
                chosen_key = candidate
                sector_info["authenticated"] = True
                sector_info["auth_key_type_used"] = key_type
                sector_info["auth_sw"] = f"{auth_sw1:02X}{auth_sw2:02X}"
                sector_info["status"] = "authenticated"
                authenticated_sectors.append(sector)

                print(f"[OK] Sector {sector:02d}: authenticated with Key {key_type}")
                break

            print(
                f"[WARN] Sector {sector:02d}: authentication failed "
                f"with Key {key_type}, SW={auth_sw1:02X}{auth_sw2:02X}"
            )

        if chosen_key is None:
            sector_info["status"] = "authentication_failed_with_provided_keys"
            non_authenticated_sectors.append(sector)

            print(f"[WARN] Sector {sector:02d}: not acquired. Authentication failed.")

            for block in sector_blocks:
                blocks[str(block)] = {
                    "sector": sector,
                    "block": block,
                    "role": mfc_block_role(block),
                    "is_sector_trailer": mfc_is_trailer_block(block),
                    "authenticated": False,
                    "readable": False,
                    "hex": None,
                    "ascii": None,
                    "auth_sw": "authentication_failed",
                    "read_sw": None,
                    "status": "not_acquired_authentication_failed",
                }
                sector_info["unreadable_blocks"].append(block)
                total_unreadable_blocks += 1

            sectors[str(sector)] = sector_info
            continue

        # Read all blocks in authenticated sector.
        key_type = chosen_key["key_type"]
        key_bytes = chosen_key["key_bytes"]

        for block in sector_blocks:
            loaded, load_sw1, load_sw2 = mfc_load_key(
                conn=conn,
                key_bytes=key_bytes,
                key_slot=key_slot
            )

            if not loaded:
                blocks[str(block)] = {
                    "sector": sector,
                    "block": block,
                    "role": mfc_block_role(block),
                    "is_sector_trailer": mfc_is_trailer_block(block),
                    "authenticated": False,
                    "readable": False,
                    "hex": None,
                    "ascii": None,
                    "auth_sw": f"{load_sw1:02X}{load_sw2:02X}",
                    "read_sw": None,
                    "status": "key_load_failed_before_read",
                }
                sector_info["unreadable_blocks"].append(block)
                total_unreadable_blocks += 1
                continue

            auth_ok, auth_sw1, auth_sw2 = mfc_authenticate_block(
                conn=conn,
                block_number=block,
                key_type=key_type,
                key_slot=key_slot
            )

            if not auth_ok:
                blocks[str(block)] = {
                    "sector": sector,
                    "block": block,
                    "role": mfc_block_role(block),
                    "is_sector_trailer": mfc_is_trailer_block(block),
                    "authenticated": False,
                    "readable": False,
                    "hex": None,
                    "ascii": None,
                    "auth_sw": f"{auth_sw1:02X}{auth_sw2:02X}",
                    "read_sw": None,
                    "status": "authentication_failed_before_read",
                }
                sector_info["unreadable_blocks"].append(block)
                total_unreadable_blocks += 1

                print(
                    f"[WARN] Sector {sector:02d}, Block {block:02d}: "
                    f"auth failed before read, SW={auth_sw1:02X}{auth_sw2:02X}"
                )
                continue

            data, read_sw1, read_sw2 = mfc_read_block(conn, block)

            if data is None:
                blocks[str(block)] = {
                    "sector": sector,
                    "block": block,
                    "role": mfc_block_role(block),
                    "is_sector_trailer": mfc_is_trailer_block(block),
                    "authenticated": True,
                    "readable": False,
                    "hex": None,
                    "ascii": None,
                    "auth_sw": f"{auth_sw1:02X}{auth_sw2:02X}",
                    "read_sw": f"{read_sw1:02X}{read_sw2:02X}",
                    "status": "read_failed_after_authentication",
                }
                sector_info["unreadable_blocks"].append(block)
                total_unreadable_blocks += 1

                print(
                    f"[WARN] Sector {sector:02d}, Block {block:02d}: "
                    f"read failed, SW={read_sw1:02X}{read_sw2:02X}"
                )
                continue

            role = mfc_block_role(block)

            blocks[str(block)] = {
                "sector": sector,
                "block": block,
                "role": role,
                "is_sector_trailer": mfc_is_trailer_block(block),
                "authenticated": True,
                "readable": True,
                "hex": hx(data),
                "ascii": ascii_preview(data),
                "auth_sw": f"{auth_sw1:02X}{auth_sw2:02X}",
                "read_sw": f"{read_sw1:02X}{read_sw2:02X}",
                "status": "acquired",
            }

            sector_info["readable_blocks"].append(block)
            total_readable_blocks += 1

            print(
                f"[OK] Sector {sector:02d}, Block {block:02d} "
                f"[{role}]: {hx(data)} | {ascii_preview(data)}"
            )

        sectors[str(sector)] = sector_info

    print("\n" + "=" * 78)
    print("MIFARE CLASSIC 1K AUTHORIZED ACQUISITION COMPLETED")
    print("=" * 78)
    print(f"Readable blocks: {total_readable_blocks}")
    print(f"Unreadable blocks: {total_unreadable_blocks}")
    print(f"Authenticated sectors: {authenticated_sectors}")
    print(f"Non-authenticated sectors: {non_authenticated_sectors}")
    print("=" * 78 + "\n")

    return {
        "method": "mifare_classic_1k_authorized_sector_block_acquisition",
        "key_source": key_database.get("source"),
        "key_entry_count": key_database.get("raw_entry_count"),
        "blocks": blocks,
        "sectors": sectors,
        "summary": {
            "total_sectors": 16,
            "total_blocks": 64,
            "readable_blocks": total_readable_blocks,
            "unreadable_blocks": total_unreadable_blocks,
            "authenticated_sectors": authenticated_sectors,
            "non_authenticated_sectors": non_authenticated_sectors,
        },
        "forensic_notes": [
            "This acquisition used only provided/authorized keys.",
            "No brute force, cracking, key recovery, nested attack, hardnested attack or cloning was performed by this script.",
            "Non-authenticated sectors were not acquired and are reported as such.",
            "Sector trailer blocks may contain access conditions and key material; handle the dump as sensitive evidence."
        ]
    }


def mfc_blocks_to_readable_bytes(blocks):
    """
    Converts readable MIFARE blocks into a contiguous byte sequence.
    """

    raw = bytearray()

    for block_key in sorted(blocks.keys(), key=lambda x: int(x)):
        entry = blocks[block_key]

        if not entry.get("readable"):
            continue

        hex_value = entry.get("hex")
        if not hex_value:
            continue

        try:
            raw.extend(int(x, 16) for x in hex_value.split())
        except ValueError:
            continue

    return bytes(raw)


def analyze_mfc_dump_payload(payload):
    """
    Performs automated triage on a MIFARE Classic 1K dump payload.
    """

    acquisition = payload.get("acquisition", {})
    blocks = acquisition.get("blocks", {})
    sectors = acquisition.get("sectors", {})
    raw_bytes = mfc_blocks_to_readable_bytes(blocks)

    ascii_strings = extract_ascii_strings(raw_bytes)
    urls, emails = extract_urls_and_emails(ascii_strings)

    readable_blocks = [
        b for b in blocks.values()
        if b.get("readable")
    ]

    unreadable_blocks = [
        b for b in blocks.values()
        if not b.get("readable")
    ]

    trailer_blocks = [
        b for b in readable_blocks
        if b.get("is_sector_trailer")
    ]

    data_blocks = [
        b for b in readable_blocks
        if not b.get("is_sector_trailer")
    ]

    empty_or_zero_blocks = []
    ff_blocks = []

    for block in readable_blocks:
        hex_value = block.get("hex") or ""
        normalized = hex_value.replace(" ", "").upper()

        if normalized == "00" * 16:
            empty_or_zero_blocks.append(block.get("block"))

        if normalized == "FF" * 16:
            ff_blocks.append(block.get("block"))

    sector_summary = []

    for sector_key in sorted(sectors.keys(), key=lambda x: int(x)):
        s = sectors[sector_key]
        sector_summary.append({
            "sector": s.get("sector"),
            "authenticated": s.get("authenticated"),
            "auth_key_type_used": s.get("auth_key_type_used"),
            "readable_blocks": s.get("readable_blocks", []),
            "unreadable_blocks": s.get("unreadable_blocks", []),
            "status": s.get("status"),
        })

    analysis = {
        "analysis_metadata": {
            "created_at": now_timestamp(),
            "analysis_mode": "mifare_classic_1k_authorized_dump_analysis",
        },
        "source_card_identification": payload.get("card_identification", {}),
        "card_profile": payload.get("card_profile") or {},
        "summary": {
            "readable_blocks": len(readable_blocks),
            "unreadable_blocks": len(unreadable_blocks),
            "readable_data_blocks": len(data_blocks),
            "readable_trailer_blocks": len(trailer_blocks),
            "readable_bytes": len(raw_bytes),
            "sha256_readable_bytes": sha256_bytes(raw_bytes),
            "ascii_string_count": len(ascii_strings),
            "url_count": len(urls),
            "email_count": len(emails),
            "zero_block_count": len(empty_or_zero_blocks),
            "ff_block_count": len(ff_blocks),
        },
        "sector_summary": sector_summary,
        "ascii_strings": ascii_strings,
        "urls": urls,
        "emails": emails,
        "zero_blocks": empty_or_zero_blocks,
        "ff_blocks": ff_blocks,
        "forensic_interpretation": [
            "Readable blocks were acquired only after successful authentication with provided keys.",
            "Non-authenticated sectors remain not acquired and may contain additional data.",
            "Sector trailer blocks should be interpreted cautiously because they may contain access conditions and key material.",
            "ASCII strings, URLs and emails are automated triage indicators and require manual verification."
        ],
        "forensic_limitations": [
            "This analysis depends on the set of keys provided to the script.",
            "The script does not recover missing keys.",
            "The absence of readable data in non-authenticated sectors does not imply absence of data.",
            "Attribution requires correlation with external systems, logs, issuer data or other investigative evidence."
        ]
    }

    return analysis


def save_mfc_dump_json(filename, reader, uid, atr, card_profile, acquisition, key_database):
    """
    Saves a MIFARE Classic 1K acquisition payload to JSON.
    Raw provided keys are intentionally not saved in the metadata.
    """

    ensure_parent_dir(filename)

    raw_bytes = mfc_blocks_to_readable_bytes(acquisition.get("blocks", {}))

    payload = {
        "case_metadata": {
            "created_at": now_timestamp(),
            "tool": "nfc_lab_tool.py",
            "tool_mode": "mifare_classic_1k_authorized_acquisition",
        },
        "reader": str(reader),
        "card_identification": {
            "uid": hx(uid) if uid else None,
            "atr": hx(atr) if atr else None,
        },
        "card_profile": card_profile,
        "key_material_metadata": {
            "source": key_database.get("source"),
            "provided_key_entry_count": key_database.get("raw_entry_count"),
            "raw_keys_saved_in_metadata": False,
        },
        "integrity": {
            "sha256_readable_bytes": sha256_bytes(raw_bytes),
            "readable_bytes_length": len(raw_bytes),
        },
        "acquisition": acquisition,
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    file_hash = sha256_file(filename)

    hash_file = filename + ".sha256"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"{file_hash}  {Path(filename).name}\n")

    print(f"[OK] Dump MIFARE Classic salvato in: {filename}")
    print(f"[OK] SHA256 dump MIFARE JSON: {file_hash}")
    print(f"[OK] Hash salvato in: {hash_file}")

    return payload


def save_mfc_analysis_json(filename, analysis):
    """
    Saves MIFARE analysis JSON and SHA256 file.
    """

    ensure_parent_dir(filename)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)

    file_hash = sha256_file(filename)

    hash_file = filename + ".sha256"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"{file_hash}  {Path(filename).name}\n")

    print(f"[OK] Analisi MIFARE salvata in: {filename}")
    print(f"[OK] SHA256 analisi MIFARE JSON: {file_hash}")
    print(f"[OK] Hash salvato in: {hash_file}")


def save_mfc_markdown_report(filename, dump_payload, analysis):
    """
    Saves a concise Markdown report for MIFARE Classic 1K acquisition.
    """

    ensure_parent_dir(filename)

    card_id = dump_payload.get("card_identification", {})
    card_profile = dump_payload.get("card_profile") or {}
    acquisition = dump_payload.get("acquisition", {})
    integrity = dump_payload.get("integrity", {})
    summary = analysis.get("summary", {})

    lines = []

    lines.append("# MIFARE Classic 1K Forensic Acquisition Report")
    lines.append("")
    lines.append(f"Generated at: `{now_timestamp()}`")
    lines.append("")
    lines.append("## 1. Card identification")
    lines.append("")
    lines.append(f"- UID: `{card_id.get('uid')}`")
    lines.append(f"- ATR: `{card_id.get('atr')}`")
    lines.append(f"- Family: `{card_profile.get('family')}`")
    lines.append(f"- Technology: `{card_profile.get('technology')}`")
    lines.append(f"- Memory model: `{card_profile.get('memory_model')}`")
    lines.append("")
    lines.append("## 2. Acquisition method")
    lines.append("")
    lines.append(f"- Method: `{acquisition.get('method')}`")
    lines.append(f"- Key source: `{acquisition.get('key_source')}`")
    lines.append(f"- Provided key entries: `{acquisition.get('key_entry_count')}`")
    lines.append("- The script used only externally provided / authorized keys.")
    lines.append("- The script did not perform brute force, cracking, key recovery, nested/hardnested attacks or cloning.")
    lines.append("")
    lines.append("## 3. Acquisition summary")
    lines.append("")
    acq_summary = acquisition.get("summary", {})
    lines.append(f"- Total sectors: `{acq_summary.get('total_sectors')}`")
    lines.append(f"- Total blocks: `{acq_summary.get('total_blocks')}`")
    lines.append(f"- Readable blocks: `{acq_summary.get('readable_blocks')}`")
    lines.append(f"- Unreadable blocks: `{acq_summary.get('unreadable_blocks')}`")
    lines.append(f"- Authenticated sectors: `{acq_summary.get('authenticated_sectors')}`")
    lines.append(f"- Non-authenticated sectors: `{acq_summary.get('non_authenticated_sectors')}`")
    lines.append(f"- SHA256 readable bytes: `{integrity.get('sha256_readable_bytes')}`")
    lines.append("")
    lines.append("## 4. Sector summary")
    lines.append("")
    lines.append("| Sector | Authenticated | Key Type Used | Readable Blocks | Unreadable Blocks | Status |")
    lines.append("|---:|---:|---|---|---|---|")

    for sector in analysis.get("sector_summary", []):
        lines.append(
            f"| {sector.get('sector')} "
            f"| {sector.get('authenticated')} "
            f"| {sector.get('auth_key_type_used')} "
            f"| {sector.get('readable_blocks')} "
            f"| {sector.get('unreadable_blocks')} "
            f"| {sector.get('status')} |"
        )

    lines.append("")
    lines.append("## 5. Content triage")
    lines.append("")
    lines.append(f"- Readable bytes: `{summary.get('readable_bytes')}`")
    lines.append(f"- ASCII strings: `{summary.get('ascii_string_count')}`")
    lines.append(f"- URLs: `{summary.get('url_count')}`")
    lines.append(f"- Emails: `{summary.get('email_count')}`")
    lines.append(f"- Zero blocks: `{summary.get('zero_block_count')}`")
    lines.append(f"- FF blocks: `{summary.get('ff_block_count')}`")
    lines.append("")

    if analysis.get("urls"):
        lines.append("### URLs")
        lines.append("")
        for url in analysis.get("urls"):
            lines.append(f"- `{url}`")
        lines.append("")

    if analysis.get("emails"):
        lines.append("### Emails")
        lines.append("")
        for email in analysis.get("emails"):
            lines.append(f"- `{email}`")
        lines.append("")

    if analysis.get("ascii_strings"):
        lines.append("### ASCII strings")
        lines.append("")
        for item in analysis.get("ascii_strings")[:50]:
            lines.append(f"- `{item}`")
        if len(analysis.get("ascii_strings")) > 50:
            lines.append("- Additional strings omitted from Markdown report; see JSON analysis.")
        lines.append("")

    lines.append("## 6. Forensic interpretation")
    lines.append("")
    for item in analysis.get("forensic_interpretation", []):
        lines.append(f"- {item}")

    lines.append("")
    lines.append("## 7. Limitations")
    lines.append("")
    for item in analysis.get("forensic_limitations", []):
        lines.append(f"- {item}")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    file_hash = sha256_file(filename)

    hash_file = filename + ".sha256"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"{file_hash}  {Path(filename).name}\n")

    print(f"[OK] Report MIFARE Markdown salvato in: {filename}")
    print(f"[OK] SHA256 report MIFARE Markdown: {file_hash}")
    print(f"[OK] Hash salvato in: {hash_file}")


def run_mfc_authorized_acquisition(
    reader_index=None,
    keyfile=None,
    single_key=None,
    single_key_type="A",
    output_dump=None,
    output_analysis=None,
    output_report=None,
):
    """
    Runs the full MIFARE Classic 1K authorized acquisition workflow.
    """

    if keyfile is None and single_key is None:
        print("[ERROR] Devi fornire --mfc-keyfile oppure --mfc-key.")
        print("[INFO] Lo script non recupera chiavi: usa solo chiavi già disponibili/autorizzate.")
        sys.exit(1)

    if keyfile:
        key_database = load_mfc_key_database(keyfile)
    else:
        key_database = build_mfc_key_database_from_single_key(
            key_hex=single_key,
            key_type=single_key_type
        )

    reader, conn = connect_reader(reader_index)

    uid = get_uid(conn)
    atr = get_atr(conn)
    card_profile = identify_card_family_from_atr(atr)

    current_uid = hx(uid) if uid else None
    expected_uid = key_database.get("uid")

    if expected_uid and expected_uid != "REPLACE_WITH_CARD_UID":
        if current_uid and expected_uid.strip().upper() != current_uid.strip().upper():
            print("[ERROR] UID del keyfile diverso dall'UID della card attuale.")
            print(f"[ERROR] UID card attuale: {current_uid}")
            print(f"[ERROR] UID nel keyfile: {expected_uid}")
            print("[INFO] Interrompo per evitare acquisizione con chiavi riferite a un'altra card.")
            sys.exit(1)

    print("\n" + "=" * 78)
    print("CARD IDENTIFICATION")
    print("=" * 78)
    print(f"Reader: {reader}")
    print(f"UID: {hx(uid) if uid else 'Not available'}")
    print(f"ATR: {hx(atr) if atr else 'Not available'}")
    print("=" * 78 + "\n")

    print_card_profile(card_profile)

    if card_profile.get("family") != "MIFARE Classic 1K":
        print("[WARN] ATR profile is not MIFARE Classic 1K.")
        print("[WARN] Continuing only because MIFARE mode was explicitly requested.")

    acquisition = mfc_dump_classic_1k_authorized(
        conn=conn,
        key_database=key_database,
        key_slot=0
    )

    if output_dump is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        uid_part = hx(uid).replace(" ", "") if uid else "unknown_uid"
        output_dump = f"dumps/mfc1k_dump_{uid_part}_{timestamp}.json"

    dump_payload = save_mfc_dump_json(
        filename=output_dump,
        reader=reader,
        uid=uid,
        atr=atr,
        card_profile=card_profile,
        acquisition=acquisition,
        key_database=key_database
    )

    analysis = analyze_mfc_dump_payload(dump_payload)

    if output_analysis is None:
        output_analysis = output_dump.replace(".json", "_analysis.json")

    save_mfc_analysis_json(output_analysis, analysis)

    if output_report is None:
        output_report = output_dump.replace(".json", "_report.md")

    save_mfc_markdown_report(output_report, dump_payload, analysis)

    return dump_payload, analysis


# =============================================================================
# Save and load dump
# =============================================================================

def dump_pages_to_readable_bytes(pages):
    """
    Converts readable pages into a contiguous byte sequence.

    Unreadable pages are skipped.
    """

    raw = bytearray()

    for page_key in sorted(pages.keys(), key=lambda x: int(x)):
        entry = pages[page_key]

        if not entry.get("readable"):
            continue

        hex_value = entry.get("hex")
        if not hex_value:
            continue

        try:
            raw.extend(int(x, 16) for x in hex_value.split())
        except ValueError:
            continue

    return bytes(raw)


def save_dump_json(filename, reader, uid, atr, acquisition, card_profile=None, pcsc_scan_snapshot=None):
    """
    Saves acquisition dump to JSON and computes file hash.
    """

    ensure_parent_dir(filename)

    pages = acquisition["pages"]
    raw_bytes = dump_pages_to_readable_bytes(pages)

    payload = {
        "case_metadata": {
            "created_at": now_timestamp(),
            "tool": "nfc_lab_tool.py",
            "tool_mode": "non_destructive_readable_dump",
        },
        "reader": str(reader),
        "card_identification": {
            "uid": hx(uid) if uid else None,
            "atr": hx(atr) if atr else None,
        },
        "card_profile": card_profile,
        "pcsc_scan_snapshot": pcsc_scan_snapshot,
        "acquisition": {
            "method": acquisition["method"],
            "summary": acquisition["summary"],
            "type2_capability_container": acquisition["type2_capability_container"],
        },
        "integrity": {
            "sha256_readable_bytes": sha256_bytes(raw_bytes),
            "readable_bytes_length": len(raw_bytes),
        },
        "pages": pages,
        "forensic_notes": [
            "The dump contains only pages readable through non-destructive PC/SC commands.",
            "Unreadable pages may be protected, absent, unsupported, or require card-specific authentication.",
            "No write operation was performed on the original card.",
            "The SHA256 over readable bytes is useful for repeatability checks but does not include unreadable pages."
        ]
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    file_hash = sha256_file(filename)

    hash_file = filename + ".sha256"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"{file_hash}  {Path(filename).name}\n")

    print(f"[OK] Dump salvato in: {filename}")
    print(f"[OK] SHA256 dump JSON: {file_hash}")
    print(f"[OK] Hash salvato in: {hash_file}")

    return payload


def load_dump_json(filename):
    """
    Loads a previously acquired dump JSON.
    """

    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================================
# Dump analysis
# =============================================================================

URI_PREFIXES = {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
    0x05: "tel:",
    0x06: "mailto:",
    0x07: "ftp://anonymous:anonymous@",
    0x08: "ftp://ftp.",
    0x09: "ftps://",
    0x0A: "sftp://",
    0x0B: "smb://",
    0x0C: "nfs://",
    0x0D: "ftp://",
    0x0E: "dav://",
    0x0F: "news:",
    0x10: "telnet://",
    0x11: "imap:",
    0x12: "rtsp://",
    0x13: "urn:",
    0x14: "pop:",
    0x15: "sip:",
    0x16: "sips:",
    0x17: "tftp:",
    0x18: "btspp://",
    0x19: "btl2cap://",
    0x1A: "btgoep://",
    0x1B: "tcpobex://",
    0x1C: "irdaobex://",
    0x1D: "file://",
    0x1E: "urn:epc:id:",
    0x1F: "urn:epc:tag:",
    0x20: "urn:epc:pat:",
    0x21: "urn:epc:raw:",
    0x22: "urn:epc:",
    0x23: "urn:nfc:",
}


def extract_ascii_strings(raw_bytes, min_length=4):
    """
    Extracts printable ASCII strings from raw bytes.
    """

    results = []
    current = []

    for b in raw_bytes:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_length:
                results.append("".join(current))
            current = []

    if len(current) >= min_length:
        results.append("".join(current))

    return results


def extract_urls_and_emails(strings):
    """
    Extracts URLs and emails from ASCII strings.
    """

    joined = "\n".join(strings)

    urls = re.findall(r"https?://[^\s\"'>]+", joined, flags=re.IGNORECASE)
    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        joined
    )

    return sorted(set(urls)), sorted(set(emails))


def find_ndef_tlvs(raw_bytes):
    """
    Searches for NDEF TLV structures.

    TLV type 0x03 = NDEF Message TLV.
    TLV type 0xFE = Terminator TLV.
    """

    results = []
    i = 0

    while i < len(raw_bytes):
        tlv_type = raw_bytes[i]

        if tlv_type == 0x03:
            if i + 1 >= len(raw_bytes):
                break

            length_byte = raw_bytes[i + 1]

            if length_byte == 0xFF:
                if i + 3 >= len(raw_bytes):
                    break

                length = (raw_bytes[i + 2] << 8) | raw_bytes[i + 3]
                payload_start = i + 4
            else:
                length = length_byte
                payload_start = i + 2

            payload_end = payload_start + length
            payload = raw_bytes[payload_start:payload_end]

            results.append({
                "offset": i,
                "tlv_type": "NDEF Message TLV",
                "length": length,
                "payload_hex": hx(payload),
                "parsed_record": parse_simple_ndef_record(payload),
            })

            i = payload_end
            continue

        i += 1

    return results


def parse_simple_ndef_record(payload):
    """
    Parses a simple first NDEF record where possible.

    Supported:
    - URI record, type U
    - Text record, type T
    """

    if not payload or len(payload) < 3:
        return {
            "parsed": False,
            "reason": "Payload too short"
        }

    try:
        header = payload[0]
        short_record = bool(header & 0x10)
        id_length_present = bool(header & 0x08)

        type_length = payload[1]
        index = 2

        if short_record:
            payload_length = payload[index]
            index += 1
        else:
            if len(payload) < index + 4:
                return {
                    "parsed": False,
                    "reason": "Long NDEF payload length incomplete"
                }

            payload_length = int.from_bytes(payload[index:index + 4], byteorder="big")
            index += 4

        if id_length_present:
            id_length = payload[index]
            index += 1
        else:
            id_length = 0

        record_type = payload[index:index + type_length]
        index += type_length

        if id_length_present:
            index += id_length

        record_payload = payload[index:index + payload_length]

        result = {
            "parsed": True,
            "header_hex": f"{header:02X}",
            "short_record": short_record,
            "type": record_type.decode("ascii", errors="replace"),
            "payload_length": payload_length,
            "payload_hex": hx(record_payload),
        }

        if record_type == b"U" and record_payload:
            prefix_code = record_payload[0]
            uri_body = record_payload[1:].decode("utf-8", errors="replace")
            result["decoded_type"] = "URI"
            result["decoded_value"] = URI_PREFIXES.get(prefix_code, "") + uri_body

        elif record_type == b"T" and record_payload:
            status = record_payload[0]
            language_length = status & 0x3F
            language = record_payload[1:1 + language_length].decode("ascii", errors="replace")
            text = record_payload[1 + language_length:].decode("utf-8", errors="replace")

            result["decoded_type"] = "Text"
            result["language"] = language
            result["decoded_value"] = text

        else:
            result["decoded_type"] = "Unknown or unsupported simple NDEF record"

        return result

    except Exception as e:
        return {
            "parsed": False,
            "reason": str(e)
        }


def analyze_dump_payload(payload):
    """
    Performs non-destructive analysis on a previously acquired dump payload.
    """

    pages = payload.get("pages", {})
    card_profile = payload.get("card_profile") or {}
    raw_bytes = dump_pages_to_readable_bytes(pages)

    ascii_strings = extract_ascii_strings(raw_bytes)
    urls, emails = extract_urls_and_emails(ascii_strings)
    ndef_tlvs = find_ndef_tlvs(raw_bytes)

    card_classification = classify_card_from_acquisition(payload)


    protected_area_analysis = infer_protected_and_unreadable_areas(payload)


    readable_pages = [
        entry for entry in pages.values()
        if entry.get("readable")
    ]

    unreadable_pages = [
        entry for entry in pages.values()
        if not entry.get("readable")
    ]

    analysis = {
        "analysis_metadata": {
            "created_at": now_timestamp(),
            "analysis_mode": "offline_analysis_of_acquired_dump",
        },
        "source_card_identification": payload.get("card_identification", {}),
        "source_acquisition": payload.get("acquisition", {}),
        "card_profile": card_profile,
        "summary": {
            "readable_pages": len(readable_pages),
            "unreadable_pages": len(unreadable_pages),
            "readable_bytes": len(raw_bytes),
            "sha256_readable_bytes": sha256_bytes(raw_bytes),
            "ascii_string_count": len(ascii_strings),
            "url_count": len(urls),
            "email_count": len(emails),
            "ndef_tlv_count": len(ndef_tlvs),
        },
        "card_classification": card_classification,
        "protected_area_analysis": protected_area_analysis,
        "ascii_strings": ascii_strings,
        "urls": urls,
        "emails": emails,
        "ndef_tlvs": ndef_tlvs,
        "interpretation_notes": build_interpretation_notes(
            payload=payload,
            ascii_strings=ascii_strings,
            urls=urls,
            emails=emails,
            ndef_tlvs=ndef_tlvs
        ),
        "forensic_limitations": [
            "The analysis is based only on pages acquired in the dump.",
            "Unreadable pages may contain additional information not accessible through non-authenticated PC/SC reads.",
            "Decoded NDEF records are automated interpretations and should be manually verified.",
            "The presence of UID alone is not sufficient to attribute the card to a person or event.",
            "Correlation with context of seizure, external systems, logs, access-control databases or witness information may be required."
        ]
    }

    return analysis

def infer_protected_and_unreadable_areas(payload):
    """
    Infers possible protected, unavailable or unsupported memory areas.

    This function does not prove that an area is protected.
    It performs forensic triage based on:
    - readable/unreadable pages
    - status words
    - expected memory range from Type 2 Capability Container, if available
    - error patterns
    """

    pages = payload.get("pages", {})
    acquisition = payload.get("acquisition", {})
    cc = acquisition.get("type2_capability_container", {})

    if not pages:
        return {
            "available": False,
            "reason": "No pages found in dump payload"
        }

    sorted_pages = [
        pages[key]
        for key in sorted(pages.keys(), key=lambda x: int(x))
    ]

    readable_pages = [
        p["page"] for p in sorted_pages
        if p.get("readable")
    ]

    unreadable_pages = [
        p["page"] for p in sorted_pages
        if not p.get("readable")
    ]

    sw_by_page = {
        p["page"]: p.get("sw")
        for p in sorted_pages
    }

    if readable_pages:
        first_readable = min(readable_pages)
        last_readable = max(readable_pages)
    else:
        first_readable = None
        last_readable = None

    # Expected range if NFC Forum Type 2 Capability Container is present.
    if cc.get("present"):
        expected_start = 0
        expected_end = cc.get("logical_end_page_estimated")
    else:
        expected_start = None
        expected_end = None

    possibly_protected = []
    probably_out_of_range = []
    unsupported_or_unknown = []

    security_status_words = {
        "6982",  # Security status not satisfied
        "6985",  # Conditions of use not satisfied
        "6986",  # Command not allowed
        "6300",  # Operation failed, common on contactless readers
    }

    address_status_words = {
        "6B00",  # Wrong parameters / often invalid page or offset
        "6A82",  # File/page/object not found
        "6A86",  # Incorrect P1/P2
    }

    for page in unreadable_pages:
        sw = sw_by_page.get(page)

        # If the card declares a Type 2 memory range and a page inside
        # that expected range is unreadable, protection is plausible.
        if expected_end is not None and expected_start <= page <= expected_end:
            possibly_protected.append({
                "page": page,
                "sw": sw,
                "reason": "Unreadable page inside expected Type 2 memory range"
            })
            continue

        # If failures are after the last readable page and status suggests
        # invalid address, probably beyond memory.
        if last_readable is not None and page > last_readable and sw in address_status_words:
            probably_out_of_range.append({
                "page": page,
                "sw": sw,
                "reason": "Unreadable page after last readable page; status suggests invalid address/end of memory"
            })
            continue

        # Security-like status words are suspicious for protection.
        if sw in security_status_words:
            possibly_protected.append({
                "page": page,
                "sw": sw,
                "reason": "Status word compatible with failed/protected operation"
            })
            continue

        unsupported_or_unknown.append({
            "page": page,
            "sw": sw,
            "reason": "Cannot classify unreadable page from current evidence"
        })

    # Detect gaps: unreadable pages between readable pages.
    internal_gaps = []
    if readable_pages:
        for page in range(min(readable_pages), max(readable_pages) + 1):
            if page in unreadable_pages:
                internal_gaps.append({
                    "page": page,
                    "sw": sw_by_page.get(page),
                    "reason": "Unreadable page located between readable pages; possible protected/reserved area"
                })

    # Detect repeated status patterns.
    sw_distribution = {}
    for page in unreadable_pages:
        sw = sw_by_page.get(page, "UNKNOWN")
        sw_distribution[sw] = sw_distribution.get(sw, 0) + 1

    interpretation = []

    if cc.get("present"):
        interpretation.append(
            "A Type 2 Capability Container was detected; unreadable pages inside the declared memory range are suspicious for protection or reserved areas."
        )
    else:
        interpretation.append(
            "No Type 2 Capability Container was detected; the card may use another memory model or require a different protocol."
        )

    if internal_gaps:
        interpretation.append(
            "Unreadable pages were found between readable pages; this pattern is more suspicious for protected/reserved areas than simple end-of-memory."
        )

    if possibly_protected:
        interpretation.append(
            "Some pages are compatible with protected or non-accessible areas based on their position/status words."
        )

    if probably_out_of_range:
        interpretation.append(
            "Some unreadable pages are probably outside the valid memory range."
        )

    if not readable_pages:
        interpretation.append(
            "No page was readable with the current FF B0 page-read method; this may indicate a non-Type-2 card, a protected application card, or an unsupported command set."
        )

    return {
        "available": True,
        "first_readable_page": first_readable,
        "last_readable_page": last_readable,
        "readable_page_count": len(readable_pages),
        "unreadable_page_count": len(unreadable_pages),
        "expected_type2_range": {
            "present": cc.get("present", False),
            "start_page": expected_start,
            "end_page": expected_end,
        },
        "status_word_distribution_for_unreadable_pages": sw_distribution,
        "possibly_protected_pages": possibly_protected,
        "probably_out_of_range_pages": probably_out_of_range,
        "internal_unreadable_gaps": internal_gaps,
        "unsupported_or_unknown_pages": unsupported_or_unknown,
        "interpretation": interpretation,
        "forensic_caution": [
            "This is an inference, not a cryptographic proof of protection.",
            "Unreadable does not always mean protected; it may also mean unsupported command, invalid page, end of memory, or different card technology.",
            "Protected areas should not be attacked or bypassed unless there is explicit legal/laboratory authorization.",
            "For forensic reporting, classify these areas as 'not acquired / possibly protected / not accessible with the current method'."
        ]
    }


def build_interpretation_notes(payload, ascii_strings, urls, emails, ndef_tlvs):
    """
    Builds concise forensic interpretation notes.
    """

    notes = []

    card_id = payload.get("card_identification", {})
    uid = card_id.get("uid")
    atr = card_id.get("atr")

    if uid:
        notes.append(f"UID acquired: {uid}")

    if atr:
        notes.append(f"ATR acquired: {atr}")

    cc = payload.get("acquisition", {}).get("type2_capability_container", {})
    if cc.get("present"):
        notes.append("The card appears compatible with an NFC Forum Type 2 / NTAG / MIFARE Ultralight-like memory layout.")
    else:
        notes.append("No standard NFC Forum Type 2 Capability Container was detected at page 3.")

    if ndef_tlvs:
        notes.append("One or more possible NDEF TLV records were found.")
    else:
        notes.append("No NDEF TLV record was automatically detected.")

    if urls:
        notes.append("One or more URLs were found in readable memory.")
    else:
        notes.append("No URL was found in readable memory.")

    if emails:
        notes.append("One or more email addresses were found in readable memory.")
    else:
        notes.append("No email address was found in readable memory.")

    if ascii_strings:
        notes.append("Printable ASCII strings were found and should be reviewed manually.")
    else:
        notes.append("No meaningful printable ASCII strings were found with the current threshold.")

    return notes

def classify_card_from_acquisition(payload):
    """
    Produces a cautious forensic classification based on UID, ATR,
    Type 2 detection and read results.
    """

    card_id = payload.get("card_identification", {})
    acquisition = payload.get("acquisition", {})
    pages = payload.get("pages", {})
    card_profile = payload.get("card_profile") or {}

    uid = card_id.get("uid")
    atr = card_id.get("atr")

    cc = acquisition.get("type2_capability_container", {})
    type2_detected = cc.get("present", False)

    readable_pages = [
        p for p in pages.values()
        if p.get("readable")
    ]

    unreadable_pages = [
        p for p in pages.values()
        if not p.get("readable")
    ]

    sw_distribution = {}
    for p in unreadable_pages:
        sw = p.get("sw", "UNKNOWN")
        sw_distribution[sw] = sw_distribution.get(sw, 0) + 1

    all_unreadable = len(readable_pages) == 0 and len(unreadable_pages) > 0
    all_same_sw = len(sw_distribution) == 1

    classification = {
        "uid_present": uid is not None,
        "atr_present": atr is not None,
        "type2_capability_container_present": type2_detected,
        "readable_page_count": len(readable_pages),
        "unreadable_page_count": len(unreadable_pages),
        "status_word_distribution": sw_distribution,
        "status_word_explanations": {
            sw: explain_status_word(sw)
            for sw in sw_distribution.keys()
        },
        "likely_classification": None,
        "confidence": "low",
        "reasoning": [],
        "recommended_next_steps": [],
    }

    if uid:
        classification["reasoning"].append(
            "The card responds to contactless activation and exposes a UID."
        )

    if atr:
        classification["reasoning"].append(
            "The card is exposed through PC/SC and provides an ATR."
        )

    if card_profile.get("family") == "MIFARE Classic 1K":
        classification["likely_classification"] = "MIFARE Classic 1K"
        classification["confidence"] = "high"
        classification["reasoning"].extend([
            "ATR-based identification indicates MIFARE Classic 1K.",
            "The correct memory model is sector/block-based, not Type-2 page-based.",
            "Type-2 page-read failures are expected and do not imply that the card is empty.",
            "Authenticated MIFARE Classic acquisition is required to read sector data."
        ])
        classification["recommended_next_steps"].extend([
            "Use MIFARE Classic 1K block acquisition with authorized sector keys.",
            "Assess Key A / Key B availability per sector.",
            "Classify sectors not authenticated as protected or not acquired.",
            "Preserve pcsc_scan output as supporting identification evidence."
        ])
        return classification

    if type2_detected:
        classification["likely_classification"] = (
            "Possible NFC Forum Type 2 / NTAG / MIFARE Ultralight-like tag"
        )
        classification["confidence"] = "medium"
        classification["reasoning"].append(
            "A Type 2 Capability Container was detected."
        )

    elif all_unreadable and all_same_sw:
        only_sw = next(iter(sw_distribution.keys()))

        classification["likely_classification"] = (
            "Non-Type-2 or protected/application contactless card"
        )
        classification["confidence"] = "medium"
        classification["reasoning"].append(
            f"No page was readable with Type-2-style FF B0 page reads; all attempts returned SW={only_sw}."
        )
        classification["reasoning"].append(
            "This pattern is more consistent with unsupported memory layout, card-specific protocol, or authentication requirement than with an empty tag."
        )

        classification["recommended_next_steps"].extend([
            "Run pcsc_scan and preserve the complete ATR/card identification output.",
            "Do not classify the card as empty.",
            "Do not attempt write operations on the original card.",
            "If the laboratory provides valid keys or documentation, perform authenticated acquisition only under authorization.",
            "Correlate UID/ATR with external systems, access-control logs, issuer data or inventory records."
        ])

    elif len(readable_pages) > 0:
        classification["likely_classification"] = (
            "Partially readable NFC memory object"
        )
        classification["confidence"] = "medium"
        classification["reasoning"].append(
            "Some pages were readable, but others were not."
        )
        classification["recommended_next_steps"].append(
            "Review internal unreadable gaps and determine whether they are protected, reserved or outside memory."
        )

    else:
        classification["likely_classification"] = (
            "Unknown contactless card type"
        )
        classification["confidence"] = "low"
        classification["reasoning"].append(
            "The available evidence is insufficient to classify the card type."
        )

    return classification
def print_analysis_summary(analysis):
    """
    Prints a concise forensic triage summary.
    """

    summary = analysis["summary"]

    print("\n" + "=" * 78)
    print("NFC FORENSIC TRIAGE SUMMARY")
    print("=" * 78)

    card_id = analysis.get("source_card_identification", {})
    card_profile = analysis.get("card_profile") or {}

    print(f"UID: {card_id.get('uid')}")
    print(f"ATR: {card_id.get('atr')}")
    if card_profile:
        print(f"Card family: {card_profile.get('family')}")
        print(f"Technology: {card_profile.get('technology')}")
        print(f"Recommended acquisition: {card_profile.get('recommended_acquisition')}")
    print(f"Readable pages: {summary['readable_pages']}")
    print(f"Unreadable pages: {summary['unreadable_pages']}")
    print(f"Readable bytes: {summary['readable_bytes']}")
    print(f"SHA256 readable bytes: {summary['sha256_readable_bytes']}")
    print(f"ASCII strings found: {summary['ascii_string_count']}")
    print(f"URLs found: {summary['url_count']}")
    print(f"Emails found: {summary['email_count']}")
    print(f"NDEF TLVs found: {summary['ndef_tlv_count']}")

    if analysis["urls"]:
        print("\n[URL]")
        for url in analysis["urls"]:
            print(f"  - {url}")

    if analysis["emails"]:
        print("\n[EMAIL]")
        for email in analysis["emails"]:
            print(f"  - {email}")

    if analysis["ndef_tlvs"]:
        print("\n[NDEF]")
        for item in analysis["ndef_tlvs"]:
            record = item.get("parsed_record", {})
            decoded_type = record.get("decoded_type")
            decoded_value = record.get("decoded_value")

            print(f"  - Offset {item['offset']}, length {item['length']}")

            if decoded_type:
                print(f"    Type: {decoded_type}")

            if decoded_value:
                print(f"    Value: {decoded_value}")
    protected = analysis.get("protected_area_analysis", {})


    if protected.get("available"):
        print("\n[PROTECTED / UNREADABLE AREA TRIAGE]")
        print(f"First readable page: {protected.get('first_readable_page')}")
        print(f"Last readable page: {protected.get('last_readable_page')}")
        print(f"Unreadable pages: {protected.get('unreadable_page_count')}")

        expected = protected.get("expected_type2_range", {})
        if expected.get("present"):
            print(
                f"Expected Type 2 range: "
                f"{expected.get('start_page')} -> {expected.get('end_page')}"
            )
        else:
            print("Expected Type 2 range: not available")

        sw_distribution = protected.get("status_word_distribution_for_unreadable_pages", {})
        if sw_distribution:
            print("Unreadable SW distribution:")
            for sw, count in sw_distribution.items():
                print(f"  - SW={sw}: {count} page(s)")

        possibly_protected = protected.get("possibly_protected_pages", [])
        if possibly_protected:
            print("\nPossibly protected/non-accessible pages:")
            for item in possibly_protected[:20]:
                print(
                    f"  - Page {item['page']:03d}, SW={item['sw']}: "
                    f"{item['reason']}"
                )

            if len(possibly_protected) > 20:
                print(f"  ... altri {len(possibly_protected) - 20} elementi")

        probably_out_of_range = protected.get("probably_out_of_range_pages", [])
        if probably_out_of_range:
            print("\nProbably out-of-range/end-of-memory pages:")
            for item in probably_out_of_range[:20]:
                print(
                    f"  - Page {item['page']:03d}, SW={item['sw']}: "
                    f"{item['reason']}"
                )

            if len(probably_out_of_range) > 20:
                print(f"  ... altri {len(probably_out_of_range) - 20} elementi")

        internal_gaps = protected.get("internal_unreadable_gaps", [])
        if internal_gaps:
            print("\nInternal unreadable gaps:")
            for item in internal_gaps[:20]:
                print(
                    f"  - Page {item['page']:03d}, SW={item['sw']}: "
                    f"{item['reason']}"
                )

            if len(internal_gaps) > 20:
                print(f"  ... altri {len(internal_gaps) - 20} elementi")


    classification = analysis.get("card_classification", {})

    if classification:
        print("\n[CARD CLASSIFICATION]")
        print(f"Likely classification: {classification.get('likely_classification')}")
        print(f"Confidence: {classification.get('confidence')}")

        print("\nReasoning:")
        for item in classification.get("reasoning", []):
            print(f"  - {item}")

        sw_explanations = classification.get("status_word_explanations", {})
        if sw_explanations:
            print("\nStatus word explanations:")
            for sw, explanation in sw_explanations.items():
                print(f"  - SW={sw}: {explanation}")

        next_steps = classification.get("recommended_next_steps", [])
        if next_steps:
            print("\nRecommended next steps:")
            for step in next_steps:
                print(f"  - {step}")


    print("\n[INTERPRETATION NOTES]")
    for note in analysis["interpretation_notes"]:
        print(f"  - {note}")

    print("=" * 78 + "\n")


def save_analysis_json(filename, analysis):
    """
    Saves analysis JSON and corresponding SHA256 file.
    """

    ensure_parent_dir(filename)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)

    file_hash = sha256_file(filename)

    hash_file = filename + ".sha256"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"{file_hash}  {Path(filename).name}\n")

    print(f"[OK] Analisi salvata in: {filename}")
    print(f"[OK] SHA256 analisi JSON: {file_hash}")
    print(f"[OK] Hash salvato in: {hash_file}")

def save_markdown_report(filename, dump_payload, analysis):
    """
    Saves a concise forensic Markdown report.
    """

    ensure_parent_dir(filename)

    card_id = dump_payload.get("card_identification", {})
    acquisition = dump_payload.get("acquisition", {})
    integrity = dump_payload.get("integrity", {})
    summary = analysis.get("summary", {})
    classification = analysis.get("card_classification", {})
    protected = analysis.get("protected_area_analysis", {})
    card_profile = dump_payload.get("card_profile") or analysis.get("card_profile") or {}

    lines = []

    lines.append("# NFC Forensic Triage Report")
    lines.append("")
    lines.append(f"Generated at: `{now_timestamp()}`")
    lines.append("")
    lines.append("## 1. Card identification")
    lines.append("")
    lines.append(f"- UID: `{card_id.get('uid')}`")
    lines.append(f"- ATR: `{card_id.get('atr')}`")
    lines.append("")
    lines.append("## 1.1 Card family profile")
    lines.append("")
    lines.append(f"- Family: `{card_profile.get('family')}`")
    lines.append(f"- Technology: `{card_profile.get('technology')}`")
    lines.append(f"- Memory model: `{card_profile.get('memory_model')}`")
    lines.append(f"- Recommended acquisition: `{card_profile.get('recommended_acquisition')}`")
    lines.append(f"- Confidence: `{card_profile.get('confidence')}`")
    lines.append("")
    lines.append("")
    lines.append(f"- UID: `{card_id.get('uid')}`")
    lines.append(f"- ATR: `{card_id.get('atr')}`")
    lines.append("")
    lines.append("## 2. Acquisition")
    lines.append("")
    lines.append(f"- Method: `{acquisition.get('method')}`")
    lines.append(f"- Pages in report: `{acquisition.get('summary', {}).get('pages_total_in_report')}`")
    lines.append(f"- Readable pages: `{acquisition.get('summary', {}).get('readable_pages')}`")
    lines.append(f"- Unreadable pages: `{acquisition.get('summary', {}).get('unreadable_pages')}`")
    lines.append(f"- SHA256 readable bytes: `{integrity.get('sha256_readable_bytes')}`")
    lines.append(f"- Readable bytes length: `{integrity.get('readable_bytes_length')}`")
    lines.append("")
    lines.append("## 3. Automated classification")
    lines.append("")
    lines.append(f"- Likely classification: **{classification.get('likely_classification')}**")
    lines.append(f"- Confidence: `{classification.get('confidence')}`")
    lines.append("")
    lines.append("### Reasoning")
    lines.append("")
    for item in classification.get("reasoning", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Status words")
    lines.append("")
    for sw, count in classification.get("status_word_distribution", {}).items():
        explanation = classification.get("status_word_explanations", {}).get(sw)
        lines.append(f"- `SW={sw}`: {count} occurrence(s). {explanation}")
    lines.append("")
    lines.append("## 4. Content triage")
    lines.append("")
    lines.append(f"- Readable bytes: `{summary.get('readable_bytes')}`")
    lines.append(f"- ASCII strings: `{summary.get('ascii_string_count')}`")
    lines.append(f"- URLs: `{summary.get('url_count')}`")
    lines.append(f"- Emails: `{summary.get('email_count')}`")
    lines.append(f"- NDEF TLVs: `{summary.get('ndef_tlv_count')}`")
    lines.append("")
    lines.append("## 5. Protected / unreadable area triage")
    lines.append("")
    lines.append(f"- First readable page: `{protected.get('first_readable_page')}`")
    lines.append(f"- Last readable page: `{protected.get('last_readable_page')}`")
    lines.append(f"- Readable page count: `{protected.get('readable_page_count')}`")
    lines.append(f"- Unreadable page count: `{protected.get('unreadable_page_count')}`")
    lines.append("")
    lines.append("### Interpretation")
    lines.append("")
    for item in protected.get("interpretation", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## 6. Forensic conclusion")
    lines.append("")

    if card_profile.get("family") == "MIFARE Classic 1K":
        lines.append(
            "The card was successfully identified as **MIFARE Classic 1K / ISO 14443 Type A**. "
            "The initial Type-2-style page-read acquisition did not recover user memory, which is expected "
            "because MIFARE Classic uses a sector/block memory model with authentication. "
            "The card must not be classified as empty. Further acquisition requires authorized MIFARE Classic "
            "sector keys and block-level reading."
        )
    else:
        lines.append(
            "The card was successfully identified at UID/ATR level. "
            "No user memory content was acquired using non-authenticated Type-2-style page reads. "
            "The card must not be classified as empty. "
            "The result is compatible with an unsupported memory layout, an application-based contactless card, "
            "or a card requiring authentication/card-specific commands."
        )
    lines.append("")
    lines.append("## 7. Limitations")
    lines.append("")
    for item in analysis.get("forensic_limitations", []):
        lines.append(f"- {item}")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    file_hash = sha256_file(filename)
    hash_file = filename + ".sha256"

    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(f"{file_hash}  {Path(filename).name}\n")

    print(f"[OK] Report Markdown salvato in: {filename}")
    print(f"[OK] SHA256 report Markdown: {file_hash}")
    print(f"[OK] Hash salvato in: {hash_file}")

# =============================================================================
# Full forensic workflow
# =============================================================================

def run_full_acquisition_and_analysis(
    reader_index=None,
    output_dump=None,
    output_analysis=None,
    max_pages=256,
    failure_threshold=8,
    forced_end_page=None,
):
    """
    Full forensic workflow:

    1. Select reader.
    2. Connect to card.
    3. Read UID and ATR.
    4. Acquire complete readable dump.
    5. Save dump.
    6. Analyze dump.
    7. Save analysis.
    """

    reader, conn = connect_reader(reader_index)

    uid = get_uid(conn)
    atr = get_atr(conn)

    print("\n" + "=" * 78)
    print("CARD IDENTIFICATION")
    print("=" * 78)
    print(f"UID: {hx(uid) if uid else 'Not available'}")
    print(f"ATR: {hx(atr) if atr else 'Not available'}")
    print("=" * 78 + "\n")

    card_profile = identify_card_family_from_atr(atr)
    print_card_profile(card_profile)

    pcsc_snapshot = capture_pcsc_scan_snapshot(timeout_seconds=4)

    acquisition = complete_readable_dump(
        conn=conn,
        max_pages=max_pages,
        failure_threshold=failure_threshold,
        forced_end_page=forced_end_page,
    )

    if output_dump is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        uid_part = hx(uid).replace(" ", "") if uid else "unknown_uid"
        output_dump = f"dumps/nfc_dump_{uid_part}_{timestamp}.json"

    dump_payload = save_dump_json(
        filename=output_dump,
        reader=reader,
        uid=uid,
        atr=atr,
        acquisition=acquisition,
        card_profile=card_profile,
        pcsc_scan_snapshot=pcsc_snapshot,
    )

    analysis = analyze_dump_payload(dump_payload)
    print_analysis_summary(analysis)

    if output_analysis is None:
        output_analysis = output_dump.replace(".json", "_analysis.json")

    save_analysis_json(output_analysis, analysis)


    report_output = output_dump.replace(".json", "_report.md")
    save_markdown_report(report_output, dump_payload, analysis)


    return dump_payload, analysis


def run_offline_analysis(input_dump, output_analysis=None):
    """
    Runs analysis on a previously acquired dump.
    Does not connect to the card or reader.
    """

    payload = load_dump_json(input_dump)
    analysis = analyze_dump_payload(payload)
    print_analysis_summary(analysis)

    if output_analysis is None:
        output_analysis = input_dump.replace(".json", "_analysis.json")

    save_analysis_json(output_analysis, analysis)
    report_output = input_dump.replace(".json", "_report.md")
    save_markdown_report(report_output, payload, analysis)


# =============================================================================
# Main CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="NFC forensic acquisition and triage tool for PC/SC readers"
    )

    parser.add_argument(
        "--reader",
        type=int,
        default=None,
        help="Indice del lettore PC/SC. Se assente, viene chiesto interattivamente."
    )

    parser.add_argument(
        "--dump-output",
        default=None,
        help="File JSON dove salvare il dump. Default: dumps/nfc_dump_<UID>_<timestamp>.json"
    )

    parser.add_argument(
        "--analysis-output",
        default=None,
        help="File JSON dove salvare l'analisi. Default: <dump>_analysis.json"
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=256,
        help="Numero massimo di pagine da tentare in modalità sequenziale. Default: 256"
    )

    parser.add_argument(
        "--failure-threshold",
        type=int,
        default=8,
        help="Numero di fallimenti consecutivi dopo cui fermare il dump sequenziale. Default: 8"
    )

    parser.add_argument(
        "--forced-end-page",
        type=int,
        default=None,
        help="Forza il dump da pagina 0 fino a questa pagina."
    )

    parser.add_argument(
        "--analyze-file",
        metavar="FILE.json",
        help="Analizza un dump JSON già acquisito, senza collegarsi al lettore."
    )

    parser.add_argument(
        "--uid-only",
        action="store_true",
        help="Legge solo UID e ATR, senza eseguire dump."
    )
    parser.add_argument(
        "--mfc-create-key-template",
        metavar="FILE.json",
        help="Crea un template JSON per chiavi MIFARE Classic autorizzate e termina."
    )

    parser.add_argument(
        "--mfc-dump-1k",
        action="store_true",
        help="Esegue acquisizione MIFARE Classic 1K usando chiavi già disponibili/autorizzate."
    )

    parser.add_argument(
        "--mfc-keyfile",
        metavar="FILE.json",
        help="File JSON con chiavi MIFARE Classic già disponibili/autorizzate."
    )

    parser.add_argument(
        "--mfc-key",
        help="Singola chiave MIFARE Classic autorizzata, 6 byte HEX. Esempio: FFFFFFFFFFFF"
    )

    parser.add_argument(
        "--mfc-key-type",
        choices=["A", "B"],
        default="A",
        help="Tipo della singola chiave MIFARE Classic fornita con --mfc-key. Default: A"
    )

    parser.add_argument(
        "--mfc-output",
        default=None,
        help="File JSON dove salvare il dump MIFARE Classic."
    )

    parser.add_argument(
        "--mfc-analysis-output",
        default=None,
        help="File JSON dove salvare l'analisi MIFARE Classic."
    )

    parser.add_argument(
        "--mfc-report-output",
        default=None,
        help="File Markdown dove salvare il report MIFARE Classic."
    )

    args = parser.parse_args()

    # Create MIFARE key template and exit.
    if args.mfc_create_key_template:
        save_mfc_key_template(args.mfc_create_key_template)
        return

    # Offline analysis mode: no reader/card access.
    if args.analyze_file:
        run_offline_analysis(
            input_dump=args.analyze_file,
            output_analysis=args.analysis_output
        )
        return


    # UID-only mode.
    if args.uid_only:
        reader, conn = connect_reader(args.reader)
        uid = get_uid(conn)
        atr = get_atr(conn)
        card_profile = identify_card_family_from_atr(atr)

        print("\n" + "=" * 78)
        print("CARD IDENTIFICATION")
        print("=" * 78)
        print(f"Reader: {reader}")
        print(f"UID: {hx(uid) if uid else 'Not available'}")
        print(f"ATR: {hx(atr) if atr else 'Not available'}")
        print("=" * 78 + "\n")

        print_card_profile(card_profile)
        return

    # MIFARE Classic 1K authorized acquisition mode.
    if args.mfc_dump_1k:
        run_mfc_authorized_acquisition(
            reader_index=args.reader,
            keyfile=args.mfc_keyfile,
            single_key=args.mfc_key,
            single_key_type=args.mfc_key_type,
            output_dump=args.mfc_output,
            output_analysis=args.mfc_analysis_output,
            output_report=args.mfc_report_output,
        )
        return

    # Default mode:
    # full acquisition first, then analysis.
    run_full_acquisition_and_analysis(
        reader_index=args.reader,
        output_dump=args.dump_output,
        output_analysis=args.analysis_output,
        max_pages=args.max_pages,
        failure_threshold=args.failure_threshold,
        forced_end_page=args.forced_end_page,
    )


if __name__ == "__main__":
    main()
