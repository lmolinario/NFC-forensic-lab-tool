#!/usr/bin/env python3
"""Read-only Proxmark3 acquisition backend for forensic laboratory triage.

The module executes a strict allowlist of non-destructive Iceman client
commands, preserves the raw transcript, and generates integrity hashes and a
machine-readable manifest. It intentionally excludes write, clone, simulation,
key-recovery, brute-force, sniffing, and authentication-bypass operations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


READ_ONLY_COMMANDS = frozenset(
    {
        "hw version",
        "hw status",
        "hw tune",
        "hf search",
        "hf 14a info",
        "hf mf info",
        "hf mfu info",
        "hf mfu ndefread",
        "hf 15 info",
        "hf felica info",
        "lf search",
    }
)

PROFILE_COMMANDS = {
    "hardware": ("hw version", "hw status", "hw tune"),
    "hf": ("hw version", "hw status", "hf search"),
    "lf": ("hw version", "hw status", "lf search"),
    "both": ("hw version", "hw status", "hf search", "lf search"),
}

DENIED_TOKENS = frozenset(
    {
        "write",
        "wrbl",
        "wipe",
        "restore",
        "clone",
        "sim",
        "brute",
        "autopwn",
        "nested",
        "hardnested",
        "setuid",
        "sniff",
        "snoop",
        "attack",
        "crack",
        "recover",
        "eload",
    }
)

ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
UID_PATTERNS = (
    re.compile(r"\bUID\s*:\s*([0-9A-Fa-f][0-9A-Fa-f](?:[ :\-]?[0-9A-Fa-f]{2}){3,9})"),
    re.compile(r"\bUID\s+([0-9A-Fa-f][0-9A-Fa-f](?:[ :\-]?[0-9A-Fa-f]{2}){3,9})"),
)
FIELD_PATTERNS = {
    "atqa": re.compile(r"\bATQA\s*:\s*([0-9A-Fa-f ]{4,})"),
    "sak": re.compile(r"\bSAK\s*:\s*([0-9A-Fa-f]{2})"),
    "ats": re.compile(r"\bATS\s*:\s*([0-9A-Fa-f ]{2,})"),
}


class Proxmark3Error(RuntimeError):
    """Base exception for Proxmark3 backend errors."""


class UnsafeCommandError(Proxmark3Error):
    """Raised when a command falls outside the read-only allowlist."""


@dataclass(frozen=True)
class AcquisitionResult:
    created_at_utc: str
    client: str
    port: str
    commands: list[str]
    return_code: int
    success: bool
    transcript_file: str
    transcript_sha256: str
    manifest_file: str
    parsed_identification: dict[str, str | None]


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_command(command: str) -> str:
    return " ".join(command.strip().lower().split())


def validate_read_only_commands(commands: Iterable[str]) -> list[str]:
    validated: list[str] = []

    for original in commands:
        command = normalize_command(original)
        if not command:
            raise UnsafeCommandError("Empty Proxmark3 command is not allowed.")

        words = set(re.findall(r"[a-z0-9_]+", command))
        denied = sorted(words.intersection(DENIED_TOKENS))
        if denied:
            raise UnsafeCommandError(
                f"Command '{original}' contains denied token(s): {', '.join(denied)}"
            )

        if command not in READ_ONLY_COMMANDS:
            raise UnsafeCommandError(
                f"Command '{original}' is not in the strict read-only allowlist."
            )

        validated.append(command)

    if not validated:
        raise UnsafeCommandError("At least one read-only command is required.")

    return validated


def discover_ports() -> list[str]:
    candidates: list[Path] = []
    for pattern in ("/dev/serial/by-id/*", "/dev/ttyACM*", "/dev/ttyUSB*"):
        candidates.extend(Path("/").glob(pattern.lstrip("/")))

    ports: list[str] = []
    seen: set[str] = set()
    for candidate in sorted(candidates, key=lambda item: str(item)):
        path = str(candidate)
        if path not in seen:
            seen.add(path)
            ports.append(path)
    return ports


def resolve_port(explicit_port: str | None) -> str:
    if explicit_port:
        port = Path(explicit_port)
        if not port.exists():
            raise Proxmark3Error(f"Proxmark3 serial port does not exist: {explicit_port}")
        return explicit_port

    ports = discover_ports()
    if not ports:
        raise Proxmark3Error(
            "No candidate Proxmark3 serial port found. Specify --port explicitly."
        )
    if len(ports) > 1:
        rendered = ", ".join(ports)
        raise Proxmark3Error(
            f"Multiple serial ports found ({rendered}). Specify --port explicitly."
        )
    return ports[0]


def resolve_client(explicit_client: str | None) -> str:
    candidates = [
        explicit_client,
        os.getenv("PM3_CLIENT"),
        shutil.which("proxmark3"),
        "/usr/local/bin/proxmark3",
        "/usr/bin/proxmark3",
    ]

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)

    raise Proxmark3Error(
        "Proxmark3 client not found. Set PM3_CLIENT or pass --client."
    )


def strip_ansi(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value)


def normalize_hex(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if len(compact) % 2:
        return compact
    return " ".join(compact[index : index + 2] for index in range(0, len(compact), 2))


def parse_identification(transcript: str) -> dict[str, str | None]:
    clean = strip_ansi(transcript)
    result: dict[str, str | None] = {
        "uid": None,
        "atqa": None,
        "sak": None,
        "ats": None,
        "technology_hint": None,
    }

    for pattern in UID_PATTERNS:
        match = pattern.search(clean)
        if match:
            result["uid"] = normalize_hex(match.group(1))
            break

    for field, pattern in FIELD_PATTERNS.items():
        match = pattern.search(clean)
        if match:
            result[field] = normalize_hex(match.group(1))

    lower = clean.lower()
    technology_hints = (
        ("mifare classic", "MIFARE Classic / ISO 14443-A"),
        ("mifare ultralight", "MIFARE Ultralight / ISO 14443-A"),
        ("ntag", "NTAG / NFC Forum Type 2"),
        ("desfire", "MIFARE DESFire / ISO 14443-A"),
        ("iso15693", "ISO 15693 / NFC-V"),
        ("felica", "FeliCa / NFC-F"),
        ("em 410", "EM410x / LF"),
        ("hid prox", "HID Prox / LF"),
    )
    for marker, description in technology_hints:
        if marker in lower:
            result["technology_hint"] = description
            break

    return result


def build_transcript_header(client: str, port: str, commands: Sequence[str]) -> str:
    command_lines = "\n".join(f"- {command}" for command in commands)
    return (
        "NFC Forensic Lab Tool - Proxmark3 read-only transcript\n"
        f"Created at (UTC): {utc_timestamp()}\n"
        f"Client: {client}\n"
        f"Port: {port}\n"
        "Commands:\n"
        f"{command_lines}\n"
        "Safety profile: strict read-only allowlist; no write, clone, simulation, "
        "key recovery, brute force, sniffing, or authentication bypass.\n"
        "=" * 78
        + "\n"
    )


def run_read_only_acquisition(
    *,
    port: str | None = None,
    client: str | None = None,
    commands: Sequence[str] | None = None,
    profile: str = "both",
    output_dir: Path | str = Path("dumps/proxmark3"),
    timeout: int = 90,
) -> AcquisitionResult:
    if commands is None:
        try:
            commands = PROFILE_COMMANDS[profile]
        except KeyError as exc:
            raise Proxmark3Error(f"Unknown acquisition profile: {profile}") from exc

    validated_commands = validate_read_only_commands(commands)
    resolved_client = resolve_client(client)
    resolved_port = resolve_port(port)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    transcript_path = output_path / f"pm3_readonly_{timestamp}.txt"
    manifest_path = output_path / f"pm3_readonly_{timestamp}.json"

    command_string = "; ".join(validated_commands)
    process = subprocess.run(
        [resolved_client, resolved_port, "-c", command_string],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env={**os.environ, "TERM": "dumb"},
    )

    header = build_transcript_header(resolved_client, resolved_port, validated_commands)
    transcript_path.write_text(header + process.stdout, encoding="utf-8")
    transcript_hash = sha256_file(transcript_path)
    transcript_hash_path = transcript_path.with_suffix(transcript_path.suffix + ".sha256")
    transcript_hash_path.write_text(
        f"{transcript_hash}  {transcript_path.name}\n", encoding="utf-8"
    )

    parsed = parse_identification(process.stdout)
    created_at = utc_timestamp()
    result = AcquisitionResult(
        created_at_utc=created_at,
        client=resolved_client,
        port=resolved_port,
        commands=validated_commands,
        return_code=process.returncode,
        success=process.returncode == 0,
        transcript_file=str(transcript_path),
        transcript_sha256=transcript_hash,
        manifest_file=str(manifest_path),
        parsed_identification=parsed,
    )

    manifest = asdict(result)
    manifest["forensic_notes"] = [
        "The raw Proxmark3 client transcript is preserved as the primary native output.",
        "Parsed fields are automated triage hints and require manual verification.",
        "The backend executes only commands in a strict non-destructive allowlist.",
        "No write, clone, simulation, key recovery, brute force, sniffing, or authentication bypass command is available.",
    ]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest_hash = sha256_file(manifest_path)
    manifest_path.with_suffix(manifest_path.suffix + ".sha256").write_text(
        f"{manifest_hash}  {manifest_path.name}\n", encoding="utf-8"
    )

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Proxmark3 forensic identification backend."
    )
    parser.add_argument("--port", help="Serial port, e.g. /dev/ttyACM0")
    parser.add_argument("--client", help="Path to the proxmark3 executable")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_COMMANDS),
        default="both",
        help="Strict read-only command profile",
    )
    parser.add_argument(
        "--output-dir",
        default="dumps/proxmark3",
        help="Directory for transcript, manifest and SHA256 files",
    )
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument(
        "--list-ports",
        action="store_true",
        help="List candidate serial ports without acquiring a card/tag",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_ports:
        ports = discover_ports()
        if not ports:
            print("No candidate serial ports found.")
            return 1
        for port in ports:
            print(port)
        return 0

    try:
        result = run_read_only_acquisition(
            port=args.port,
            client=args.client,
            profile=args.profile,
            output_dir=args.output_dir,
            timeout=args.timeout,
        )
    except (Proxmark3Error, subprocess.TimeoutExpired) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))
    return 0 if result.success else 3


if __name__ == "__main__":
    raise SystemExit(main())
