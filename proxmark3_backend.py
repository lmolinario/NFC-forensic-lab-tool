#!/usr/bin/env python3
"""Read-only Proxmark3 acquisition backend for forensic laboratory triage.

The module intentionally exposes only predefined, non-destructive command
profiles. It does not accept arbitrary Proxmark3 commands and does not perform
key recovery, brute force, nested/hardnested attacks, simulation, cloning, or
writes to a card/tag.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence


SAFE_COMMAND_PROFILES: dict[str, tuple[str, ...]] = {
    "identify": ("hw version", "hw status", "hf search", "lf search"),
    "hf": ("hw version", "hw status", "hf search"),
    "lf": ("hw version", "hw status", "lf search"),
    "hardware": ("hw version", "hw status", "hw tune"),
}

DENIED_TOKENS = {
    "autopwn",
    "brute",
    "clone",
    "darkside",
    "hardnested",
    "nested",
    "restore",
    "setuid",
    "sim",
    "sniff",
    "wipe",
    "write",
    "wrbl",
}

COMMON_CLIENT_PATHS = (
    "/usr/local/bin/proxmark3",
    "/usr/bin/proxmark3",
    "./client/proxmark3",
    "./proxmark3/client/proxmark3",
)

PORT_PATTERNS = (
    "/dev/serial/by-id/*Proxmark*",
    "/dev/serial/by-id/*proxmark*",
    "/dev/ttyACM*",
    "/dev/ttyUSB*",
)


@dataclass(frozen=True)
class CommandResult:
    command: str
    argv: list[str]
    started_at: str
    finished_at: str
    returncode: int | None
    timed_out: bool
    stdout: str


class ProxmarkBackendError(RuntimeError):
    """Raised for deterministic backend configuration or execution failures."""


def now_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_case_id(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    normalized = normalized.strip("._-")
    if not normalized:
        raise ProxmarkBackendError("Il case ID non contiene caratteri utilizzabili.")
    return normalized[:100]


def validate_read_only_commands(commands: Iterable[str]) -> tuple[str, ...]:
    validated: list[str] = []
    for command in commands:
        normalized = " ".join(command.strip().lower().split())
        tokens = set(re.findall(r"[a-z0-9_-]+", normalized))
        denied = sorted(tokens.intersection(DENIED_TOKENS))
        if denied:
            raise ProxmarkBackendError(
                f"Comando non consentito dal profilo read-only: {command!r}; "
                f"token vietati: {', '.join(denied)}"
            )
        validated.append(" ".join(command.strip().split()))
    return tuple(validated)


def resolve_client(explicit: str | None = None) -> Path:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.getenv("PM3_CLIENT"):
        candidates.append(os.environ["PM3_CLIENT"])

    discovered = shutil.which("proxmark3")
    if discovered:
        candidates.append(discovered)
    candidates.extend(COMMON_CLIENT_PATHS)

    checked: list[str] = []
    for candidate in candidates:
        expanded = Path(candidate).expanduser()
        checked.append(str(expanded))
        if expanded.is_file() and os.access(expanded, os.X_OK):
            return expanded.resolve()

    raise ProxmarkBackendError(
        "Client Proxmark3 non trovato o non eseguibile. "
        "Usa --client oppure imposta PM3_CLIENT. Percorsi controllati: "
        + ", ".join(checked)
    )


def discover_ports() -> list[Path]:
    discovered: list[Path] = []
    seen: set[str] = set()

    for pattern in PORT_PATTERNS:
        for raw_path in sorted(glob.glob(pattern)):
            path = Path(raw_path)
            try:
                canonical = str(path.resolve())
            except OSError:
                canonical = str(path)
            if canonical in seen:
                continue
            if path.exists():
                seen.add(canonical)
                discovered.append(path)

    return discovered


def resolve_port(explicit: str | None = None) -> Path:
    selected = explicit or os.getenv("PM3_PORT")
    if selected:
        path = Path(selected).expanduser()
        if not path.exists():
            raise ProxmarkBackendError(f"Porta Proxmark3 non trovata: {path}")
        return path

    ports = discover_ports()
    if not ports:
        raise ProxmarkBackendError(
            "Nessuna porta seriale Proxmark3 rilevata. "
            "Collega il dispositivo e usa --port /dev/ttyACM0."
        )
    if len(ports) > 1:
        rendered = ", ".join(str(port) for port in ports)
        raise ProxmarkBackendError(
            "Più porte seriali compatibili rilevate; specifica --port per evitare "
            f"ambiguità forense: {rendered}"
        )
    return ports[0]


def run_command(
    client: Path,
    port: Path,
    command: str,
    timeout_seconds: int,
) -> CommandResult:
    argv = [str(client), str(port), "-c", command]
    started_at = now_timestamp()
    env = {**os.environ, "TERM": "dumb", "NO_COLOR": "1"}

    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
        return CommandResult(
            command=command,
            argv=argv,
            started_at=started_at,
            finished_at=now_timestamp(),
            returncode=completed.returncode,
            timed_out=False,
            stdout=completed.stdout or "",
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return CommandResult(
            command=command,
            argv=argv,
            started_at=started_at,
            finished_at=now_timestamp(),
            returncode=None,
            timed_out=True,
            stdout=output,
        )


def parse_pm3_identification(output: str) -> dict[str, object]:
    compact_output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)

    uid_patterns = (
        r"(?im)^\s*UID\s*[:=]\s*([0-9A-F][0-9A-F :.-]{5,})\s*$",
        r"(?im)^\s*Card UID\s*[:=]\s*([0-9A-F][0-9A-F :.-]{5,})\s*$",
    )
    uid = None
    for pattern in uid_patterns:
        match = re.search(pattern, compact_output)
        if match:
            pairs = re.findall(r"[0-9A-Fa-f]{2}", match.group(1))
            if pairs:
                uid = " ".join(pair.upper() for pair in pairs)
                break

    upper = compact_output.upper()
    family_candidates = (
        ("MIFARE DESFIRE", "MIFARE DESFire"),
        ("MIFARE CLASSIC", "MIFARE Classic"),
        ("MIFARE ULTRALIGHT", "MIFARE Ultralight"),
        ("NTAG", "NTAG / NFC Forum Type 2"),
        ("ISO15693", "ISO 15693"),
        ("ISO 15693", "ISO 15693"),
        ("EM 410", "EM410x"),
        ("EM410", "EM410x"),
        ("HID PROX", "HID Prox"),
        ("FELICA", "FeliCa"),
    )

    families: list[str] = []
    for marker, label in family_candidates:
        if marker in upper and label not in families:
            families.append(label)

    technologies: list[str] = []
    if any(marker in upper for marker in ("13.56", "ISO14443", "ISO 14443", "ISO15693", "ISO 15693", "MIFARE", "NTAG", "FELICA")):
        technologies.append("HF / NFC 13.56 MHz")
    if any(marker in upper for marker in ("125 KHZ", "134 KHZ", "EM410", "HID PROX", "T55")):
        technologies.append("LF 125/134 kHz")

    return {
        "uid": uid,
        "families_detected": families,
        "technologies_detected": technologies,
        "classification_confidence": "medium" if families or uid else "low",
        "interpretation_caution": (
            "Automated parsing of Proxmark3 console output is a triage aid and "
            "must be verified against the preserved transcript."
        ),
    }


def render_transcript(
    case_id: str,
    mode: str,
    client: Path,
    port: Path,
    results: Sequence[CommandResult],
) -> str:
    lines = [
        "PROXMARK3 READ-ONLY FORENSIC TRANSCRIPT",
        "=" * 78,
        f"Case ID: {case_id}",
        f"Created at: {now_timestamp()}",
        f"Mode: {mode}",
        f"Client: {client}",
        f"Port: {port}",
        "Safety profile: predefined read-only commands only",
        "=" * 78,
        "",
    ]

    for index, result in enumerate(results, start=1):
        lines.extend(
            [
                f"COMMAND {index}: {result.command}",
                "-" * 78,
                f"ARGV: {json.dumps(result.argv, ensure_ascii=False)}",
                f"Started at: {result.started_at}",
                f"Finished at: {result.finished_at}",
                f"Return code: {result.returncode}",
                f"Timed out: {result.timed_out}",
                "",
                result.stdout.rstrip(),
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def write_hash_sidecar(path: Path) -> str:
    digest = sha256_file(path)
    sidecar = Path(f"{path}.sha256")
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def acquire(
    *,
    mode: str,
    case_id: str,
    output_dir: Path,
    client: Path,
    port: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    commands = validate_read_only_commands(SAFE_COMMAND_PROFILES[mode])
    results = [
        run_command(client, port, command, timeout_seconds)
        for command in commands
    ]

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"pm3_{safe_case_id(case_id)}_{mode}_{timestamp}"
    transcript_path = output_dir / f"{stem}.log"
    json_path = output_dir / f"{stem}.json"

    transcript = render_transcript(case_id, mode, client, port, results)
    transcript_path.write_text(transcript, encoding="utf-8")
    transcript_hash = write_hash_sidecar(transcript_path)

    combined_output = "\n".join(result.stdout for result in results)
    identification = parse_pm3_identification(combined_output)

    payload: dict[str, object] = {
        "case_metadata": {
            "case_id": case_id,
            "created_at": now_timestamp(),
            "tool": "proxmark3_backend.py",
            "tool_mode": "read_only_proxmark3_triage",
        },
        "device": {
            "client": str(client),
            "port": str(port),
        },
        "safety": {
            "profile": mode,
            "commands_are_predefined": True,
            "arbitrary_commands_supported": False,
            "write_clone_attack_commands_supported": False,
        },
        "commands": [asdict(result) for result in results],
        "identification": identification,
        "integrity": {
            "transcript_file": transcript_path.name,
            "sha256_transcript": transcript_hash,
        },
        "limitations": [
            "This phase records read-only identification and hardware triage only.",
            "No memory dump, authentication bypass, key recovery, cloning or write operation is performed.",
            "Console-output parsing is heuristic; the original transcript is the primary record.",
            "UID alone is not sufficient for attribution and requires external correlation.",
        ],
    }

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    json_hash = write_hash_sidecar(json_path)

    return {
        "transcript": str(transcript_path),
        "transcript_sha256": transcript_hash,
        "json": str(json_path),
        "json_sha256": json_hash,
        "identification": identification,
        "command_failures": [
            result.command
            for result in results
            if result.timed_out or result.returncode not in (0, None)
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Backend Proxmark3 read-only per identificazione e triage forense "
            "di laboratorio."
        )
    )
    parser.add_argument(
        "--mode",
        choices=sorted(SAFE_COMMAND_PROFILES),
        default="identify",
        help="Profilo di comandi read-only da eseguire.",
    )
    parser.add_argument("--case-id", default="LAB", help="Identificativo del caso/laboratorio.")
    parser.add_argument("--client", help="Percorso del client proxmark3.")
    parser.add_argument("--port", help="Porta seriale, ad esempio /dev/ttyACM0.")
    parser.add_argument(
        "--output-dir",
        default="dumps/proxmark3",
        help="Directory per transcript, JSON e hash SHA256.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="Timeout massimo per ogni comando, in secondi.",
    )
    parser.add_argument(
        "--list-ports",
        action="store_true",
        help="Elenca le porte seriali candidate senza eseguire acquisizioni.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra client, porta e comandi senza eseguirli.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout < 1 or args.timeout > 600:
        parser.error("--timeout deve essere compreso tra 1 e 600 secondi.")

    if args.list_ports:
        ports = discover_ports()
        if not ports:
            print("Nessuna porta candidata rilevata.")
            return 1
        for port in ports:
            print(port)
        return 0

    try:
        client = resolve_client(args.client)
        port = resolve_port(args.port)
        commands = validate_read_only_commands(SAFE_COMMAND_PROFILES[args.mode])

        if args.dry_run:
            print(f"Client: {client}")
            print(f"Port: {port}")
            print(f"Mode: {args.mode}")
            for command in commands:
                print(f"  - {command}")
            return 0

        result = acquire(
            mode=args.mode,
            case_id=args.case_id,
            output_dir=Path(args.output_dir),
            client=client,
            port=port,
            timeout_seconds=args.timeout,
        )
    except ProxmarkBackendError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[ERROR] Errore di sistema: {exc}", file=sys.stderr)
        return 3

    print("[OK] Acquisizione Proxmark3 read-only completata.")
    print(f"Transcript: {result['transcript']}")
    print(f"SHA256 transcript: {result['transcript_sha256']}")
    print(f"JSON: {result['json']}")
    print(f"SHA256 JSON: {result['json_sha256']}")
    print("Identificazione:")
    print(json.dumps(result["identification"], indent=2, ensure_ascii=False))

    failures = result["command_failures"]
    if failures:
        print(f"[WARN] Comandi con errore/timeout: {', '.join(failures)}")
        return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
