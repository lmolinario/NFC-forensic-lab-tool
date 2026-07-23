#!/usr/bin/env python3
"""Guarded active-laboratory operations for Proxmark3.

This module is intentionally narrower than the full Proxmark3 command set. It
supports controlled vulnerability assessment and reversible/user-memory writes
on owned or explicitly authorized test tags. It does not expose arbitrary
commands and does not implement key recovery, nested/hardnested attacks,
autopwn, cloning, simulation, UID rewriting, sector-trailer writes, lock-byte
writes, or manufacturer-block writes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from typing import Sequence

from proxmark3_backend import (
    CommandResult,
    ProxmarkBackendError,
    now_timestamp,
    parse_pm3_identification,
    resolve_client,
    resolve_port,
    run_command,
    safe_case_id,
    write_hash_sidecar,
)


AUTHORIZATION_PHRASE = "I-OWN-OR-AM-AUTHORIZED"
ACTIVE_OPERATIONS = {
    "assess",
    "ntag-write-page",
    "ntag-writable-probe",
    "mfc-write-block",
    "mfc-writable-probe",
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class ActiveLabError(ProxmarkBackendError):
    """Raised when an active operation fails a safety or validation check."""


def normalize_hex(value: str, expected_bytes: int, label: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    expected_length = expected_bytes * 2
    if len(cleaned) != expected_length:
        raise ActiveLabError(
            f"{label} deve contenere esattamente {expected_bytes} byte "
            f"({expected_length} caratteri HEX)."
        )
    try:
        bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ActiveLabError(f"{label} non è HEX valido.") from exc
    return cleaned


def normalize_uid(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(cleaned) not in {8, 14, 20}:
        raise ActiveLabError("L'UID atteso deve essere di 4, 7 oppure 10 byte.")
    return cleaned


def format_uid(compact_uid: str) -> str:
    return " ".join(compact_uid[index:index + 2] for index in range(0, len(compact_uid), 2))


def contains_hex(output: str, compact_hex: str) -> bool:
    pairs = [compact_hex[index:index + 2] for index in range(0, len(compact_hex), 2)]
    pattern = r"(?i)(?<![0-9a-f])" + r"[\s:._-]*".join(pairs) + r"(?![0-9a-f])"
    return re.search(pattern, ANSI_RE.sub("", output)) is not None


def redact_text(value: str, secrets: Sequence[str]) -> str:
    redacted = value
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        compact = re.sub(r"[^0-9A-Fa-f]", "", secret).upper()
        variants = {secret, secret.upper(), compact}
        if compact and len(compact) % 2 == 0:
            variants.add(" ".join(compact[index:index + 2] for index in range(0, len(compact), 2)))
        for variant in sorted(variants, key=len, reverse=True):
            redacted = re.sub(re.escape(variant), "<REDACTED>", redacted, flags=re.IGNORECASE)
    return redacted


def redact_result(result: CommandResult, secrets: Sequence[str]) -> CommandResult:
    return replace(
        result,
        command=redact_text(result.command, secrets),
        argv=[redact_text(item, secrets) for item in result.argv],
        stdout=redact_text(result.stdout, secrets),
    )


def ensure_success(result: CommandResult, label: str) -> None:
    if result.timed_out:
        raise ActiveLabError(f"Timeout durante {label}.")
    if result.returncode != 0:
        raise ActiveLabError(
            f"Il client Proxmark3 ha restituito codice {result.returncode} durante {label}."
        )


def verify_expected_uid(output: str, expected_uid: str) -> dict[str, object]:
    identification = parse_pm3_identification(output)
    detected = identification.get("uid")
    if not detected:
        raise ActiveLabError(
            "UID non rilevato. Operazione attiva interrotta per evitare di agire sul tag sbagliato."
        )
    detected_compact = normalize_uid(str(detected))
    if detected_compact != expected_uid:
        raise ActiveLabError(
            "UID diverso da quello autorizzato: "
            f"atteso {format_uid(expected_uid)}, rilevato {format_uid(detected_compact)}."
        )
    return identification


def validate_ntag_page(page: int) -> None:
    # Pages 0-3 contain UID/manufacturer/lock/OTP information. Pages above 39
    # can include dynamic locks, configuration, passwords or model-specific data.
    if page < 4 or page > 39:
        raise ActiveLabError(
            "Per sicurezza sono consentite solo le pagine utente NTAG/Ultralight 4-39. "
            "Pagine UID, lock, OTP, password e configurazione restano escluse."
        )


def validate_mfc_data_block(block: int) -> None:
    if block < 1 or block > 63:
        raise ActiveLabError("Il blocco MIFARE Classic deve essere compreso tra 1 e 63.")
    if block % 4 == 3:
        raise ActiveLabError(
            "I sector trailer non sono scrivibili da questo modulo perché contengono chiavi e access bits."
        )


def ntag_read_command(page: int, password: str | None) -> str:
    command = f"hf mfu rdbl -b {page}"
    if password:
        command += f" -k {password}"
    return command


def ntag_write_command(page: int, data: str, password: str | None) -> str:
    command = f"hf mfu wrbl -b {page} -d {data}"
    if password:
        command += f" -k {password}"
    return command


def mfc_read_command(block: int, key: str, key_type: str) -> str:
    key_flag = "-a" if key_type == "A" else "-b"
    return f"hf mf rdbl --blk {block} {key_flag} -k {key}"


def mfc_write_command(block: int, key: str, key_type: str, data: str) -> str:
    key_flag = "-a" if key_type == "A" else "-b"
    return f"hf mf wrbl --blk {block} {key_flag} -k {key} -d {data}"


def assess_indicators(output: str) -> dict[str, object]:
    clean = ANSI_RE.sub("", output)
    upper = clean.upper()

    indicators: list[dict[str, str]] = []
    checks = (
        ("MAGIC", "possible_magic_or_uid_changeable_tag", "high"),
        ("DEFAULT KEY", "default_key_reference_detected", "medium"),
        ("WEAK PRNG", "weak_prng_indicator", "high"),
        ("STATIC NONCE", "static_nonce_indicator", "high"),
        ("BACKDOOR", "backdoor_indicator", "high"),
        ("WRITEABLE", "writable_indicator", "medium"),
        ("WRITABLE", "writable_indicator", "medium"),
    )
    seen: set[str] = set()
    for marker, finding, severity in checks:
        if marker in upper and finding not in seen:
            seen.add(finding)
            indicators.append({"finding": finding, "severity": severity, "marker": marker})

    identification = parse_pm3_identification(clean)
    if identification.get("uid"):
        indicators.append(
            {
                "finding": "static_identifier_exposed",
                "severity": "informational",
                "marker": "UID",
            }
        )

    return {
        "identification": identification,
        "indicators": indicators,
        "assessment_scope": (
            "Passive identification and console-output indicators only; no key recovery, "
            "authentication bypass, cloning or simulation was attempted."
        ),
    }


def render_active_transcript(
    *,
    case_id: str,
    operation: str,
    client: Path,
    port: Path,
    expected_uid: str,
    results: Sequence[CommandResult],
    outcome: dict[str, object],
) -> str:
    lines = [
        "PROXMARK3 GUARDED ACTIVE-LAB TRANSCRIPT",
        "=" * 78,
        f"Case ID: {case_id}",
        f"Created at: {now_timestamp()}",
        f"Operation: {operation}",
        f"Client: {client}",
        f"Port: {port}",
        f"Authorized target UID: {format_uid(expected_uid)}",
        "Authorization attestation supplied: yes",
        "Arbitrary Proxmark3 commands: disabled",
        "Key recovery / cloning / simulation / UID rewriting: disabled",
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

    lines.extend(
        [
            "OUTCOME",
            "-" * 78,
            json.dumps(outcome, indent=2, ensure_ascii=False),
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def run_identification(client: Path, port: Path, timeout: int, expected_uid: str) -> tuple[CommandResult, dict[str, object]]:
    result = run_command(client, port, "hf 14a info", timeout)
    ensure_success(result, "identificazione UID")
    identification = verify_expected_uid(result.stdout, expected_uid)
    return result, identification


def execute_assessment(
    client: Path,
    port: Path,
    timeout: int,
    expected_uid: str,
) -> tuple[list[CommandResult], dict[str, object]]:
    identify_result, identification = run_identification(client, port, timeout, expected_uid)
    commands = ("hf search", "hf mf info", "hf mfu info")
    results = [identify_result]
    for command in commands:
        results.append(run_command(client, port, command, timeout))

    combined = "\n".join(result.stdout for result in results)
    assessment = assess_indicators(combined)
    assessment["identification"] = identification
    assessment["command_status"] = [
        {
            "command": result.command,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
        }
        for result in results
    ]
    return results, assessment


def execute_ntag_operation(
    *,
    client: Path,
    port: Path,
    timeout: int,
    expected_uid: str,
    page: int,
    expected_before: str,
    new_data: str,
    password: str | None,
    reversible_probe: bool,
) -> tuple[list[CommandResult], dict[str, object]]:
    validate_ntag_page(page)
    results: list[CommandResult] = []
    identify_result, identification = run_identification(client, port, timeout, expected_uid)
    results.append(identify_result)

    before = run_command(client, port, ntag_read_command(page, password), timeout)
    results.append(before)
    ensure_success(before, "lettura iniziale pagina NTAG")
    if not contains_hex(before.stdout, expected_before):
        raise ActiveLabError(
            "Il contenuto attuale della pagina non coincide con --expected-before. "
            "Scrittura interrotta per evitare sovrascritture accidentali."
        )

    write_result = run_command(client, port, ntag_write_command(page, new_data, password), timeout)
    results.append(write_result)
    ensure_success(write_result, "scrittura pagina NTAG")

    after_write = run_command(client, port, ntag_read_command(page, password), timeout)
    results.append(after_write)
    ensure_success(after_write, "verifica scrittura pagina NTAG")
    write_verified = contains_hex(after_write.stdout, new_data)

    restored = None
    restore_verified = None
    if reversible_probe:
        restore_result = run_command(
            client,
            port,
            ntag_write_command(page, expected_before, password),
            timeout,
        )
        results.append(restore_result)
        ensure_success(restore_result, "ripristino pagina NTAG")
        restored = True

        verify_restore = run_command(client, port, ntag_read_command(page, password), timeout)
        results.append(verify_restore)
        ensure_success(verify_restore, "verifica ripristino pagina NTAG")
        restore_verified = contains_hex(verify_restore.stdout, expected_before)
        if not restore_verified:
            raise ActiveLabError(
                "CRITICO: il ripristino della pagina NTAG non è stato verificato. "
                "Isolare il tag e conservare il transcript."
            )

    if not write_verified:
        raise ActiveLabError("La scrittura NTAG non è stata confermata dalla rilettura.")

    return results, {
        "operation_family": "ntag_ultralight_user_page",
        "uid": identification.get("uid"),
        "page": page,
        "expected_before": expected_before,
        "new_data": new_data,
        "write_verified": write_verified,
        "reversible_probe": reversible_probe,
        "restore_attempted": restored,
        "restore_verified": restore_verified,
    }


def execute_mfc_operation(
    *,
    client: Path,
    port: Path,
    timeout: int,
    expected_uid: str,
    block: int,
    expected_before: str,
    new_data: str,
    key: str,
    key_type: str,
    reversible_probe: bool,
) -> tuple[list[CommandResult], dict[str, object]]:
    validate_mfc_data_block(block)
    results: list[CommandResult] = []
    identify_result, identification = run_identification(client, port, timeout, expected_uid)
    results.append(identify_result)

    read_command = mfc_read_command(block, key, key_type)
    before = run_command(client, port, read_command, timeout)
    results.append(before)
    ensure_success(before, "lettura iniziale blocco MIFARE Classic")
    if not contains_hex(before.stdout, expected_before):
        raise ActiveLabError(
            "Il contenuto attuale del blocco non coincide con --expected-before. "
            "Scrittura interrotta per evitare sovrascritture accidentali."
        )

    write_result = run_command(
        client,
        port,
        mfc_write_command(block, key, key_type, new_data),
        timeout,
    )
    results.append(write_result)
    ensure_success(write_result, "scrittura blocco MIFARE Classic")

    after_write = run_command(client, port, read_command, timeout)
    results.append(after_write)
    ensure_success(after_write, "verifica scrittura blocco MIFARE Classic")
    write_verified = contains_hex(after_write.stdout, new_data)

    restored = None
    restore_verified = None
    if reversible_probe:
        restore_result = run_command(
            client,
            port,
            mfc_write_command(block, key, key_type, expected_before),
            timeout,
        )
        results.append(restore_result)
        ensure_success(restore_result, "ripristino blocco MIFARE Classic")
        restored = True

        verify_restore = run_command(client, port, read_command, timeout)
        results.append(verify_restore)
        ensure_success(verify_restore, "verifica ripristino blocco MIFARE Classic")
        restore_verified = contains_hex(verify_restore.stdout, expected_before)
        if not restore_verified:
            raise ActiveLabError(
                "CRITICO: il ripristino del blocco MIFARE Classic non è stato verificato. "
                "Isolare il tag e conservare il transcript."
            )

    if not write_verified:
        raise ActiveLabError("La scrittura MIFARE Classic non è stata confermata dalla rilettura.")

    return results, {
        "operation_family": "mifare_classic_data_block",
        "uid": identification.get("uid"),
        "block": block,
        "key_type": key_type,
        "expected_before": expected_before,
        "new_data": new_data,
        "write_verified": write_verified,
        "reversible_probe": reversible_probe,
        "restore_attempted": restored,
        "restore_verified": restore_verified,
        "key_material_saved": False,
    }


def save_evidence(
    *,
    output_dir: Path,
    case_id: str,
    operation: str,
    client: Path,
    port: Path,
    expected_uid: str,
    results: Sequence[CommandResult],
    outcome: dict[str, object],
    secrets: Sequence[str],
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"pm3_active_{safe_case_id(case_id)}_{operation}_{timestamp}"
    transcript_path = output_dir / f"{stem}.log"
    json_path = output_dir / f"{stem}.json"

    redacted_results = [redact_result(result, secrets) for result in results]
    redacted_outcome = json.loads(redact_text(json.dumps(outcome), secrets))

    transcript_path.write_text(
        render_active_transcript(
            case_id=case_id,
            operation=operation,
            client=client,
            port=port,
            expected_uid=expected_uid,
            results=redacted_results,
            outcome=redacted_outcome,
        ),
        encoding="utf-8",
    )
    transcript_hash = write_hash_sidecar(transcript_path)

    payload = {
        "case_metadata": {
            "case_id": case_id,
            "created_at": now_timestamp(),
            "tool": "proxmark3_active_lab.py",
            "operation": operation,
        },
        "authorization": {
            "attestation_supplied": True,
            "expected_uid": format_uid(expected_uid),
            "arbitrary_commands_enabled": False,
        },
        "device": {"client": str(client), "port": str(port)},
        "safety_controls": {
            "uid_match_required": True,
            "expected_original_data_required": operation != "assess",
            "protected_pages_and_blocks_excluded": True,
            "key_recovery_enabled": False,
            "cloning_enabled": False,
            "simulation_enabled": False,
            "uid_rewriting_enabled": False,
            "secrets_redacted_from_saved_evidence": True,
        },
        "commands": [asdict(result) for result in redacted_results],
        "outcome": redacted_outcome,
        "integrity": {
            "transcript_file": transcript_path.name,
            "sha256_transcript": transcript_hash,
        },
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    json_hash = write_hash_sidecar(json_path)

    return {
        "transcript": str(transcript_path),
        "transcript_sha256": transcript_hash,
        "json": str(json_path),
        "json_sha256": json_hash,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Operazioni Proxmark3 attive e controllate per tag di laboratorio propri "
            "o esplicitamente autorizzati."
        )
    )
    parser.add_argument("--operation", choices=sorted(ACTIVE_OPERATIONS), required=True)
    parser.add_argument("--authorization", required=True, help=f"Deve essere: {AUTHORIZATION_PHRASE}")
    parser.add_argument("--expected-uid", required=True, help="UID esatto del tag autorizzato.")
    parser.add_argument("--case-id", default="LAB")
    parser.add_argument("--client", help="Percorso del client proxmark3.")
    parser.add_argument("--port", help="Porta seriale, ad esempio /dev/ttyACM0.")
    parser.add_argument("--output-dir", default="dumps/proxmark3-active")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--dry-run", action="store_true")

    parser.add_argument("--page", type=int, help="Pagina NTAG/Ultralight utente, consentita 4-39.")
    parser.add_argument("--password", help="Password NTAG/Ultralight autorizzata, 4 byte HEX.")
    parser.add_argument("--block", type=int, help="Blocco dati MIFARE Classic, esclusi 0 e sector trailer.")
    parser.add_argument("--key", help="Chiave MIFARE Classic autorizzata, 6 byte HEX.")
    parser.add_argument("--key-type", choices=("A", "B"), default="A")
    parser.add_argument("--expected-before", help="Contenuto originale obbligatorio prima della scrittura.")
    parser.add_argument("--new-data", help="Nuovo contenuto HEX o pattern temporaneo del probe.")
    return parser


def validate_arguments(args: argparse.Namespace) -> dict[str, object]:
    if args.authorization != AUTHORIZATION_PHRASE:
        raise ActiveLabError("Attestazione di autorizzazione mancante o non valida.")
    if args.timeout < 1 or args.timeout > 600:
        raise ActiveLabError("--timeout deve essere compreso tra 1 e 600 secondi.")

    normalized: dict[str, object] = {"expected_uid": normalize_uid(args.expected_uid)}

    if args.operation.startswith("ntag-"):
        if args.page is None:
            raise ActiveLabError("--page è obbligatorio per le operazioni NTAG/Ultralight.")
        validate_ntag_page(args.page)
        if not args.expected_before or not args.new_data:
            raise ActiveLabError("--expected-before e --new-data sono obbligatori.")
        normalized["expected_before"] = normalize_hex(args.expected_before, 4, "expected-before")
        normalized["new_data"] = normalize_hex(args.new_data, 4, "new-data")
        normalized["password"] = (
            normalize_hex(args.password, 4, "password") if args.password else None
        )

    if args.operation.startswith("mfc-"):
        if args.block is None:
            raise ActiveLabError("--block è obbligatorio per le operazioni MIFARE Classic.")
        validate_mfc_data_block(args.block)
        if not args.key:
            raise ActiveLabError("--key è obbligatoria e deve essere una chiave autorizzata.")
        if not args.expected_before or not args.new_data:
            raise ActiveLabError("--expected-before e --new-data sono obbligatori.")
        normalized["key"] = normalize_hex(args.key, 6, "key")
        normalized["expected_before"] = normalize_hex(args.expected_before, 16, "expected-before")
        normalized["new_data"] = normalize_hex(args.new_data, 16, "new-data")

    return normalized


def dry_run_commands(args: argparse.Namespace, normalized: dict[str, object]) -> list[str]:
    commands = ["hf 14a info"]
    if args.operation == "assess":
        commands.extend(["hf search", "hf mf info", "hf mfu info"])
    elif args.operation.startswith("ntag-"):
        page = args.page
        password = normalized.get("password")
        commands.extend(
            [
                ntag_read_command(page, password),
                ntag_write_command(page, str(normalized["new_data"]), password),
                ntag_read_command(page, password),
            ]
        )
        if args.operation.endswith("probe"):
            commands.extend(
                [
                    ntag_write_command(page, str(normalized["expected_before"]), password),
                    ntag_read_command(page, password),
                ]
            )
    elif args.operation.startswith("mfc-"):
        block = args.block
        key = str(normalized["key"])
        read_command = mfc_read_command(block, key, args.key_type)
        commands.extend(
            [
                read_command,
                mfc_write_command(block, key, args.key_type, str(normalized["new_data"])),
                read_command,
            ]
        )
        if args.operation.endswith("probe"):
            commands.extend(
                [
                    mfc_write_command(
                        block,
                        key,
                        args.key_type,
                        str(normalized["expected_before"]),
                    ),
                    read_command,
                ]
            )
    return commands


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        normalized = validate_arguments(args)
        client = resolve_client(args.client)
        port = resolve_port(args.port)

        secrets = [str(normalized.get("key") or ""), str(normalized.get("password") or "")]

        if args.dry_run:
            print(f"Client: {client}")
            print(f"Port: {port}")
            print(f"Authorized UID: {format_uid(str(normalized['expected_uid']))}")
            print(f"Operation: {args.operation}")
            for command in dry_run_commands(args, normalized):
                print(f"  - {redact_text(command, secrets)}")
            return 0

        if args.operation == "assess":
            results, outcome = execute_assessment(
                client,
                port,
                args.timeout,
                str(normalized["expected_uid"]),
            )
        elif args.operation.startswith("ntag-"):
            results, outcome = execute_ntag_operation(
                client=client,
                port=port,
                timeout=args.timeout,
                expected_uid=str(normalized["expected_uid"]),
                page=args.page,
                expected_before=str(normalized["expected_before"]),
                new_data=str(normalized["new_data"]),
                password=normalized.get("password"),
                reversible_probe=args.operation == "ntag-writable-probe",
            )
        else:
            results, outcome = execute_mfc_operation(
                client=client,
                port=port,
                timeout=args.timeout,
                expected_uid=str(normalized["expected_uid"]),
                block=args.block,
                expected_before=str(normalized["expected_before"]),
                new_data=str(normalized["new_data"]),
                key=str(normalized["key"]),
                key_type=args.key_type,
                reversible_probe=args.operation == "mfc-writable-probe",
            )

        evidence = save_evidence(
            output_dir=Path(args.output_dir),
            case_id=args.case_id,
            operation=args.operation,
            client=client,
            port=port,
            expected_uid=str(normalized["expected_uid"]),
            results=results,
            outcome=outcome,
            secrets=secrets,
        )
    except ActiveLabError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except ProxmarkBackendError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"[ERROR] Errore di sistema: {exc}", file=sys.stderr)
        return 4

    print("[OK] Operazione Proxmark3 active-lab completata.")
    print(json.dumps(outcome, indent=2, ensure_ascii=False))
    print(f"Transcript: {evidence['transcript']}")
    print(f"SHA256 transcript: {evidence['transcript_sha256']}")
    print(f"JSON: {evidence['json']}")
    print(f"SHA256 JSON: {evidence['json_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
