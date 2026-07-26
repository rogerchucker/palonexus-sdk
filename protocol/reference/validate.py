"""Minimal reference validation for draft PaloNexus protocol version 1."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime
from functools import lru_cache
from itertools import zip_longest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

PROTOCOL_ROOT = Path(__file__).parents[1]
SCHEMA_ROOT = PROTOCOL_ROOT / "schemas"
_RFC3339 = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_EXTENSION_NUMBER_LIMIT = 1e308
_UNIX_EPOCH_ORDINAL = datetime(1970, 1, 1).toordinal()


class ProtocolValidationError(ValueError):
    """Safe failure containing a stable code and no raw protocol value."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}: {detail}")


def loads_json_strict(document: str) -> Any:
    """Parse standards-compliant JSON with unique object keys."""

    def reject_constant(_value: str) -> None:
        raise ProtocolValidationError("invalid_json_number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolValidationError("duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(
            document,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except ProtocolValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise ProtocolValidationError("invalid_json") from exc


def _read_document(path: Path) -> dict[str, Any]:
    try:
        value = loads_json_strict(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProtocolValidationError("input_unavailable") from exc
    if not isinstance(value, dict):
        raise ProtocolValidationError("schema_invalid")
    return value


@lru_cache(maxsize=2)
def _validator(kind: str) -> Draft202012Validator:
    common = _read_document(SCHEMA_ROOT / "common-v1.schema.json")
    schema = _read_document(SCHEMA_ROOT / f"{kind}-v1.schema.json")
    registry = Registry().with_resource(
        common["$id"],
        Resource.from_contents(common),
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=registry)


def _validate_structure(kind: str, document: dict[str, Any]) -> None:
    try:
        errors = sorted(
            _validator(kind).iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except RecursionError as exc:
        raise ProtocolValidationError("schema_nesting_exceeded") from exc
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise ProtocolValidationError("schema_invalid", f"{kind}.{path}")


def _parse_rfc3339(value: Any) -> tuple[int, str]:
    if not isinstance(value, str):
        raise ProtocolValidationError("timestamp_invalid")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ProtocolValidationError("timestamp_invalid")
    base, _fraction_with_dot, fraction, zone = match.groups()
    try:
        parsed = datetime.fromisoformat(base)
    except ValueError as exc:
        raise ProtocolValidationError("timestamp_invalid") from exc
    offset_seconds = 0
    if zone != "Z":
        offset_hour = int(zone[1:3])
        offset_minute = int(zone[4:6])
        if offset_hour > 23 or offset_minute > 59:
            raise ProtocolValidationError("timestamp_invalid")
        offset_seconds = (offset_hour * 60 + offset_minute) * 60
        if zone[0] == "-":
            offset_seconds = -offset_seconds
    local_seconds = (
        (parsed.toordinal() - _UNIX_EPOCH_ORDINAL) * 86_400
        + parsed.hour * 3_600
        + parsed.minute * 60
        + parsed.second
    )
    return local_seconds - offset_seconds, fraction or ""


def _timestamp_order(left: tuple[int, str], right: tuple[int, str]) -> int:
    if left[0] != right[0]:
        return -1 if left[0] < right[0] else 1
    for left_digit, right_digit in zip_longest(
        left[1],
        right[1],
        fillvalue="0",
    ):
        if left_digit != right_digit:
            return -1 if left_digit < right_digit else 1
    return 0


def _validate_extension_numbers(document: dict[str, Any]) -> None:
    containers: list[Any] = [document]
    extension_values: list[Any] = []
    while containers:
        value = containers.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "extensions":
                    extension_values.append(child)
                elif isinstance(child, (dict, list)):
                    containers.append(child)
        elif isinstance(value, list):
            containers.extend(value)

    while extension_values:
        value = extension_values.pop()
        if isinstance(value, dict):
            extension_values.extend(value.values())
        elif isinstance(value, list):
            extension_values.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ProtocolValidationError("extension_number_invalid")
        elif (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (
                value < -_EXTENSION_NUMBER_LIMIT
                or value > _EXTENSION_NUMBER_LIMIT
            )
        ):
            raise ProtocolValidationError("extension_number_invalid")


def validate_action_document(document: dict[str, Any]) -> None:
    """Validate the Task 5 structural action contract."""

    if not isinstance(document, dict):
        raise ProtocolValidationError("schema_invalid")
    _validate_structure("action", document)
    _parse_rfc3339(document["occurredAt"])
    _validate_extension_numbers(document)


def validate_decision_document(document: dict[str, Any]) -> None:
    """Validate decision structure and the Task 5 expiry-order invariant."""

    if not isinstance(document, dict):
        raise ProtocolValidationError("schema_invalid")
    _validate_structure("decision", document)
    server_time = _parse_rfc3339(document["serverTime"])
    expires_at = _parse_rfc3339(document["expiresAt"])
    if "approval" in document:
        _parse_rfc3339(document["approval"]["expiresAt"])
    if _timestamp_order(expires_at, server_time) <= 0:
        raise ProtocolValidationError("decision_expiry_order")
    _validate_extension_numbers(document)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="palonexus-protocol-validate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    action = subparsers.add_parser("action")
    action.add_argument("document")
    decision = subparsers.add_parser("decision")
    decision.add_argument("document")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = _read_document(Path(args.document))
        if args.command == "action":
            validate_action_document(document)
        else:
            validate_decision_document(document)
    except ProtocolValidationError as exc:
        print(f"validation failed: {exc.code}", file=sys.stderr)
        return 2
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
