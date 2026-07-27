# SPDX-License-Identifier: MIT
"""Protocol-v1 canonicalization shared by the SDK and golden-vector reference.

This module generates and checks the protocol vectors; it is not an SDK client
or a network transport.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import posixpath
import re
import shlex
import sys
import types
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal, DecimalException
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import idna
import idna.core as idna_core
import unicodedata2 as unicode_data

VECTORS = Path(__file__).parents[1] / "test-vectors" / "canonicalization"
UNICODE_VERSION: Final = "15.1.0"
IDNA_VERSION: Final = "3.18"
MAX_INPUT_BYTES: Final = 65_536
MAX_NESTING_DEPTH: Final = 32
MAX_OBJECT_KEYS: Final = 256
MAX_ARRAY_ITEMS: Final = 1_024
MAX_STRING_BYTES: Final = 8_192
MAX_SIGNIFICANT_DIGITS: Final = 128
MIN_NORMALIZED_EXPONENT: Final = -435
MAX_NORMALIZED_EXPONENT: Final = 308
MAX_DECIMAL: Final = Decimal("1e308")
MIN_NONZERO_DECIMAL: Final = Decimal("1e-308")
MCP_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SENSITIVE_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
DNS_LABEL: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AMBIGUOUS_NUMERIC_HOST: Final = re.compile(
    r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$",
    re.IGNORECASE,
)
PERCENT_ESCAPE: Final = re.compile(r"%[0-9A-Fa-f]{2}")
UNRESERVED: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
SENSITIVE_NAMES: Final = frozenset(
    {
        "access-key",
        "access_key",
        "api-key",
        "api_key",
        "authorization",
        "cookie",
        "password",
        "secret",
        "token",
    }
)
SENSITIVE_QUERY_KEYS: Final = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "code",
        "credential",
        "password",
        "secret",
        "signature",
        "token",
    }
)
REDACTED: Final = "[REDACTED]"

if unicode_data.unidata_version != UNICODE_VERSION:
    raise RuntimeError(
        "canonicalization requires Unicode data "
        f"{UNICODE_VERSION}, got {unicode_data.unidata_version}"
    )
if idna.__version__ != IDNA_VERSION:
    raise RuntimeError(
        f"canonicalization requires idna {IDNA_VERSION}, got {idna.__version__}"
    )


def _isolated_idna_functions() -> tuple[Any, Any]:
    """Clone idna.core functions with pinned Unicode globals.

    The third-party module remains untouched, so importing PaloNexus cannot
    change IDNA behavior for another library in this process.
    """

    isolated_globals = dict(vars(idna_core))
    isolated_globals["unicodedata"] = unicode_data
    for name, value in tuple(isolated_globals.items()):
        if (
            isinstance(value, types.FunctionType)
            and value.__globals__ is idna_core.__dict__
        ):
            isolated_globals[name] = types.FunctionType(
                value.__code__,
                isolated_globals,
                name=value.__name__,
                argdefs=value.__defaults__,
                closure=value.__closure__,
            )
            isolated_globals[name].__kwdefaults__ = value.__kwdefaults__
    return isolated_globals["encode"], isolated_globals["decode"]


_idna_encode, _idna_decode = _isolated_idna_functions()


class _Absent:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Final = _Absent()


class CanonicalizationError(ValueError):
    """A fail-closed error with a stable vector-facing code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _nfc(value: str, *, code: str = "invalid_string") -> str:
    if not isinstance(value, str):
        raise CanonicalizationError(code, "expected a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(code, "string is not valid Unicode") from exc
    if len(encoded) > MAX_STRING_BYTES:
        raise CanonicalizationError(
            "string_too_large",
            "canonical string exceeds the portable byte limit",
        )
    if any(unicode_data.category(character) == "Cn" for character in value):
        raise CanonicalizationError(
            "unassigned_unicode",
            "string contains a code point unassigned in Unicode 15.1.0",
        )
    normalized = unicode_data.normalize("NFC", value)
    try:
        normalized_bytes = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(code, "string is not valid Unicode") from exc
    if len(normalized_bytes) > MAX_STRING_BYTES:
        raise CanonicalizationError(
            "string_too_large",
            "normalized string exceeds the portable byte limit",
        )
    if any(unicode_data.category(character) == "Cn" for character in normalized):
        raise CanonicalizationError(
            "unassigned_unicode",
            "normalized string contains an unassigned Unicode 15.1.0 code point",
        )
    return normalized


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, value in pairs:
        key = _nfc(raw_key, code="invalid_json")
        if key in result:
            raise CanonicalizationError(
                "duplicate_key",
                "JSON object contains duplicate keys after NFC normalization",
            )
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise CanonicalizationError("non_finite_number", "JSON number must be finite")


def parse_json(source: str | bytes) -> Any:
    """Parse JSON without losing exact decimal values or duplicate keys."""

    try:
        if isinstance(source, bytes):
            if len(source) > MAX_INPUT_BYTES:
                raise CanonicalizationError(
                    "input_too_large",
                    "JSON input exceeds the portable byte limit",
                )
            source = source.decode("utf-8", errors="strict")
        if not isinstance(source, str):
            raise CanonicalizationError("invalid_json", "JSON input must be text")
        try:
            source_bytes = source.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError(
                "invalid_json",
                "JSON input is not valid Unicode",
            ) from exc
        if len(source_bytes) > MAX_INPUT_BYTES:
            raise CanonicalizationError(
                "input_too_large",
                "JSON input exceeds the portable byte limit",
            )
        value = json.loads(
            source,
            parse_float=Decimal,
            parse_int=Decimal,
            parse_constant=_invalid_constant,
            object_pairs_hook=_object_from_pairs,
        )
        _validate_value(value)
        return value
    except CanonicalizationError:
        raise
    except RecursionError as exc:
        raise CanonicalizationError(
            "nesting_too_deep",
            "JSON nesting exceeds the portable limit",
        ) from exc
    except MemoryError as exc:
        raise CanonicalizationError(
            "input_too_large",
            "JSON input exceeds available canonicalization resources",
        ) from exc
    except DecimalException as exc:
        raise CanonicalizationError(
            "number_out_of_range",
            "JSON number is outside the portable decimal range",
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalizationError("invalid_json", "invalid JSON input") from exc


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise CanonicalizationError(
            "non_finite_number",
            "canonical numbers must be finite",
        )
    if value == 0:
        return "0"
    _sign, raw_digits, raw_exponent = value.as_tuple()
    digits = list(raw_digits)
    exponent = raw_exponent
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    if len(digits) > MAX_SIGNIFICANT_DIGITS:
        raise CanonicalizationError(
            "number_too_precise",
            "canonical number exceeds the significant-digit limit",
        )
    if exponent < MIN_NORMALIZED_EXPONENT or exponent > MAX_NORMALIZED_EXPONENT:
        raise CanonicalizationError(
            "number_out_of_range",
            "canonical number exponent is outside the portable range",
        )
    magnitude = abs(value)
    if magnitude > MAX_DECIMAL or magnitude < MIN_NONZERO_DECIMAL:
        raise CanonicalizationError(
            "number_out_of_range",
            "canonical numbers must be in [1e-308, 1e308] by magnitude",
        )
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _snapshot_value(value: Any) -> Any:
    """Capture a bounded immutable view without re-reading caller containers."""

    active: set[int] = set()
    memo: dict[int, tuple[Any, int]] = {}
    used = [0]

    def charge(amount: int) -> None:
        used[0] += amount
        if used[0] > MAX_INPUT_BYTES:
            raise CanonicalizationError(
                "input_too_large",
                "canonical input exceeds the portable byte limit",
            )

    def visit(item: Any, depth: int) -> Any:
        if item is ABSENT or item is None or isinstance(item, bool):
            charge(5)
            return item
        if isinstance(item, str):
            normalized = _nfc(item)
            charge(len(normalized.encode("utf-8")) + 2)
            return normalized
        if isinstance(item, float):
            raise CanonicalizationError(
                "binary_float",
                "binary floating-point values are not portable canonical inputs",
            )
        if isinstance(item, int):
            charge(len(_decimal_text(Decimal(item))))
            return item
        if isinstance(item, Decimal):
            charge(len(_decimal_text(item)))
            return item
        is_mapping = isinstance(item, Mapping)
        is_sequence = isinstance(item, Sequence) and not isinstance(
            item, (str, bytes, bytearray)
        )
        if not is_mapping and not is_sequence:
            raise CanonicalizationError(
                "unsupported_value",
                f"unsupported canonical JSON value type: {type(item).__name__}",
            )
        if depth >= MAX_NESTING_DEPTH:
            raise CanonicalizationError(
                "nesting_too_deep",
                "canonical input exceeds the portable nesting limit",
            )
        identity = id(item)
        if identity in active:
            raise CanonicalizationError(
                "cyclic_value",
                "canonical input contains a cycle",
            )
        cached = memo.get(identity)
        if cached is not None:
            charge(cached[1])
            return cached[0]
        active.add(identity)
        before = used[0]
        charge(2)
        try:
            if is_mapping:
                captured: dict[str, Any] = {}
                count = 0
                for raw_key, child in item.items():
                    count += 1
                    if count > MAX_OBJECT_KEYS:
                        raise CanonicalizationError(
                            "too_many_object_keys",
                            "object exceeds the portable key-count limit",
                        )
                    if not isinstance(raw_key, str):
                        raise CanonicalizationError(
                            "invalid_object_key",
                            "canonical JSON object keys must be strings",
                        )
                    key = _nfc(raw_key)
                    if key in captured:
                        raise CanonicalizationError(
                            "duplicate_key",
                            "object contains duplicate keys after NFC normalization",
                        )
                    charge(len(key.encode("utf-8")) + 4)
                    captured[key] = visit(child, depth + 1)
                snapshot: Any = MappingProxyType(captured)
            else:
                values: list[Any] = []
                for child in item:
                    if len(values) >= MAX_ARRAY_ITEMS:
                        raise CanonicalizationError(
                            "too_many_array_items",
                            "array exceeds the portable item-count limit",
                        )
                    charge(1)
                    values.append(visit(child, depth + 1))
                snapshot = tuple(values)
        finally:
            active.remove(identity)
        memo[identity] = (snapshot, used[0] - before)
        return snapshot

    return visit(value, 0)


def _validate_value(value: Any) -> None:
    _snapshot_value(value)


def _json_string(value: str) -> str:
    return json.dumps(
        _nfc(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _encode_canonical(value: Any) -> str:
    if value is ABSENT:
        raise CanonicalizationError(
            "absent_value",
            "ABSENT is valid only as an object value",
        )
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, float):
        raise CanonicalizationError(
            "binary_float",
            "binary floating-point values are not portable canonical inputs",
        )
    if isinstance(value, int):
        return _decimal_text(Decimal(value))
    if isinstance(value, Decimal):
        return _decimal_text(value)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise CanonicalizationError(
                    "invalid_object_key",
                    "canonical JSON object keys must be strings",
                )
            key = _nfc(raw_key)
            if key in normalized:
                raise CanonicalizationError(
                    "duplicate_key",
                    "object contains duplicate keys after NFC normalization",
                )
            if item is not ABSENT:
                normalized[key] = item
        fields = (
            f"{_json_string(key)}:{_encode_canonical(normalized[key])}"
            for key in sorted(normalized)
        )
        return "{" + ",".join(fields) + "}"
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        if any(item is ABSENT for item in value):
            raise CanonicalizationError(
                "absent_array_value",
                "array positions cannot be omitted",
            )
        return "[" + ",".join(_encode_canonical(item) for item in value) + "]"
    raise CanonicalizationError(
        "unsupported_value",
        f"unsupported canonical JSON value type: {type(value).__name__}",
    )


def canonical_json(value: Any) -> bytes:
    """Return canonical JSON encoded as UTF-8 bytes."""

    try:
        snapshot = _snapshot_value(value)
        result = _encode_canonical(snapshot).encode("utf-8", errors="strict")
        if len(result) > MAX_INPUT_BYTES:
            raise CanonicalizationError(
                "input_too_large",
                "canonical JSON exceeds the portable byte limit",
            )
        return result
    except CanonicalizationError:
        raise
    except RecursionError as exc:
        raise CanonicalizationError(
            "nesting_too_deep",
            "canonical input exceeds the portable nesting limit",
        ) from exc
    except MemoryError as exc:
        raise CanonicalizationError(
            "input_too_large",
            "canonical input exceeds available resources",
        ) from exc
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(
            "invalid_string",
            "canonical JSON contains invalid Unicode",
        ) from exc
    except DecimalException as exc:
        raise CanonicalizationError(
            "number_out_of_range",
            "canonical number is outside the portable decimal range",
        ) from exc


def canonical_hash(value: Any) -> str:
    """Hash canonical JSON, or already-canonical bytes, with SHA-256."""

    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
    else:
        payload = canonical_json(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def canonicalize_path(path: str, *, cwd: str) -> str:
    """Create a POSIX lexical absolute path without filesystem inspection."""

    normalized_path = _nfc(path, code="invalid_path")
    normalized_cwd = _nfc(cwd, code="invalid_path")
    if "\x00" in normalized_path or "\x00" in normalized_cwd:
        raise CanonicalizationError("invalid_path", "path contains NUL")
    if "\\" in normalized_path or "\\" in normalized_cwd:
        raise CanonicalizationError(
            "unsupported_path_syntax",
            "protocol v1 canonical paths use POSIX slash syntax",
        )
    if not normalized_cwd.startswith("/"):
        raise CanonicalizationError(
            "cwd_not_absolute",
            "captured working directory must be absolute",
        )
    combined = (
        normalized_path
        if normalized_path.startswith("/")
        else posixpath.join(normalized_cwd, normalized_path)
    )
    parts: list[str] = []
    for part in combined.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _validate_percent_encoding(value: str) -> None:
    position = 0
    while position < len(value):
        if value[position] != "%":
            position += 1
            continue
        match = PERCENT_ESCAPE.match(value, position)
        if match is None:
            raise CanonicalizationError(
                "invalid_percent_encoding",
                "URL contains malformed percent encoding",
            )
        position = match.end()


def _normalize_percent_component(value: str, *, safe: str) -> str:
    _validate_percent_encoding(value)
    output: list[str] = []
    position = 0
    while position < len(value):
        if value[position] != "%":
            output.append(value[position])
            position += 1
            continue
        encoded: list[int] = []
        while position < len(value) and value[position] == "%":
            encoded.append(int(value[position + 1 : position + 3], 16))
            position += 3
        byte_position = 0
        while byte_position < len(encoded):
            byte = encoded[byte_position]
            if byte < 128:
                if byte < 0x20 or byte == 0x7F:
                    raise CanonicalizationError(
                        "invalid_url",
                        "URL contains a percent-encoded control character",
                    )
                character = chr(byte)
                output.append(character if character in UNRESERVED else f"%{byte:02X}")
                byte_position += 1
                continue
            end = byte_position
            while end < len(encoded) and encoded[end] >= 128:
                end += 1
            try:
                output.append(bytes(encoded[byte_position:end]).decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise CanonicalizationError(
                    "invalid_url_utf8",
                    "URL percent bytes are not valid UTF-8",
                ) from exc
            byte_position = end
    normalized = _nfc("".join(output), code="invalid_url")
    if any(
        unicode_data.category(character) == "Cc" or character in {"\u2028", "\u2029"}
        for character in normalized
    ):
        raise CanonicalizationError("invalid_url", "URL contains control characters")
    rendered = quote(normalized, safe=safe + "%", encoding="utf-8", errors="strict")
    return re.sub(
        r"%[0-9a-fA-F]{2}",
        lambda match: match.group(0).upper(),
        rendered,
    )


def _remove_last_url_segment(output: str) -> str:
    slash = output.rfind("/")
    return "" if slash < 0 else output[:slash]


def _remove_url_dot_segments(path: str) -> str:
    """Apply RFC 3986 section 5.2.4 without collapsing empty segments."""

    remaining = path
    output = ""
    while remaining:
        if remaining.startswith("../"):
            remaining = remaining[3:]
        elif remaining.startswith("./"):
            remaining = remaining[2:]
        elif remaining.startswith("/./"):
            remaining = "/" + remaining[3:]
        elif remaining == "/.":
            remaining = "/"
        elif remaining.startswith("/../"):
            remaining = "/" + remaining[4:]
            output = _remove_last_url_segment(output)
        elif remaining == "/..":
            remaining = "/"
            output = _remove_last_url_segment(output)
        elif remaining in {".", ".."}:
            remaining = ""
        else:
            start = 1 if remaining.startswith("/") else 0
            slash = remaining.find("/", start)
            if slash < 0:
                output += remaining
                remaining = ""
            else:
                output += remaining[:slash]
                remaining = remaining[slash:]
    return output or "/"


def _canonical_host(host: str) -> str:
    raw = _nfc(host, code="invalid_url")
    if raw.endswith("."):
        raise CanonicalizationError(
            "noncanonical_url_host",
            "URL host must not contain a trailing dot",
        )
    if ":" in raw:
        raise CanonicalizationError(
            "unsupported_ipv6",
            "protocol v1 does not canonicalize IPv6 URL authorities",
        )
    try:
        normalized = raw.encode("ascii").decode("ascii").lower()
    except UnicodeError as exc:
        raise CanonicalizationError(
            "unsupported_url_host",
            "protocol v1 requires DNS hosts in ASCII A-label form",
        ) from exc
    if not normalized:
        raise CanonicalizationError("missing_url_host", "URL host is missing")
    try:
        address = ipaddress.IPv4Address(normalized)
    except ValueError:
        if AMBIGUOUS_NUMERIC_HOST.fullmatch(normalized):
            raise CanonicalizationError(
                "ambiguous_numeric_host",
                "numeric URL host is not canonical dotted-decimal IPv4",
            )
        if len(normalized) > 253:
            raise CanonicalizationError("invalid_url_host", "URL host is too long")
        labels = normalized.split(".")
        if any(DNS_LABEL.fullmatch(label) is None for label in labels):
            raise CanonicalizationError(
                "invalid_url_host",
                "URL host contains an invalid DNS A-label",
            )
        for label in labels:
            if not label.startswith("xn--"):
                continue
            try:
                decoded = _idna_decode(
                    label,
                    strict=True,
                    uts46=False,
                    std3_rules=True,
                )
                _nfc(decoded, code="invalid_url_host")
                round_trip = _idna_encode(
                    decoded,
                    strict=True,
                    uts46=False,
                    std3_rules=True,
                ).decode("ascii")
            except idna.IDNAError as exc:
                raise CanonicalizationError(
                    "invalid_url_host",
                    "URL host contains an invalid DNS A-label",
                ) from exc
            if round_trip.lower() != label.lower():
                raise CanonicalizationError(
                    "invalid_url_host",
                    "URL host contains an invalid DNS A-label",
                )
        return normalized
    if str(address) != normalized:
        raise CanonicalizationError(
            "ambiguous_numeric_host",
            "IPv4 host is not canonical dotted decimal",
        )
    return str(address)


def _reject_ambiguous_url_source(source: str) -> None:
    if "\\" in source:
        raise CanonicalizationError("invalid_url", "URL contains backslash syntax")
    if any(
        unicode_data.category(character) == "Cc" or character in {"\u2028", "\u2029"}
        for character in source
    ):
        raise CanonicalizationError("invalid_url", "URL contains control characters")


def canonicalize_url(
    value: str,
    *,
    sensitive_query_keys: frozenset[str] = SENSITIVE_QUERY_KEYS,
    _redact_sensitive_values: bool = True,
) -> str:
    """Normalize an HTTP(S) authorization target and redact query secrets."""

    source = _nfc(value, code="invalid_url")
    _reject_ambiguous_url_source(source)
    try:
        parsed = urlsplit(source)
    except ValueError as exc:
        raise CanonicalizationError("invalid_url", "invalid URL") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise CanonicalizationError(
            "unsupported_url_scheme",
            "only HTTP and HTTPS URLs are canonicalized in protocol v1",
        )
    if parsed.hostname is None:
        raise CanonicalizationError("missing_url_host", "URL host is missing")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise CanonicalizationError(
            "url_userinfo",
            "URL user information is not part of protocol v1 resources",
        )
    if "%" in parsed.netloc:
        raise CanonicalizationError(
            "invalid_url_host",
            "URL authority must not contain percent encoding",
        )
    if "[" in parsed.netloc or "]" in parsed.netloc:
        raise CanonicalizationError(
            "unsupported_ipv6",
            "protocol v1 does not canonicalize IPv6 URL authorities",
        )
    host = _canonical_host(parsed.hostname)
    raw_port: str | None = None
    if ":" in parsed.netloc:
        _raw_host, _separator, raw_port = parsed.netloc.rpartition(":")
        if (
            not raw_port.isascii()
            or not raw_port.isdigit()
            or (len(raw_port) > 1 and raw_port.startswith("0"))
        ):
            raise CanonicalizationError(
                "noncanonical_url_port",
                "URL port must use canonical unsigned decimal syntax",
            )
    try:
        port = parsed.port
    except ValueError as exc:
        raise CanonicalizationError("invalid_url_port", "invalid URL port") from exc
    if port == 0:
        raise CanonicalizationError("invalid_url_port", "URL port zero is invalid")
    if raw_port is not None and int(raw_port) != port:
        raise CanonicalizationError(
            "noncanonical_url_port",
            "URL port is not canonical",
        )
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = host if port is None or default_port else f"{host}:{port}"

    path = _normalize_percent_component(parsed.path or "/", safe="/:@!$&'()*+,;=-._~")
    path = _remove_url_dot_segments(path)

    _validate_percent_encoding(parsed.query)
    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
            encoding="utf-8",
            errors="strict",
        )
    except UnicodeDecodeError as exc:
        raise CanonicalizationError(
            "invalid_url_utf8",
            "URL query is not valid UTF-8",
        ) from exc
    normalized_pairs: list[tuple[str, str, int]] = []
    sensitive = _sensitive_names(set(SENSITIVE_QUERY_KEYS) | set(sensitive_query_keys))
    for index, (raw_key, raw_value) in enumerate(pairs):
        key = _nfc(raw_key, code="invalid_url")
        item = _nfc(raw_value, code="invalid_url")
        _reject_ambiguous_url_source(key)
        _reject_ambiguous_url_source(item)
        if _redact_sensitive_values and _sensitive_name(key, sensitive):
            item = REDACTED
        normalized_pairs.append((key, item, index))
    normalized_pairs.sort(key=lambda item: (item[0], item[2]))
    query = urlencode(
        [(key, item) for key, item, _ in normalized_pairs],
        doseq=True,
        safe="-._~",
        encoding="utf-8",
        errors="strict",
        quote_via=quote,
    )
    return urlunsplit((scheme, netloc, path, query, ""))


def _normalize_sensitive_name(value: str) -> str:
    if not isinstance(value, str):
        raise CanonicalizationError(
            "invalid_sensitive_name",
            "sensitive names must be strings",
        )
    normalized = _nfc(value, code="invalid_sensitive_name")
    normalized = normalized.strip().lstrip("-")
    if not normalized.isascii():
        raise CanonicalizationError(
            "invalid_sensitive_name",
            "sensitive names must contain ASCII characters only",
        )
    normalized = normalized.lower().replace("_", "-")
    if SENSITIVE_NAME.fullmatch(normalized) is None:
        raise CanonicalizationError(
            "invalid_sensitive_name",
            "sensitive name is not a portable option or assignment name",
        )
    return normalized


def _sensitive_names(additional: set[str] | frozenset[str]) -> frozenset[str]:
    mandatory = {_normalize_sensitive_name(value) for value in SENSITIVE_NAMES}
    additions = {_normalize_sensitive_name(value) for value in additional}
    return frozenset(mandatory | additions)


def _sensitive_name(value: str, names: frozenset[str]) -> bool:
    try:
        normalized = _normalize_sensitive_name(value)
    except CanonicalizationError:
        return False
    return normalized in names


def _redact_header(value: str) -> str:
    name, separator, _contents = value.partition(":")
    if separator and name.strip().lower() in {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
    }:
        return f"{name.strip()}: {REDACTED}"
    return value


def _redact_shell_tokens(
    tokens: list[str],
    sensitive_names: frozenset[str],
) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    header_next = False
    for token in tokens:
        if redact_next:
            redacted.append(REDACTED)
            redact_next = False
            continue
        if header_next:
            redacted.append(REDACTED)
            header_next = False
            continue
        if token in {"-H", "--header"}:
            redacted.append(token)
            header_next = True
            continue
        if token.startswith("--header="):
            redacted.append(f"--header={REDACTED}")
            continue
        if token.startswith("-H") and len(token) > 2:
            redacted.append(f"-H{REDACTED}")
            continue
        name, separator, _item = token.partition("=")
        if separator and _sensitive_name(name, sensitive_names):
            redacted.append(f"{name}={REDACTED}")
            continue
        if _sensitive_name(token, sensitive_names):
            redacted.append(token)
            redact_next = True
            continue
        if token.lower().startswith(("http://", "https://")):
            try:
                redacted.append(
                    canonicalize_url(
                        token,
                        sensitive_query_keys=sensitive_names,
                    )
                )
            except CanonicalizationError:
                redacted.append("[URL]")
            continue
        redacted.append(_redact_header(token))
    if redact_next or header_next:
        redacted.append(REDACTED)
    return redacted


def canonicalize_shell(
    command: str,
    *,
    additional_sensitive_names: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Return safe diagnostic tokens plus a binding to the full command."""

    normalized = _nfc(command, code="invalid_shell_command")
    names = _sensitive_names(additional_sensitive_names)
    command_hash = canonical_hash(normalized.encode("utf-8"))
    try:
        tokens = shlex.split(normalized, posix=True)
    except ValueError:
        tokens = ["[UNPARSEABLE]"]
    else:
        tokens = _redact_shell_tokens(tokens, names)
    return {
        "commandHash": command_hash,
        "tokens": tokens,
    }


def canonicalize_mcp(server: str, tool: str, tool_input: Any) -> str:
    """Bind a server-qualified MCP tool to canonical JSON tool input."""

    normalized_server = _nfc(server, code="invalid_mcp_name")
    normalized_tool = _nfc(tool, code="invalid_mcp_name")
    if (
        MCP_NAME.fullmatch(normalized_server) is None
        or MCP_NAME.fullmatch(normalized_tool) is None
    ):
        raise CanonicalizationError(
            "invalid_mcp_name",
            "MCP server and tool names must be unambiguous name segments",
        )
    return f"mcp:{normalized_server}/{normalized_tool}#{canonical_hash(tool_input)}"


@dataclass(frozen=True)
class PreparedResource:
    """A canonical resource paired with the exact value an adapter executes."""

    resource: str
    execution: Any


def prepare_path_resource(path: str, *, cwd: str) -> PreparedResource:
    execution = canonicalize_path(path, cwd=cwd)
    return PreparedResource(resource=f"path:{execution}", execution=execution)


def prepare_url_resource(
    value: str,
    *,
    sensitive_query_keys: frozenset[str] = frozenset(),
) -> PreparedResource:
    execution = canonicalize_url(
        value,
        sensitive_query_keys=sensitive_query_keys,
        _redact_sensitive_values=False,
    )
    diagnostic_url = canonicalize_url(
        value,
        sensitive_query_keys=sensitive_query_keys,
    )
    resource = canonical_json(
        {
            "executionHash": canonical_hash(
                {
                    "preimageType": "palonexus.url-execution",
                    "preimageVersion": "1",
                    "url": execution,
                }
            ),
            "url": diagnostic_url,
        }
    ).decode("utf-8")
    return PreparedResource(resource=resource, execution=execution)


def prepare_shell_resource(
    command: str,
    *,
    additional_sensitive_names: set[str] | frozenset[str] = frozenset(),
) -> PreparedResource:
    execution = _nfc(command, code="invalid_shell_command")
    safe_resource = canonicalize_shell(
        execution,
        additional_sensitive_names=additional_sensitive_names,
    )
    return PreparedResource(
        resource=canonical_json(safe_resource).decode("utf-8"),
        execution=execution,
    )


def prepare_mcp_resource(
    server: str,
    tool: str,
    tool_input: Any,
) -> PreparedResource:
    normalized_input = parse_json(canonical_json(tool_input))
    normalized_server = _nfc(server, code="invalid_mcp_name")
    normalized_tool = _nfc(tool, code="invalid_mcp_name")
    resource = canonicalize_mcp(
        normalized_server,
        normalized_tool,
        normalized_input,
    )
    return PreparedResource(
        resource=resource,
        execution={
            "server": normalized_server,
            "tool": normalized_tool,
            "input": normalized_input,
        },
    )


def _required_mapping(
    value: Any,
    field: str,
    *,
    code: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CanonicalizationError(code, f"{field} must be an object")
    return value


def _required_string(
    value: Mapping[str, Any],
    field: str,
    *,
    code: str,
) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise CanonicalizationError(code, f"{field} must be a nonempty string")
    return _nfc(item, code=code)


def resource_hash_input(target: Mapping[str, Any]) -> dict[str, str]:
    code = "invalid_target_resource"
    value = _required_mapping(target, "target", code=code)
    return {
        "preimageType": "palonexus.resource",
        "preimageVersion": "1",
        "kind": _required_string(value, "kind", code=code),
        "service": _required_string(value, "service", code=code),
        "resource": _required_string(value, "resource", code=code),
    }


def computed_resource_hash(target: Mapping[str, Any]) -> str:
    return canonical_hash(resource_hash_input(target))


def build_target(
    *,
    kind: str,
    service: str,
    prepared: PreparedResource,
) -> dict[str, str]:
    if not isinstance(prepared, PreparedResource):
        raise CanonicalizationError(
            "unprepared_resource",
            "target construction requires a PreparedResource",
        )
    target = {
        "kind": _nfc(kind, code="invalid_target_resource"),
        "service": _nfc(service, code="invalid_target_resource"),
        "resource": _nfc(prepared.resource, code="invalid_target_resource"),
    }
    target["resourceHash"] = computed_resource_hash(target)
    return target


def validated_target(target: Mapping[str, Any]) -> dict[str, str]:
    value = resource_hash_input(target)
    expected = canonical_hash(value)
    supplied = target.get("resourceHash")
    if supplied != expected:
        raise CanonicalizationError(
            "resource_hash_mismatch",
            "target resourceHash does not bind the canonical resource preimage",
        )
    return {
        "kind": value["kind"],
        "service": value["service"],
        "resource": value["resource"],
        "resourceHash": expected,
    }


def client_scope_input(action_request: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the explicit client-visible scope-hash input."""

    code = "invalid_client_scope"
    action = _required_mapping(action_request, "action request", code=code)
    adapter = _required_mapping(action.get("adapter"), "adapter", code=code)
    task = _required_mapping(action.get("task"), "task", code=code)
    target = validated_target(
        _required_mapping(action.get("target"), "target", code=code)
    )
    return {
        "scopeType": "client",
        "scopeVersion": "1",
        "adapter": {
            "id": _required_string(adapter, "id", code=code),
            "version": _required_string(adapter, "version", code=code),
        },
        "task": {
            "taskId": _required_string(task, "taskId", code=code),
            "sessionId": _required_string(task, "sessionId", code=code),
        },
        "action": _required_string(action, "action", code=code),
        "target": {
            "kind": _required_string(target, "kind", code=code),
            "service": _required_string(target, "service", code=code),
            "resourceHash": _required_string(target, "resourceHash", code=code),
        },
        "sideEffect": _required_string(action, "sideEffect", code=code),
    }


def _trusted_scope(trusted_context: Mapping[str, Any]) -> dict[str, str]:
    code = "invalid_authoritative_scope"
    trusted = _required_mapping(trusted_context, "trusted context", code=code)
    allowed = {
        "tenantId",
        "actorId",
        "agentId",
        "delegationId",
        "clientId",
    }
    if set(trusted) - allowed:
        raise CanonicalizationError(
            code,
            "trusted context contains unknown fields",
        )
    result = {
        "tenantId": _required_string(trusted, "tenantId", code=code),
        "actorId": _required_string(trusted, "actorId", code=code),
        "clientId": _required_string(trusted, "clientId", code=code),
    }
    for field in ("agentId", "delegationId"):
        if field in trusted:
            result[field] = _required_string(trusted, field, code=code)
    return result


def authoritative_scope_input(
    action_request: Mapping[str, Any],
    trusted_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the server-only scope input from client scope and trusted identity."""

    return {
        "scopeType": "authoritative",
        "scopeVersion": "1",
        "clientScope": client_scope_input(action_request),
        "trusted": _trusted_scope(trusted_context),
    }


def client_scope_hash(action_request: Mapping[str, Any]) -> str:
    return canonical_hash(client_scope_input(action_request))


def authoritative_scope_hash(
    action_request: Mapping[str, Any],
    trusted_context: Mapping[str, Any],
) -> str:
    return canonical_hash(authoritative_scope_input(action_request, trusted_context))


def _vector_action() -> dict[str, Any]:
    target = build_target(
        kind="local-action",
        service="workspace",
        prepared=prepare_path_resource(
            "deploy/production.yaml",
            cwd="/workspace",
        ),
    )
    return {
        "schemaVersion": "1",
        "actionId": "act_01J5ABCDEFGHJKMNPQRSTVWXY0",
        "requestId": "req_01J5ABCDEFGHJKMNPQRSTVWXY0",
        "correlationId": "corr_01J5ABCDEFGHJKMNPQRSTVWXY0",
        "idempotencyKey": "authz_01J5ABCDEFGHJKMNPQRSTVWXY0",
        "adapter": {
            "id": "codex",
            "version": "0.2.0-alpha.1",
            "hostVersion": "0.145.0",
        },
        "task": {
            "taskId": "task_01J5ABCDEFGHJKMNPQRSTVWXY0",
            "sessionId": "session_01J5ABCDEFGHJKMNPQRSTVWXY0",
        },
        "action": "file:write",
        "target": target,
        "sideEffect": "write",
        "occurredAt": "2026-07-25T20:00:00Z",
        "context": {"toolName": "apply_patch"},
    }


def _vector_trusted() -> dict[str, str]:
    return {
        "tenantId": "tenant_example",
        "actorId": "subject_example",
        "agentId": "agent_example",
        "delegationId": "delegation_example",
        "clientId": "registered-codex",
    }


def _vector(case: str, contract: str, inputs: Any) -> dict[str, Any]:
    return {
        "canonicalizationVersion": "1",
        "case": case,
        "status": "draft-pending-gate-0",
        "contract": contract,
        "inputs": inputs,
        "expected": _derive_vector_expected(case, inputs),
    }


def _error_code(operation: Any) -> str:
    try:
        operation()
    except CanonicalizationError as exc:
        return exc.code
    return "missing_expected_error"


def _derive_vector_expected(case: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if case == "unicode-equivalence":
        left = canonical_json(parse_json(inputs["leftJson"]))
        right = canonical_json(parse_json(inputs["rightJson"]))
        path_left = prepare_path_resource(
            inputs["pathNfc"],
            cwd=inputs["cwd"],
        )
        path_right = prepare_path_resource(
            inputs["pathNfd"],
            cwd=inputs["cwd"],
        )
        url_left = prepare_url_resource(inputs["urlNfc"])
        url_right = prepare_url_resource(inputs["urlNfd"])
        shell_left = prepare_shell_resource(inputs["shellNfc"])
        shell_right = prepare_shell_resource(inputs["shellNfd"])
        mcp_left = prepare_mcp_resource(
            inputs["mcpServer"],
            inputs["mcpTool"],
            parse_json(inputs["mcpLeftJson"]),
        )
        mcp_right = prepare_mcp_resource(
            inputs["mcpServer"],
            inputs["mcpTool"],
            parse_json(inputs["mcpRightJson"]),
        )
        return {
            "canonicalUtf8": left.decode(),
            "hash": canonical_hash(left),
            "jsonEqual": left == right,
            "scalarOrderCanonical": canonical_json(
                parse_json(inputs["scalarOrderJson"])
            ).decode(),
            "pathExecutions": [path_left.execution, path_right.execution],
            "pathEqual": path_left == path_right,
            "urlExecutions": [url_left.execution, url_right.execution],
            "urlEqual": url_left == url_right,
            "shellExecutions": [shell_left.execution, shell_right.execution],
            "shellResourcesEqual": shell_left.resource == shell_right.resource,
            "mcpResources": [mcp_left.resource, mcp_right.resource],
            "mcpEqual": mcp_left.resource == mcp_right.resource,
        }
    if case == "duplicate-keys":
        return {
            "errorCodes": [
                _error_code(lambda source=source: parse_json(source))
                for source in inputs["rawJson"]
            ]
        }
    if case == "numeric-portability":
        return {
            "canonical": [
                canonical_json(parse_json(source)).decode()
                for source in inputs["acceptedJson"]
            ],
            "rejectedErrorCodes": [
                _error_code(lambda source=source: parse_json(source))
                for source in inputs["rejectedJson"]
            ],
        }
    if case == "idna2008-a-label":
        return {
            "canonical": [canonicalize_url(value) for value in inputs["accepted"]],
            "rejectedErrorCodes": [
                _error_code(lambda value=value: canonicalize_url(value))
                for value in inputs["rejected"]
            ],
        }
    if case == "url-credential-binding":
        first = prepare_url_resource(inputs["first"])
        second = prepare_url_resource(inputs["second"])
        first_resource = parse_json(first.resource)
        second_resource = parse_json(second.resource)
        return {
            "diagnosticUrls": [first_resource["url"], second_resource["url"]],
            "resourcesEqual": first.resource == second.resource,
            "executionHashesEqual": (
                first_resource["executionHash"] == second_resource["executionHash"]
            ),
            "executorReceivesCanonical": True,
        }
    if case == "path-traversal-symlink-policy":
        canonical = [
            canonicalize_path(item["path"], cwd=item["cwd"]) for item in inputs["cases"]
        ]
        collisions = []
        for pair in inputs["collisionPairs"]:
            left = canonicalize_path(pair["left"], cwd=pair["cwd"])
            right = canonicalize_path(pair["right"], cwd=pair["cwd"])
            collisions.append({"left": left, "right": right, "equal": left == right})
        return {
            "canonical": canonical,
            "collisions": collisions,
            "physicalTargetClaimed": False,
            "executorMustUseCanonical": True,
        }
    if case == "url-normalization-policy":
        canonical = [canonicalize_url(value) for value in inputs["accepted"]]
        collisions = []
        for pair in inputs["collisionPairs"]:
            left = canonicalize_url(pair["left"])
            right = canonicalize_url(pair["right"])
            collisions.append({"left": left, "right": right, "equal": left == right})
        return {
            "canonical": canonical,
            "collisions": collisions,
            "rejectedErrorCodes": [
                _error_code(lambda value=value: canonicalize_url(value))
                for value in inputs["rejected"]
            ],
        }
    if case == "shell-redaction-collision-resistance":
        names = set(inputs["additionalSensitiveNames"])
        first = canonicalize_shell(
            inputs["first"],
            additional_sensitive_names=names,
        )
        second = canonicalize_shell(
            inputs["second"],
            additional_sensitive_names=names,
        )
        return {
            "first": first,
            "second": second,
            "sameRedactedTokens": first["tokens"] == second["tokens"],
            "differentCommandHashes": (first["commandHash"] != second["commandHash"]),
        }
    if case == "mcp-nested-json":
        left_input = parse_json(inputs["leftJson"])
        right_input = parse_json(inputs["rightJson"])
        left = canonicalize_mcp(inputs["server"], inputs["tool"], left_input)
        right = canonicalize_mcp(inputs["server"], inputs["tool"], right_input)
        return {
            "leftCanonicalInput": canonical_json(left_input).decode(),
            "rightCanonicalInput": canonical_json(right_input).decode(),
            "leftResource": left,
            "rightResource": right,
            "equal": left == right,
        }
    if case == "missing-vs-null":
        missing = canonical_json(parse_json(inputs["missingJson"]))
        explicit_null = canonical_json(parse_json(inputs["nullJson"]))
        return {
            "missingCanonical": missing.decode(),
            "nullCanonical": explicit_null.decode(),
            "missingHash": canonical_hash(missing),
            "nullHash": canonical_hash(explicit_null),
            "equal": missing == explicit_null,
        }
    if case == "adapter-client-trust-boundary":
        action = inputs["action"]
        adapter_mutation = inputs["adapterMutation"]
        trusted = inputs["trusted"]
        client_mutation = inputs["trustedClientMutation"]
        return {
            "clientScopeInput": client_scope_input(action),
            "authoritativeScopeInput": authoritative_scope_input(action, trusted),
            "clientScopeHash": client_scope_hash(action),
            "authoritativeScopeHash": authoritative_scope_hash(action, trusted),
            "changedAdapterClientScopeHash": client_scope_hash(adapter_mutation),
            "changedTrustedClientAuthoritativeScopeHash": (
                authoritative_scope_hash(action, client_mutation)
            ),
        }
    if case == "resource-preimage-binding":
        target = inputs["target"]
        mutation = inputs["resourceMutation"]
        return {
            "preimage": resource_hash_input(target),
            "resourceHash": computed_resource_hash(target),
            "validatedTarget": validated_target(target),
            "mutationErrorCode": _error_code(lambda: validated_target(mutation)),
        }
    raise CanonicalizationError("unknown_vector", "unknown vector case")


def _vectors() -> dict[str, dict[str, Any]]:
    action = _vector_action()
    trusted = _vector_trusted()
    other_adapter = deepcopy(action)
    other_adapter["adapter"]["id"] = "claude-code"
    other_client = dict(trusted)
    other_client["clientId"] = "registered-claude"
    resource_mutation = deepcopy(action["target"])
    resource_mutation["resource"] = "path:/workspace/deploy/staging.yaml"

    return {
        "unicode-equivalence.json": _vector(
            "unicode-equivalence",
            "pinned Unicode NFC and scalar ordering across every resource family",
            {
                "leftJson": '{"e\\u0301":"Cafe\\u0301","z":1}',
                "rightJson": '{"z":1.0,"\\u00e9":"Caf\\u00e9"}',
                "scalarOrderJson": '{"\\ud800\\udc00":2,"\\ue000":1}',
                "cwd": "/workspace",
                "pathNfc": "Café/résumé.txt",
                "pathNfd": "Cafe\u0301/re\u0301sume\u0301.txt",
                "urlNfc": "https://example.com/Caf%C3%A9?q=r%C3%A9sum%C3%A9",
                "urlNfd": "https://example.com/Cafe%CC%81?q=re%CC%81sume%CC%81",
                "shellNfc": "printf 'Café'",
                "shellNfd": "printf 'Cafe\u0301'",
                "mcpServer": "github",
                "mcpTool": "issues.create",
                "mcpLeftJson": '{"title":"Café","nested":{"b":2,"a":1}}',
                "mcpRightJson": ('{"nested":{"a":1.0,"b":2},"title":"Cafe\\u0301"}'),
            },
        ),
        "duplicate-keys.json": _vector(
            "duplicate-keys",
            "duplicate object keys fail after NFC normalization",
            {
                "rawJson": [
                    '{"scope":1,"scope":2}',
                    '{"e\\u0301":1,"\\u00e9":2}',
                ]
            },
        ),
        "numeric-portability.json": _vector(
            "numeric-portability",
            "exact raw decimals normalize and concrete invalid forms fail closed",
            {
                "acceptedJson": ["1.2300", "1e3", "-0.000", "1e-3"],
                "rejectedJson": [
                    "NaN",
                    "1e309",
                    "1e-309",
                    "1." + ("2" * 128),
                    "1e999999999999999999999999999999999999",
                ],
            },
        ),
        "idna2008-a-label.json": _vector(
            "idna2008-a-label",
            "strict IDNA2008 A-label validation without UTS 46 mapping",
            {
                "accepted": [
                    "https://example.com/",
                    "https://XN--BCHER-KVA.example/",
                    "https://xn--8g0n.example/",
                ],
                "rejected": [
                    "https://xn--a.example/",
                    "https://xn--0.example/",
                    "https://xn--a-ecp.example/",
                    "https://xn--1ug.example/",
                ],
            },
        ),
        "path-traversal-symlink-policy.json": _vector(
            "path-traversal-symlink-policy",
            "absolute POSIX lexical scope; no symlink or filesystem resolution",
            {
                "cases": [
                    {
                        "cwd": "/workspace/project",
                        "path": "src/../deploy/./production.yaml",
                    },
                    {
                        "cwd": "/workspace/project",
                        "path": "../../shared/policy.rego",
                    },
                    {
                        "cwd": "/workspace/project",
                        "path": "/workspace/link/../secret.txt",
                    },
                ],
                "collisionPairs": [
                    {
                        "cwd": "/workspace",
                        "left": "link/../target.txt",
                        "right": "target.txt",
                    },
                    {
                        "cwd": "/workspace",
                        "left": "Cafe\u0301.txt",
                        "right": "Café.txt",
                    },
                ],
            },
        ),
        "url-normalization-policy.json": _vector(
            "url-normalization-policy",
            "strict authority, empty paths, reserved escapes, and query ordering",
            {
                "accepted": [
                    (
                        "HTTPS://Example.COM:443/a/../b?"
                        "z=last&token=secret&a=2&a=1#fragment"
                    ),
                    "https://example.com/a//b",
                    "https://example.com/a%2fb",
                ],
                "collisionPairs": [
                    {
                        "left": "https://example.com/?b=3&a=2&a=1",
                        "right": "https://example.com/?a=2&a=1&b=3",
                    },
                    {
                        "left": "https://example.com/?a=2&a=1",
                        "right": "https://example.com/?a=1&a=2",
                    },
                    {
                        "left": "https://example.com/a//b",
                        "right": "https://example.com/a/b",
                    },
                    {
                        "left": "https://example.com/a%2Fb",
                        "right": "https://example.com/a/b",
                    },
                ],
                "rejected": [
                    "https://user:secret@example.com/",
                    "https://example.com./",
                    "https://bad_host.example/",
                    "https://127.1/",
                    "https://[2001:db8::1]/",
                    "https:\\\\example.com\\path",
                ],
            },
        ),
        "url-credential-binding.json": _vector(
            "url-credential-binding",
            "redacted diagnostics plus a domain-separated full execution binding",
            {
                "first": "https://example.com/run?token=synthetic-alpha",
                "second": "https://example.com/run?token=synthetic-bravo",
            },
        ),
        "shell-redaction-collision-resistance.json": _vector(
            "shell-redaction-collision-resistance",
            "safe tokens redact known secrets; "
            "full normalized command hash binds scope",
            {
                "first": (
                    "deploy --tenant-secret alpha TENANT_SECRET=bravo "
                    "--tenant-secret=charlie --token mandatory"
                ),
                "second": (
                    "deploy --tenant-secret delta TENANT_SECRET=echo "
                    "--tenant-secret=foxtrot --token changed"
                ),
                "additionalSensitiveNames": ["tenant_secret"],
            },
        ),
        "mcp-nested-json.json": _vector(
            "mcp-nested-json",
            "server-qualified tool plus canonical nested JSON input hash",
            {
                "server": "github",
                "tool": "issues.create",
                "leftJson": (
                    '{"labels":["security","agent"],'
                    '"issue":{"title":"Cafe\\u0301","priority":1.0}}'
                ),
                "rightJson": (
                    '{"issue":{"priority":1,"title":"Café"},'
                    '"labels":["security","agent"]}'
                ),
            },
        ),
        "missing-vs-null.json": _vector(
            "missing-vs-null",
            "absent object values are omitted; explicit null remains in scope",
            {
                "missingJson": '{"required":"value"}',
                "nullJson": '{"required":"value","optional":null}',
            },
        ),
        "adapter-client-trust-boundary.json": _vector(
            "adapter-client-trust-boundary",
            "diagnostic adapter binds client scope; trusted clientId is server-only",
            {
                "action": action,
                "adapterMutation": other_adapter,
                "trusted": trusted,
                "trustedClientMutation": other_client,
            },
        ),
        "resource-preimage-binding.json": _vector(
            "resource-preimage-binding",
            "typed resource preimage rejects a resource mutation with a stale hash",
            {
                "target": action["target"],
                "resourceMutation": resource_mutation,
            },
        ),
    }


def _vector_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def render_vectors() -> dict[str, bytes]:
    """Render every committed canonicalization vector deterministically."""

    return {name: _vector_bytes(value) for name, value in sorted(_vectors().items())}


def _diff_vector_values(
    actual: Any,
    expected: Any,
    *,
    path: str = "expected",
) -> list[str]:
    if isinstance(actual, dict) and isinstance(expected, dict):
        errors: list[str] = []
        for key in sorted(set(actual) | set(expected)):
            child = f"{path}.{key}"
            if key not in actual:
                errors.append(f"{child}: missing")
            elif key not in expected:
                errors.append(f"{child}: unexpected")
            else:
                errors.extend(
                    _diff_vector_values(actual[key], expected[key], path=child)
                )
        return errors
    if isinstance(actual, list) and isinstance(expected, list):
        if len(actual) != len(expected):
            return [f"{path}: list length differs"]
        errors = []
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            errors.extend(_diff_vector_values(left, right, path=f"{path}[{index}]"))
        return errors
    return [] if actual == expected else [f"{path}: value differs"]


def verify_vector(vector: Mapping[str, Any]) -> list[str]:
    case = vector.get("case")
    inputs = vector.get("inputs")
    if not isinstance(case, str) or not isinstance(inputs, Mapping):
        return ["vector case or inputs are invalid"]
    try:
        recomputed = _derive_vector_expected(case, inputs)
    except CanonicalizationError as exc:
        return [f"vector recomputation failed: {exc.code}"]
    return _diff_vector_values(vector.get("expected"), recomputed)


def write_vectors() -> None:
    VECTORS.mkdir(parents=True, exist_ok=True)
    rendered = render_vectors()
    for stale in VECTORS.glob("*.json"):
        if stale.name not in rendered:
            stale.unlink()
    for name, contents in rendered.items():
        (VECTORS / name).write_bytes(contents)
    print(f"wrote {len(rendered)} canonicalization vectors")


def check_vectors() -> bool:
    generated = _vectors()
    expected_names = set(generated)
    paths = sorted(VECTORS.glob("*.json"))
    actual_names = {path.name for path in paths}
    errors = [
        f"missing vector: {name}" for name in sorted(expected_names - actual_names)
    ]
    errors.extend(
        f"unexpected vector: {name}" for name in sorted(actual_names - expected_names)
    )
    for path in paths:
        try:
            document = parse_json(path.read_bytes())
        except CanonicalizationError as exc:
            errors.append(f"{path.name}: invalid vector JSON: {exc.code}")
            continue
        if not isinstance(document, Mapping):
            errors.append(f"{path.name}: vector is not an object")
            continue
        baseline = generated.get(path.name)
        if baseline is not None:
            source_fields = {
                key: value for key, value in document.items() if key != "expected"
            }
            baseline_fields = {
                key: value for key, value in baseline.items() if key != "expected"
            }
            if source_fields != baseline_fields:
                errors.append(f"{path.name}: committed raw inputs drifted")
        errors.extend(f"{path.name}: {error}" for error in verify_vector(document))
        if _vector_bytes(document) != path.read_bytes():
            errors.append(f"{path.name}: nondeterministic vector formatting")
    if errors:
        print("canonicalization vector drift:")
        for error in errors:
            print(f"- {error}")
        return False
    print("canonicalization vectors are current")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify draft protocol canonicalization vectors."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-vectors", action="store_true")
    mode.add_argument("--check-vectors", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.write_vectors:
        write_vectors()
        return 0
    return 0 if check_vectors() else 1


if __name__ == "__main__":
    sys.exit(main())
