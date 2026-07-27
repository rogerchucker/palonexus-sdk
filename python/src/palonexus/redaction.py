# SPDX-License-Identifier: MIT
"""Bounded, cycle-safe redaction for application diagnostics."""

from __future__ import annotations

import math
import re
import shlex
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Final, cast
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from . import _canonicalize

REDACTED: Final = "[REDACTED]"
_CONTROL: Final = "[CONTROL]"
_CYCLE: Final = "[CYCLE]"
_MAX_DEPTH: Final = "[MAX_DEPTH]"
_LIMIT: Final = "[LIMIT]"
_TRUNCATED: Final = "[TRUNCATED]"
_UNPARSEABLE: Final = "[UNPARSEABLE]"

_PORTABLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"(?![A-Za-z0-9_-])"
)
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/\-=]{4,}")
_NAMED_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>[^\s,;&:=]{1,256})(?P<separator>\s*[:=]\s*)"
    r"(?P<value>(?:Bearer|Basic)\s+[^\s,;&]+|\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_TOKEN_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:sk|pk|ghp|gho|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}"
    r"|[A-Za-z0-9][A-Za-z0-9+/_=-]{23,}"
    r")(?![A-Za-z0-9])"
)

_MANDATORY_NAMES: Final = frozenset(
    {
        "access-key",
        "access-token",
        "api-key",
        "apikey",
        "authorization",
        "client-secret",
        "code",
        "cookie",
        "credential",
        "password",
        "passwd",
        "proxy-authorization",
        "secret",
        "set-cookie",
        "signature",
        "token",
        "x-access-token",
        "x-api-key",
    }
)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def _default_ignorable(character: str) -> bool:
    value = ord(character)
    return (
        unicodedata.category(character) in {"Cc", "Cf"}
        or 0xFE00 <= value <= 0xFE0F
        or 0xE0100 <= value <= 0xE01EF
    )


def _bounded_percent_decode(value: str, *, max_length: int) -> tuple[str, bool]:
    if type(value) is not str or len(value) > max_length:
        return "", True
    current = value
    for _ in range(3):
        try:
            decoded = unquote(current, encoding="utf-8", errors="strict")
        except UnicodeError:
            # A layer may expose only the lead byte of a still-encoded UTF-8
            # sequence. Peel escaped percent signs without accepting malformed
            # final text, then validate normally on the next bounded round.
            decoded = re.sub(r"(?i)%25", "%", current)
        except ValueError:
            return "", True
        if len(decoded) > max_length:
            return "", True
        if decoded == current:
            break
        current = decoded
    return current, _PERCENT_ESCAPE.search(current) is not None


def _normalize_name(value: str) -> str:
    if type(value) is not str:
        raise ValueError("invalid sensitive name")
    if len(value) > 256:
        raise ValueError("invalid sensitive name")
    decoded, unresolved = _bounded_percent_decode(value, max_length=256)
    if unresolved:
        raise ValueError("unresolved sensitive name encoding")
    normalized = "".join(
        character for character in decoded if not _default_ignorable(character)
    )
    normalized = normalized.strip().lstrip("-")
    if (
        not normalized
        or not normalized.isascii()
        or _PORTABLE_NAME.fullmatch(normalized) is None
    ):
        raise ValueError("invalid sensitive name")
    return normalized.lower().replace("_", "-")


def _has_control(value: str) -> bool:
    return any(
        _default_ignorable(character)
        or ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or ord(character)
        in {
            0x061C,
            0x200E,
            0x200F,
            0x2028,
            0x2029,
            0x202A,
            0x202B,
            0x202C,
            0x202D,
            0x202E,
            0x2066,
            0x2067,
            0x2068,
            0x2069,
        }
        for character in value
    )


def _replace_controls(value: str) -> str:
    return "".join(
        _CONTROL if _has_control(character) else character for character in value
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_like_secret(value: str) -> bool:
    if len(value) < 24:
        return False
    classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        )
    )
    return classes >= 2 and len(set(value)) >= 10 and _entropy(value) >= 3.5


def _redact_candidates(match: re.Match[str]) -> str:
    value = match.group(0)
    return REDACTED if _looks_like_secret(value) else value


class Redactor:
    """Return safe primitive diagnostics without mutating caller input.

    The mandatory names include the protocol-v1 URL and shell redaction set.
    Deployments can extend but cannot remove that set.
    """

    __slots__ = (
        "_max_depth",
        "_max_items",
        "_max_nodes",
        "_max_query_pairs",
        "_max_string_length",
        "_max_total_bytes",
        "_names",
    )

    _names: frozenset[str]
    _max_depth: int
    _max_items: int
    _max_nodes: int
    _max_query_pairs: int
    _max_string_length: int
    _max_total_bytes: int

    def __init__(
        self,
        *,
        additional_sensitive_names: set[str] | frozenset[str] = frozenset(),
        max_depth: int = 8,
        max_items: int = 128,
        max_nodes: int = 4096,
        max_total_bytes: int = 262_144,
        max_string_length: int = 4096,
        max_query_pairs: int = 128,
    ) -> None:
        failed = False
        names: set[str] = set(_MANDATORY_NAMES)
        try:
            if (
                isinstance(max_depth, bool)
                or not isinstance(max_depth, int)
                or max_depth < 1
                or max_depth > 32
                or isinstance(max_items, bool)
                or not isinstance(max_items, int)
                or max_items < 1
                or max_items > 4096
                or isinstance(max_nodes, bool)
                or not isinstance(max_nodes, int)
                or max_nodes < 1
                or max_nodes > 1_000_000
                or isinstance(max_total_bytes, bool)
                or not isinstance(max_total_bytes, int)
                or max_total_bytes < 16
                or max_total_bytes > 16_777_216
                or isinstance(max_string_length, bool)
                or not isinstance(max_string_length, int)
                or max_string_length < 16
                or max_string_length > 65536
                or isinstance(max_query_pairs, bool)
                or not isinstance(max_query_pairs, int)
                or max_query_pairs < 1
                or max_query_pairs > 4096
            ):
                raise ValueError
            for name in additional_sensitive_names:
                names.add(_normalize_name(name))
        except Exception:
            failed = True
        if failed:
            raise ValueError("invalid redaction policy") from None
        object.__setattr__(self, "_names", frozenset(names))
        object.__setattr__(self, "_max_depth", max_depth)
        object.__setattr__(self, "_max_items", max_items)
        object.__setattr__(self, "_max_nodes", max_nodes)
        object.__setattr__(self, "_max_total_bytes", max_total_bytes)
        object.__setattr__(self, "_max_string_length", max_string_length)
        object.__setattr__(self, "_max_query_pairs", max_query_pairs)

    def _sensitive_name(self, value: str) -> bool:
        if type(value) is not str:
            return True
        if len(value) > 256:
            return True
        _decoded, unresolved = _bounded_percent_decode(value, max_length=256)
        if unresolved:
            return True
        try:
            normalized = _normalize_name(value)
        except ValueError:
            return False
        return normalized in self._names

    def redact_text(self, value: str) -> str:
        """Redact credential forms and neutralize log-control characters."""

        if type(value) is not str:
            return REDACTED
        if len(value) > self._max_string_length:
            return _TRUNCATED
        comparison, unresolved = _bounded_percent_decode(
            value,
            max_length=self._max_string_length,
        )
        comparison = "".join(
            character for character in comparison if not _default_ignorable(character)
        )
        if not unresolved and comparison != value:
            for match in _NAMED_ASSIGNMENT.finditer(comparison):
                if self._sensitive_name(match.group("name")):
                    return REDACTED
        rendered = _replace_controls(value)
        rendered = _JWT.sub(REDACTED, rendered)

        def redact_assignment(match: re.Match[str]) -> str:
            if not self._sensitive_name(match.group("name")):
                return match.group(0)
            return f"{match.group('name')}{match.group('separator')}{REDACTED}"

        rendered = _NAMED_ASSIGNMENT.sub(redact_assignment, rendered)
        rendered = _AUTH_SCHEME.sub(
            lambda match: f"{match.group(1)} {REDACTED}",
            rendered,
        )
        rendered = _TOKEN_CANDIDATE.sub(_redact_candidates, rendered)
        return rendered

    def redact_headers(self, headers: Mapping[str, object]) -> dict[str, str]:
        """Return a copied, safe header mapping."""

        output: dict[str, str] = {}
        try:
            items = headers.items()
            for index, (raw_name, raw_value) in enumerate(items):
                if index >= self._max_items:
                    output[_TRUNCATED] = _TRUNCATED
                    break
                if type(raw_name) is not str:
                    output[REDACTED] = REDACTED
                    continue
                if len(raw_name) > self._max_string_length:
                    output[REDACTED] = REDACTED
                    continue
                name = self.redact_text(raw_name)
                if self._sensitive_name(raw_name):
                    output[name] = REDACTED
                elif type(raw_value) is str:
                    output[name] = (
                        _TRUNCATED
                        if len(raw_value) > self._max_string_length
                        else self.redact_text(raw_value)
                    )
                else:
                    output[name] = REDACTED
        except Exception:
            return {REDACTED: REDACTED}
        return output

    def redact_query(self, query: Mapping[str, object]) -> dict[str, object]:
        """Return a copied query mapping with mandatory values removed."""

        output: dict[str, object] = {}
        try:
            items = query.items()
            for index, (raw_name, raw_value) in enumerate(items):
                if index >= self._max_items:
                    output[_TRUNCATED] = _TRUNCATED
                    break
                if type(raw_name) is not str:
                    output[REDACTED] = REDACTED
                    continue
                if len(raw_name) > self._max_string_length:
                    output[REDACTED] = REDACTED
                    continue
                name = self.redact_text(raw_name)
                if self._sensitive_name(raw_name):
                    output[name] = REDACTED
                elif type(raw_value) is str:
                    decoded, unresolved = _bounded_percent_decode(
                        raw_value, max_length=self._max_string_length
                    )
                    output[name] = REDACTED if unresolved else self.redact_text(decoded)
                else:
                    output[name] = self.redact(raw_value)
        except Exception:
            return {REDACTED: REDACTED}
        return output

    def redact_url(self, value: str) -> str:
        """Return a credential-free HTTP(S) diagnostic URL."""

        if (
            type(value) is not str
            or len(value) > self._max_string_length
            or _has_control(value)
        ):
            return "[URL]"
        failed = False
        rendered = "[URL]"
        try:
            parts = urlsplit(value)
            field_length = 0
            field_count = 1
            for character in parts.query:
                if character in {"&", ";"}:
                    field_count += 1
                    field_length = 0
                else:
                    field_length += 1
                if (
                    field_length > self._max_string_length
                    or field_count > self._max_query_pairs
                ):
                    raise ValueError
            if (
                len(parts.query) > self._max_string_length
                or parts.query.count("&") + parts.query.count(";")
                >= self._max_query_pairs
            ):
                raise ValueError
            scheme = parts.scheme.lower()
            if scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError
            host = parts.hostname.lower()
            port = parts.port
            if ":" in host:
                host = f"[{host}]"
            netloc = host if port is None else f"{host}:{port}"
            path_text = self.redact_text(parts.path or "/")
            path = quote(path_text, safe="/:@-._~!$&'()*+,;=%")
            query_values: list[tuple[str, str]] = []
            parsed_query = parse_qsl(
                parts.query,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=self._max_query_pairs,
            )
            for index, (raw_name, raw_value) in enumerate(parsed_query):
                if index >= min(self._max_items, self._max_query_pairs):
                    raise ValueError
                name = self.redact_text(raw_name)
                decoded_value, unresolved = _bounded_percent_decode(
                    raw_value, max_length=self._max_string_length
                )
                item = REDACTED
                if not self._sensitive_name(raw_name) and not unresolved:
                    item = self.redact_text(decoded_value)
                query_values.append((name, item))
            candidate = urlunsplit(
                (
                    scheme,
                    netloc,
                    path,
                    urlencode(query_values, doseq=True),
                    "",
                )
            )
            rendered = _canonicalize.canonicalize_url(
                candidate,
                sensitive_query_keys=self._names,
            )
        except Exception:
            failed = True
        return "[URL]" if failed else rendered

    def redact_shell(self, command: str) -> list[str]:
        """Return protocol-v1 redacted shell tokens, further pattern-scrubbed."""

        if type(command) is not str or len(command) > self._max_string_length:
            return [_UNPARSEABLE]
        try:
            tokens = shlex.split(command, posix=True)
        except Exception:
            return [_UNPARSEABLE]
        if len(tokens) > self._max_items:
            return [_UNPARSEABLE]

        output: list[str] = []
        redact_next = False
        header_next = False
        for token in tokens:
            if type(token) is not str or len(token) > self._max_string_length:
                return [_UNPARSEABLE]
            if redact_next or header_next:
                output.append(REDACTED)
                redact_next = False
                header_next = False
                continue
            if token in {"-H", "--header"}:
                output.append(token)
                header_next = True
                continue
            if token.startswith("--header="):
                output.append(f"--header={REDACTED}")
                continue
            if token.startswith("-H") and len(token) > 2:
                output.append(f"-H{REDACTED}")
                continue
            if token.lower().startswith(("http://", "https://")):
                output.append(self.redact_url(token))
                continue
            name, separator, _raw_value = token.partition("=")
            if separator and self._sensitive_name(name):
                output.append(f"{name}={REDACTED}")
                continue
            if self._sensitive_name(token):
                output.append(self.redact_text(token))
                redact_next = True
                continue
            output.append(self.redact_text(token))
        if redact_next or header_next:
            output.append(REDACTED)
        return output

    def redact(self, value: object) -> object:
        """Create one bounded, iterative snapshot of nested diagnostics."""

        holder: list[object] = [REDACTED]
        snapshots: dict[int, tuple[str, tuple[object, ...], bool]] = {}
        stack: list[
            tuple[
                object,
                int,
                frozenset[int],
                list[object] | dict[str, object],
                int | str,
            ]
        ] = [(value, 0, frozenset(), holder, 0)]
        nodes = 0
        used_bytes = 0

        def assign(
            target: list[object] | dict[str, object],
            key: int | str,
            item: object,
        ) -> None:
            target[key] = item  # type: ignore[index]

        def charge_text(item: str) -> bool:
            nonlocal used_bytes
            if len(item) > self._max_string_length:
                return False
            amount = 0
            for character in item:
                codepoint = ord(character)
                amount += (
                    1
                    if codepoint <= 0x7F
                    else 2
                    if codepoint <= 0x7FF
                    else 3
                    if codepoint <= 0xFFFF
                    else 4
                )
                if used_bytes + amount > self._max_total_bytes:
                    return False
            used_bytes += amount
            return True

        while stack:
            item, depth, path, target, key = stack.pop()
            nodes += 1
            if nodes > self._max_nodes:
                assign(target, key, _LIMIT)
                continue
            if item is None or type(item) in {bool, int}:
                assign(target, key, item)
                continue
            if type(item) is float:
                assign(target, key, item if math.isfinite(item) else REDACTED)
                continue
            if type(item) is str:
                assign(
                    target,
                    key,
                    self.redact_text(item) if charge_text(item) else _LIMIT,
                )
                continue
            if isinstance(item, (bytes, bytearray, memoryview)):
                assign(target, key, REDACTED)
                continue
            if depth >= self._max_depth:
                assign(target, key, _MAX_DEPTH)
                continue
            if not isinstance(item, (Mapping, Sequence)):
                assign(target, key, REDACTED)
                continue

            identity = id(item)
            if identity in path:
                assign(target, key, _CYCLE)
                continue
            snapshot = snapshots.get(identity)
            if snapshot is None:
                try:
                    if isinstance(item, Mapping):
                        captured: list[object] = []
                        iterator = iter(item.items())
                        truncated = False
                        for index, pair in enumerate(iterator):
                            if index >= self._max_items:
                                truncated = True
                                break
                            if not isinstance(pair, tuple) or len(pair) != 2:
                                raise TypeError
                            captured.append(pair)
                        snapshot = ("mapping", tuple(captured), truncated)
                    else:
                        captured = []
                        iterator = iter(item)
                        truncated = False
                        for index, child in enumerate(iterator):
                            if index >= self._max_items:
                                truncated = True
                                break
                            captured.append(child)
                        snapshot = ("sequence", tuple(captured), truncated)
                    snapshots[identity] = snapshot
                except Exception:
                    assign(target, key, REDACTED)
                    continue

            kind, captured_items, truncated = snapshot
            child_path = path | {identity}
            if kind == "mapping":
                output_mapping: dict[str, object] = {}
                assign(target, key, output_mapping)
                if truncated:
                    output_mapping[_TRUNCATED] = _TRUNCATED
                pending: list[tuple[object, str]] = []
                for raw_pair in captured_items:
                    raw_key, mapping_child = cast(
                        tuple[object, object],
                        raw_pair,
                    )
                    if type(raw_key) is not str or not charge_text(raw_key):
                        safe_key = REDACTED
                    else:
                        safe_key = self.redact_text(raw_key)
                    while safe_key in output_mapping:
                        safe_key = f"{safe_key}[DUPLICATE]"
                    output_mapping[safe_key] = REDACTED
                    if type(raw_key) is not str or self._sensitive_name(raw_key):
                        continue
                    pending.append((mapping_child, safe_key))
                for pending_child, safe_key in reversed(pending):
                    stack.append(
                        (
                            pending_child,
                            depth + 1,
                            child_path,
                            output_mapping,
                            safe_key,
                        )
                    )
            else:
                output_sequence: list[object] = [REDACTED for _ in captured_items]
                if truncated:
                    output_sequence.append(_TRUNCATED)
                assign(target, key, output_sequence)
                for index in range(len(captured_items) - 1, -1, -1):
                    stack.append(
                        (
                            captured_items[index],
                            depth + 1,
                            child_path,
                            output_sequence,
                            index,
                        )
                    )

        return holder[0]

    def __repr__(self) -> str:
        return (
            "Redactor("
            f"max_depth={self._max_depth}, "
            f"max_items={self._max_items}, "
            f"max_nodes={self._max_nodes}, "
            f"max_total_bytes={self._max_total_bytes}, "
            f"max_string_length={self._max_string_length})"
        )


__all__ = ["REDACTED", "Redactor"]
