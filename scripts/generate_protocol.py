#!/usr/bin/env python3
# ruff: noqa: E501
"""Generate deterministic Python and Go structural DTOs from protocol schemas."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

GENERATOR_VERSION = "2"
MAX_RUNTIME_STRING_BYTES = 8_192
REVIEWED_PATTERN_DIGESTS_V2 = frozenset(
    {
        "0439e4f1ac4c4bf739a810c6967a802549d4cb7ed911500a29af8fad905f6f0d",
        "0546595ebdf758bfb3307e124ac04e624b1b85f74781130c8b2770aab0459d0d",
        "0ccc27ef531dc450711369ab164570678099c1ce51203e757a86e8391b7fe44f",
        "0d0927cb4a04035fd34b1a0462610ecbf51233ee264a493bfea7cd175a013453",
        "131b125764f3da405f39a84f60c11e464d67bf9a0bdee295bc8b57e06c3af2f6",
        "16995d82cd30c455b5f8157277cfaed2467b6065225431bcc42a48c95bdbe69c",
        "209bd7567538f1912e0656b452ff8b95e46e42970d1a28327c8cfcc0a958270e",
        "22bb28ae3df406a72f09ee8de4820c193ce18660d751b4aeacab8e1f03a6bf3e",
        "22f41c0827b92a607f9719726028f4e90c09e741cd62d8ee102e52d8ada7c919",
        "3e94e5276bb467d38306f57d5512c0930f7ecb1cfff633d1e9bb35f98daf9c9a",
        "4772bd12041c326822e4980a64e28717ad6445c56fab19717b4a84b0e6553e12",
        "50c5de9b292c5a5f41229ec9679f04c85e2cfec5bc767e2044d7a287dbb5b103",
        "6f683835550aa47aac75f7f0e2dcf36c77010a0c8a1186515b6595deb63b006e",
        "7ea85d36e7ccf8fffe123fee96c218bd8a82acafef1f55908a671e246e75a215",
        "924696fa664879175d7c7dc9d29546047e2f028735fbb56e54342627e1cdf0d3",
        "a6f1b312e2abd90a194156ce8cbe2f00231b335382c7ef692d8cd33913938a0e",
        "b784e28149052146b8142fca3ff3741ec4e44ff1b4065c07b109f370675d0923",
        "b9ad157e3b51da366e8767f23335a93577031c39172eb0665c37140db3518aee",
        "bc1445f03c701ca917c89f5c4406d27d0332bbba9bb43b59f02fab52e09f77b2",
        "bfad10bc904a2491b5ef5b6870fba321258ccf265fc0c493a4523580b34409e7",
        "c0de6851a7550192f49b2e75630c7e5772ceb4c0e8da14b3597b33a660815c4d",
        "c5174ea2dece20037ab626b919af89c0db7e5c99ffcb52742a7080e9d015c4e9",
        "d0aa0cf377ed6f8d1c95394502ab908ceafc317c6be1c7bcf4215b3b418ca4ce",
        "d9bd1ec0a09bf273a16b1b462a0cbe71e781ecc06be7bff569e222aa0dc2d715",
        "e1c36482d5343006635d0c311f137c999e0bcc1db2ff703b1dc2c215c46123e9",
        "ec92a5860dc5b12066728c393c3f6ae2a2def44492b1e0d9a7987bb0d3e31b56",
        "ecb688ba169e2bd044bbb6c286f9a3949988409d9b5703a2625ce3c403655d38",
        "feb953cfbf73c949ec8277e6718f8be5022ac7bdb25051478b33c73454e1421a",
    }
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA_ROOT = REPOSITORY_ROOT / "protocol" / "schemas"
PYTHON_OUTPUT = Path("python/src/palonexus/_generated/protocol.py")
GO_OUTPUT = Path("guard/pkg/protocol/generated.go")
SCHEMA_FILES = (
    "common-v1.schema.json",
    "action-v1.schema.json",
    "decision-v1.schema.json",
    "approval-v1.schema.json",
    "error-v1.schema.json",
    "reconciliation-v1.schema.json",
)
ROOT_CLASS_NAMES = {
    "action": "ActionRequest",
    "decision": "AuthorizationDecision",
    "approval": "ApprovalRecord",
    "error": "ProtocolError",
    "reconciliation": "ReconciliationRecord",
}
COMMON_OBJECTS = {
    "adapter": "Adapter",
    "task": "TaskBinding",
    "target": "ActionTarget",
    "context": "ActionContext",
    "approvalSummary": "ApprovalSummary",
    "cacheDirective": "CacheDirective",
}
DIRECT_OBJECTS = {
    ("reconciliation", "deliveryPolicy"): "DeliveryPolicy",
    ("reconciliation", "acknowledgement"): "ReconciliationAcknowledgement",
    ("reconciliation", "discard"): "ReconciliationDiscard",
}
STRING_REF_NAMES = {
    ("common", "schemaVersion"): "SchemaVersion",
    ("common", "actionId"): "ActionID",
    ("common", "requestId"): "RequestID",
    ("common", "correlationId"): "CorrelationID",
    ("common", "causationId"): "CausationID",
    ("common", "idempotencyKey"): "AuthorizationIdempotencyKey",
    ("common", "taskId"): "TaskID",
    ("common", "sessionId"): "SessionID",
    ("common", "decisionId"): "DecisionID",
    ("common", "approvalId"): "ApprovalID",
    ("common", "auditRef"): "AuditRef",
    ("common", "sha256"): "SHA256Digest",
    ("common", "timestamp"): "RFC3339Timestamp",
    ("common", "semver"): "SemanticVersion",
    ("common", "safeText"): "SafeText",
    ("approval", "principalRef"): "PrincipalRef",
    ("approval", "resolutionIdempotencyKey"): "ApprovalResolutionIdempotencyKey",
}
DIRECT_STRING_NAMES = {
    ("reconciliation", "reconciliationId"): "ReconciliationID",
    ("reconciliation", "batchId"): "BatchID",
    ("reconciliation", "receiptId"): "ReceiptID",
}
DIRECT_STRING_POINTERS = {
    "ReconciliationID": "/properties/reconciliationId",
    "BatchID": "/properties/batchId",
    "ReceiptID": "/properties/acknowledgement/properties/receiptId",
}


@dataclass(frozen=True)
class SchemaSet:
    by_kind: dict[str, dict[str, Any]]
    by_id: dict[str, dict[str, Any]]
    canonical_json: dict[str, str]
    digest: str


@dataclass(frozen=True)
class ObjectSpec:
    name: str
    kind: str
    pointer: str
    schema: dict[str, Any]


def _strict_json(raw: bytes, filename: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate schema key {key!r}")
            value[key] = child
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"invalid schema {filename}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"schema {filename} must be an object")
    return value


def _read_schemas(schema_root: Path) -> SchemaSet:
    by_kind: dict[str, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    canonical_json: dict[str, str] = {}
    digest = hashlib.sha256()
    for filename in SCHEMA_FILES:
        path = schema_root / filename
        raw = path.read_bytes()
        schema = _strict_json(raw, filename)
        if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
            raise SystemExit(f"schema {filename} must be an object with $id")
        _validate_schema_patterns(schema, filename)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise SystemExit(f"invalid JSON Schema {filename}: {exc}") from exc
        kind = filename.removesuffix("-v1.schema.json")
        by_kind[kind] = schema
        by_id[schema["$id"]] = schema
        canonical_json[kind] = json.dumps(
            schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(raw)
        digest.update(b"\0")
    schemas = SchemaSet(
        by_kind=by_kind,
        by_id=by_id,
        canonical_json=canonical_json,
        digest=digest.hexdigest(),
    )
    _validate_generator_inputs(schemas)
    return schemas


def _walk(value: Any) -> list[dict[str, Any]]:
    pending = [value]
    objects: list[dict[str, Any]] = []
    while pending:
        child = pending.pop()
        if isinstance(child, dict):
            objects.append(child)
            pending.extend(child.values())
        elif isinstance(child, list):
            pending.extend(child)
    return objects


def _validate_schema_patterns(schema: dict[str, Any], filename: str) -> None:
    for node in _walk(schema):
        pattern = node.get("pattern")
        if not isinstance(pattern, str):
            continue
        maximum = node.get("maxLength")
        if isinstance(maximum, int) and maximum > MAX_RUNTIME_STRING_BYTES:
            raise SystemExit(f"pattern maxLength exceeds runtime bound in {filename}")
        reason = _unsafe_pattern_reason(pattern)
        if reason is not None:
            raise SystemExit(f"unsafe schema pattern in {filename}: {reason}")


def _unsafe_pattern_reason(pattern: str) -> str | None:
    if len(pattern) > 512:
        return "pattern exceeds 512 characters"
    if any(0xD800 <= ord(character) <= 0xDFFF for character in pattern):
        return "pattern contains a lone surrogate"
    digest = hashlib.sha256(pattern.encode("utf-8")).hexdigest()
    if digest in REVIEWED_PATTERN_DIGESTS_V2:
        try:
            re.compile(pattern)
        except (re.error, OverflowError):
            return "reviewed pattern no longer compiles in Python"
        return None
    reason = _simple_pattern_reason(pattern)
    if reason is not None:
        return reason
    try:
        re.compile(pattern)
    except (re.error, OverflowError):
        return "pattern does not compile in Python"
    return None


def _simple_pattern_reason(pattern: str) -> str | None:
    end = len(pattern)
    index = 1 if pattern.startswith("^") else 0
    if end > index and pattern.endswith("$") and not pattern.endswith(r"\$"):
        end -= 1
    atoms = 0
    approved_escapes = frozenset(r".^$*+?{}[]()|\-/")
    while index < end:
        character = pattern[index]
        if character == "\\":
            if index + 1 >= end or pattern[index + 1] not in approved_escapes:
                return "unsupported escape in unreviewed pattern"
            index += 2
        elif character == "[":
            class_start = index
            index += 1
            if index < end and pattern[index] == "^":
                index += 1
            class_atoms = 0
            while index < end and pattern[index] != "]":
                if pattern[index] == "[" or pattern[index : index + 2] == "[:":
                    return "nested and locale character classes are unsupported"
                if pattern[index] == "\\":
                    if index + 1 >= end or pattern[index + 1] not in approved_escapes:
                        return "unsupported character-class escape"
                    index += 2
                else:
                    index += 1
                class_atoms += 1
            if index >= end or pattern[index] != "]" or class_atoms == 0:
                return "malformed character class"
            index += 1
            if index == class_start + 1:
                return "empty character class"
        elif character in "()|":
            return "groups and alternation require reviewed-pattern approval"
        elif character in "{}*+?[]^$":
            return "misplaced metacharacter in unreviewed pattern"
        else:
            index += 1
        atoms += 1
        if index < end and pattern[index] == "{":
            close = pattern.find("}", index + 1, end)
            if close < 0:
                return "unterminated bounded quantifier"
            body = pattern[index + 1 : close]
            fields = body.split(",")
            if (
                len(fields) not in (1, 2)
                or any(not field.isascii() or not field.isdigit() for field in fields)
                or any(len(field) > 4 for field in fields)
            ):
                return "malformed or unbounded quantifier"
            lower = int(fields[0])
            upper = lower if len(fields) == 1 else int(fields[1])
            if lower > upper or upper > MAX_RUNTIME_STRING_BYTES:
                return "quantifier exceeds runtime bound"
            index = close + 1
        elif index < end and pattern[index] in "*+?":
            return "variable quantifier requires reviewed-pattern approval"
    if atoms == 0:
        return "empty unreviewed pattern"
    return None


def _validate_generator_inputs(schemas: SchemaSet) -> None:
    allowed_ids = {
        f"https://schemas.palonexus.dev/protocol/v1/{filename}"
        for filename in SCHEMA_FILES
    }
    if set(schemas.by_id) != allowed_ids:
        raise SystemExit("schema identifiers do not match the local allowlist")
    safe_property = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
    for kind, root in schemas.by_kind.items():
        for node in _walk(root):
            ref = node.get("$ref")
            if isinstance(ref, str):
                target_kind, fragment = _absolute_ref(kind, ref, schemas)
                _pointer(schemas.by_kind[target_kind], fragment)
            properties = node.get("properties")
            if isinstance(properties, dict):
                for name in properties:
                    if safe_property.fullmatch(name) is None:
                        raise SystemExit(
                            f"unsafe schema property name in {kind}: {name!r}"
                        )
                python_names = [_snake(name) for name in properties]
                go_names = [_go_name(name) for name in properties]
                if len(python_names) != len(set(python_names)):
                    raise SystemExit(f"Python property-name collision in {kind}")
                if len(go_names) != len(set(go_names)):
                    raise SystemExit(f"Go property-name collision in {kind}")
            enum = node.get("enum")
            if isinstance(enum, list) and all(isinstance(item, str) for item in enum):
                python_members = [_enum_member(item) for item in enum]
                go_members = [_go_name(member.lower()) for member in python_members]
                if len(python_members) != len(set(python_members)):
                    raise SystemExit(f"enum identifier collision in {kind}")
                if len(go_members) != len(set(go_members)):
                    raise SystemExit(f"Go enum identifier collision in {kind}")
    _validate_ref_graph(schemas)


def _validate_ref_graph(schemas: SchemaSet) -> None:
    Node = tuple[str, str]
    edges: dict[Node, list[tuple[Node, bool]]] = {}
    nodes: dict[Node, dict[str, Any]] = {}

    def escaped(token: str) -> str:
        return token.replace("~", "~0").replace("/", "~1")

    def collect(kind: str, value: Any, pointer: str) -> None:
        if not isinstance(value, dict):
            return
        source = (kind, pointer)
        nodes[source] = value
        edges.setdefault(source, [])
        ref = value.get("$ref")
        if isinstance(ref, str):
            edges[source].append((_absolute_ref(kind, ref, schemas), False))
        for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
            children = value.get(keyword)
            if not isinstance(children, list):
                continue
            consuming = keyword == "prefixItems"
            for index, child in enumerate(children):
                if isinstance(child, dict):
                    child_pointer = f"{pointer}/{keyword}/{index}"
                    collect(kind, child, child_pointer)
                    edges[source].append(((kind, child_pointer), consuming))
        for keyword in ("not", "if", "then", "else", "contentSchema"):
            child = value.get(keyword)
            if isinstance(child, dict):
                child_pointer = f"{pointer}/{keyword}"
                collect(kind, child, child_pointer)
                edges[source].append(((kind, child_pointer), False))
        for keyword in (
            "items",
            "contains",
            "additionalItems",
            "additionalProperties",
            "unevaluatedItems",
            "unevaluatedProperties",
            "propertyNames",
        ):
            child = value.get(keyword)
            if isinstance(child, dict):
                child_pointer = f"{pointer}/{keyword}"
                collect(kind, child, child_pointer)
                edges[source].append(((kind, child_pointer), True))
        for keyword, consuming in (
            ("properties", True),
            ("patternProperties", True),
            ("dependentSchemas", False),
        ):
            children = value.get(keyword)
            if not isinstance(children, dict):
                continue
            for name, child in sorted(children.items()):
                if isinstance(child, dict):
                    child_pointer = f"{pointer}/{keyword}/{escaped(name)}"
                    collect(kind, child, child_pointer)
                    edges[source].append(((kind, child_pointer), consuming))
        definitions = value.get("$defs")
        if isinstance(definitions, dict):
            for name, child in sorted(definitions.items()):
                if isinstance(child, dict):
                    collect(kind, child, f"{pointer}/$defs/{escaped(name)}")

    for kind, root in sorted(schemas.by_kind.items()):
        collect(kind, root, "")

    zero_edges = {
        node: sorted(target for target, consuming in targets if not consuming)
        for node, targets in edges.items()
    }
    visiting: list[Node] = []
    visited: set[Node] = set()

    def visit(node: Node) -> None:
        if node in visiting:
            start = visiting.index(node)
            cycle = [*visiting[start:], node]
            rendered = " -> ".join(pointer or "/" for _, pointer in cycle)
            raise SystemExit(f"non-consuming schema reference cycle: {rendered}")
        if node in visited:
            return
        visiting.append(node)
        for target in zero_edges.get(node, []):
            visit(target)
        visiting.pop()
        visited.add(node)

    for node in sorted(nodes):
        visit(node)


def _pointer(document: dict[str, Any], pointer: str) -> dict[str, Any]:
    value: Any = document
    for token in pointer.split("/"):
        if not token:
            continue
        key = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or key not in value:
            raise SystemExit(f"schema pointer does not exist: {pointer}")
        value = value[key]
    if not isinstance(value, dict):
        raise SystemExit(f"schema pointer is not an object: {pointer}")
    return value


def _absolute_ref(kind: str, ref: str, schemas: SchemaSet) -> tuple[str, str]:
    if ref.startswith("#"):
        schema_id = schemas.by_kind[kind]["$id"]
        fragment = ref[1:]
    else:
        schema_id, separator, fragment = ref.partition("#")
        if not separator:
            fragment = ""
    target_kind = next(
        (
            candidate
            for candidate, schema in schemas.by_kind.items()
            if schema["$id"] == schema_id
        ),
        "",
    )
    if not target_kind:
        raise SystemExit(f"unknown schema reference: {ref}")
    return target_kind, fragment


def _resolved_schema(
    kind: str,
    schema: dict[str, Any],
    schemas: SchemaSet,
) -> tuple[str, dict[str, Any]]:
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return kind, schema
    target_kind, fragment = _absolute_ref(kind, ref, schemas)
    target = _pointer(schemas.by_kind[target_kind], fragment)
    return target_kind, target


def _objects(schemas: SchemaSet) -> list[ObjectSpec]:
    values: list[ObjectSpec] = []
    common_defs = schemas.by_kind["common"]["$defs"]
    for definition, class_name in COMMON_OBJECTS.items():
        values.append(
            ObjectSpec(
                class_name,
                "common",
                f"/$defs/{definition}",
                common_defs[definition],
            )
        )
    reconciliation = schemas.by_kind["reconciliation"]
    for (kind, field), class_name in DIRECT_OBJECTS.items():
        values.append(
            ObjectSpec(
                class_name,
                kind,
                f"/properties/{field}",
                reconciliation["properties"][field],
            )
        )
    for kind, class_name in ROOT_CLASS_NAMES.items():
        values.append(ObjectSpec(class_name, kind, "", schemas.by_kind[kind]))
    return values


def _enums(schemas: SchemaSet) -> dict[str, list[str]]:
    action = schemas.by_kind["action"]["properties"]
    decision = schemas.by_kind["decision"]["properties"]
    approval = schemas.by_kind["approval"]["properties"]
    error = schemas.by_kind["error"]["properties"]
    reconciliation = schemas.by_kind["reconciliation"]["properties"]
    common_defs = schemas.by_kind["common"]["$defs"]
    return {
        "ActionName": list(action["action"]["enum"]),
        "SideEffect": list(action["sideEffect"]["enum"]),
        "TargetKind": list(common_defs["target"]["properties"]["kind"]["enum"]),
        "DecisionOutcome": list(decision["outcome"]["enum"]),
        "ApprovalStatus": list(approval["status"]["enum"]),
        "ProtocolErrorCode": list(error["code"]["enum"]),
        "ReconciliationOutcome": list(reconciliation["outcome"]["enum"]),
        "DeliveryDisposition": list(reconciliation["deliveryDisposition"]["enum"]),
        "ReconciliationState": list(reconciliation["state"]["enum"]),
        "DiscardAuthorityType": list(
            reconciliation["discard"]["properties"]["authorityType"]["enum"]
        ),
    }


def _snake(value: str) -> str:
    first = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first).lower()


def _pascal(value: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in _snake(value).split("_"))


def _go_name(value: str) -> str:
    initialisms = {
        "api": "API",
        "http": "HTTP",
        "id": "ID",
        "json": "JSON",
        "mcp": "MCP",
        "sdk": "SDK",
        "url": "URL",
    }
    return "".join(
        initialisms.get(part, part[:1].upper() + part[1:])
        for part in _snake(value).split("_")
    )


def _enum_member(value: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    if not candidate or candidate[0].isdigit():
        candidate = f"VALUE_{candidate}"
    return candidate


def _enum_for_field(parent: str, field: str) -> str | None:
    if field == "action":
        return "ActionName"
    if field in {"kind", "targetKind"}:
        return "TargetKind"
    if field == "sideEffect":
        return "SideEffect"
    if field == "status" and parent in {"ApprovalRecord", "ApprovalSummary"}:
        return "ApprovalStatus"
    if field == "code" and parent == "ProtocolError":
        return "ProtocolErrorCode"
    if field == "outcome":
        return (
            "ReconciliationOutcome"
            if parent == "ReconciliationRecord"
            else "DecisionOutcome"
        )
    if field == "deliveryDisposition":
        return "DeliveryDisposition"
    if field == "state":
        return "ReconciliationState"
    if field == "authorityType":
        return "DiscardAuthorityType"
    return None


def _ref_target(
    kind: str,
    schema: dict[str, Any],
    schemas: SchemaSet,
) -> tuple[str, str] | None:
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return None
    target_kind, fragment = _absolute_ref(kind, ref, schemas)
    definition = fragment.removeprefix("/$defs/")
    return target_kind, definition


def _object_type(
    parent: str,
    kind: str,
    field: str,
    schema: dict[str, Any],
    schemas: SchemaSet,
) -> str | None:
    ref_target = _ref_target(kind, schema, schemas)
    if ref_target and ref_target[0] == "common":
        common_name = COMMON_OBJECTS.get(ref_target[1])
        if common_name:
            return common_name
    direct = DIRECT_OBJECTS.get((kind, field))
    if direct:
        return direct
    return None


def _string_type(
    kind: str,
    field: str,
    schema: dict[str, Any],
    schemas: SchemaSet,
) -> str | None:
    ref_target = _ref_target(kind, schema, schemas)
    if ref_target in STRING_REF_NAMES:
        return STRING_REF_NAMES[ref_target]
    direct = DIRECT_STRING_NAMES.get((kind, field))
    if direct:
        return direct
    return None


def _python_type(
    parent: str,
    kind: str,
    field: str,
    schema: dict[str, Any],
    schemas: SchemaSet,
) -> str:
    enum = _enum_for_field(parent, field)
    if enum and ("enum" in schema or "const" in schema):
        return enum
    object_type = _object_type(parent, kind, field, schema, schemas)
    if object_type:
        return object_type
    string_type = _string_type(kind, field, schema, schemas)
    if string_type:
        return string_type
    resolved_kind, resolved = _resolved_schema(kind, schema, schemas)
    if resolved.get("type") == "object":
        if field == "extensions" or resolved_kind == "common":
            return "dict[str, JSONValue]"
        return "dict[str, JSONValue]"
    if resolved.get("type") == "array":
        return "list[JSONValue]"
    if resolved.get("type") == "integer":
        return "int"
    if resolved.get("type") == "number":
        return "int | float"
    if resolved.get("type") == "boolean":
        return "bool"
    return "str"


def _go_type(
    parent: str,
    kind: str,
    field: str,
    schema: dict[str, Any],
    schemas: SchemaSet,
) -> str:
    enum = _enum_for_field(parent, field)
    if enum and ("enum" in schema or "const" in schema):
        return enum
    object_type = _object_type(parent, kind, field, schema, schemas)
    if object_type:
        return object_type
    string_type = _string_type(kind, field, schema, schemas)
    if string_type:
        return string_type
    _, resolved = _resolved_schema(kind, schema, schemas)
    if resolved.get("type") == "object":
        return "map[string]any"
    if resolved.get("type") == "array":
        return "[]any"
    if resolved.get("type") == "integer":
        return "JSONInteger"
    if resolved.get("type") == "number":
        return "float64"
    if resolved.get("type") == "boolean":
        return "bool"
    return "string"


def _python_conversion(
    parent: str,
    kind: str,
    field: str,
    schema: dict[str, Any],
    value: str,
    schemas: SchemaSet,
) -> str:
    enum = _enum_for_field(parent, field)
    if enum and ("enum" in schema or "const" in schema):
        return f"{enum}({value})"
    object_type = _object_type(parent, kind, field, schema, schemas)
    if object_type:
        return f"{object_type}._from_dict({value})"
    string_type = _string_type(kind, field, schema, schemas)
    if string_type:
        return f"{string_type}({value})"
    _, resolved = _resolved_schema(kind, schema, schemas)
    if resolved.get("type") in {"object", "array"}:
        return f"_copy_json({value})"
    if resolved.get("type") == "integer":
        return f"int({value})"
    return value


def _schema_header(digest: str, comment: str) -> str:
    header = (
        f"{comment} SPDX-License-Identifier: MIT\n"
        f"{comment} Code generated by scripts/generate_protocol.py; DO NOT EDIT.\n"
        f"{comment} Generator version: {GENERATOR_VERSION}\n"
        f"{comment} Schema digest: {digest}\n"
    )
    return header + "".join(
        f"{comment} Source schema: {filename}\n" for filename in SCHEMA_FILES
    )


def _python_schema_runtime(schemas: SchemaSet) -> str:
    encoded = json.dumps(
        schemas.canonical_json,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    encoded_b64 = base64.b64encode(encoded.encode("utf-8")).decode("ascii")
    encoded_lines = "\n".join(
        f'    "{encoded_b64[offset : offset + 76]}"'
        for offset in range(0, len(encoded_b64), 76)
    )
    return f'''
_SCHEMA_B64: Final[str] = (
{encoded_lines}
)
_SCHEMA_TEXT: Final[str] = base64.b64decode(_SCHEMA_B64).decode("utf-8")
_SCHEMAS: Final[dict[str, dict[str, JSONValue]]] = {{
    kind: json.loads(document, parse_float=Decimal)
    for kind, document in json.loads(_SCHEMA_TEXT).items()
}}
_SCHEMAS_BY_ID: Final[dict[str, dict[str, JSONValue]]] = {{
    str(schema["$id"]): schema for schema in _SCHEMAS.values()
}}


class ProtocolStructureError(ValueError):
    """A safe structural validation error containing no protocol value."""


MAX_WIRE_BYTES: Final[int] = 65_536
MAX_NESTING: Final[int] = 32
MAX_NODES: Final[int] = 4_096
MAX_COLLECTION_ITEMS: Final[int] = 1_024
MAX_STRING_BYTES: Final[int] = 8_192
MAX_NUMERIC_TOKEN_BYTES: Final[int] = 512


def _wire_error(code: str) -> ProtocolStructureError:
    return ProtocolStructureError(code)


def _preflight_wire(document: bytes | str) -> str:
    if isinstance(document, str):
        try:
            raw = document.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise _wire_error("invalid_utf8") from exc
    elif isinstance(document, bytes):
        raw = document
    else:
        raise _wire_error("invalid_json")
    if len(raw) > MAX_WIRE_BYTES:
        raise _wire_error("wire_too_large")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _wire_error("invalid_utf8") from exc

    depth = 0
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            index += 1
            continue
        if character in "[{{":
            depth += 1
            if depth > MAX_NESTING:
                raise _wire_error("nesting_too_deep")
        elif character in "]}}":
            depth -= 1
            if depth < 0:
                raise _wire_error("invalid_json")
        elif character == "-" or character.isascii() and character.isdigit():
            end = index + 1
            while end < len(text) and text[end] in "0123456789.eE+-":
                end += 1
            if len(text[index:end].encode("utf-8")) > MAX_NUMERIC_TOKEN_BYTES:
                raise _wire_error("numeric_token_too_long")
            index = end
            continue
        index += 1
    if in_string or depth != 0:
        raise _wire_error("invalid_json")
    return text


def _validate_memory_limits(value: JSONValue) -> None:
    pending: list[tuple[JSONValue, int]] = [(value, 0)]
    nodes = 0
    while pending:
        child, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise _wire_error("node_limit_exceeded")
        if depth > MAX_NESTING:
            raise _wire_error("nesting_too_deep")
        if isinstance(child, dict):
            if len(child) > MAX_COLLECTION_ITEMS:
                raise _wire_error("collection_limit_exceeded")
            for key, nested in child.items():
                if _utf8_length(key) > MAX_STRING_BYTES:
                    raise _wire_error("string_too_large")
                pending.append((nested, depth + 1))
        elif isinstance(child, list):
            if len(child) > MAX_COLLECTION_ITEMS:
                raise _wire_error("collection_limit_exceeded")
            pending.extend((nested, depth + 1) for nested in child)
        elif isinstance(child, str):
            if _utf8_length(child) > MAX_STRING_BYTES:
                raise _wire_error("string_too_large")


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise _wire_error("invalid_utf8") from exc


def _strict_loads_json(document: bytes | str) -> JSONValue:
    text = _preflight_wire(document)

    def unique_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
        if len(pairs) > MAX_COLLECTION_ITEMS:
            raise _wire_error("collection_limit_exceeded")
        result: dict[str, JSONValue] = {{}}
        for key, value in pairs:
            if key in result:
                raise _wire_error("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise _wire_error("invalid_json_number")

    def parse_decimal(token: str) -> Decimal:
        try:
            value = Decimal(token)
            if not value.is_finite() or abs(value.adjusted()) > 10_000:
                raise _wire_error("invalid_json_number")
            return value
        except (DecimalException, OverflowError, ValueError) as exc:
            raise _wire_error("invalid_json_number") from exc

    try:
        value: JSONValue = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_int=int,
            parse_float=parse_decimal,
            parse_constant=reject_constant,
        )
    except ProtocolStructureError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _wire_error("invalid_json") from exc
    _validate_memory_limits(value)
    return value


def _error(path: str, keyword: str) -> ProtocolStructureError:
    return ProtocolStructureError(f"schema_invalid: {{path}} ({{keyword}})")


def _schema_pointer(document: dict[str, JSONValue], pointer: str) -> dict[str, JSONValue]:
    value: JSONValue = document
    for raw in pointer.split("/"):
        if not raw:
            continue
        token = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            raise ProtocolStructureError("generated_schema_reference_invalid")
        value = value[token]
    if not isinstance(value, dict):
        raise ProtocolStructureError("generated_schema_reference_invalid")
    return value


def _resolve_ref(
    root: dict[str, JSONValue],
    ref: str,
) -> tuple[dict[str, JSONValue], dict[str, JSONValue]]:
    if ref.startswith("#"):
        target_root = root
        fragment = ref[1:]
    else:
        schema_id, separator, fragment = ref.partition("#")
        if not separator or schema_id not in _SCHEMAS_BY_ID:
            raise ProtocolStructureError("generated_schema_reference_invalid")
        target_root = _SCHEMAS_BY_ID[schema_id]
    return target_root, _schema_pointer(target_root, fragment)


def _is_rfc3339(value: str) -> bool:
    match = re.fullmatch(
        r"[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}"
        r"(?:\\.[0-9]+)?(?:Z|[+-][0-9]{{2}}:[0-9]{{2}})",
        value,
    )
    if match is None:
        return False
    seconds = int(value[17:19])
    if seconds > 60:
        return False
    base = value[:17] + ("59" if seconds == 60 else value[17:19])
    try:
        datetime.fromisoformat(base)
    except ValueError:
        return False
    zone = value[-6:] if value[-1:] != "Z" else "+00:00"
    if zone != "+00:00":
        try:
            hour = int(zone[1:3])
            minute = int(zone[4:6])
        except ValueError:
            return False
        if hour > 23 or minute > 59:
            return False
    return True


def _matches(
    root: dict[str, JSONValue],
    schema: dict[str, JSONValue],
    value: JSONValue,
    path: str,
) -> bool:
    try:
        _validate(root, schema, value, path)
    except ProtocolStructureError:
        return False
    return True


def _validate(
    root: dict[str, JSONValue],
    schema: dict[str, JSONValue],
    value: JSONValue,
    path: str,
) -> None:
    ref = schema.get("$ref")
    if isinstance(ref, str):
        target_root, target = _resolve_ref(root, ref)
        _validate(target_root, target, value, path)

    expected = schema.get("type")
    type_valid = (
        expected is None
        or (expected == "object" and isinstance(value, dict))
        or (expected == "array" and isinstance(value, list))
        or (expected == "string" and isinstance(value, str))
        or (expected == "boolean" and isinstance(value, bool))
        or (
            expected == "integer"
            and (
                (isinstance(value, int) and not isinstance(value, bool))
                or (
                    isinstance(value, Decimal)
                    and value.is_finite()
                    and value == value.to_integral_value()
                )
            )
        )
        or (
            expected == "number"
            and isinstance(value, (int, Decimal))
            and not isinstance(value, bool)
            and (not isinstance(value, Decimal) or value.is_finite())
        )
    )
    if not type_valid:
        raise _error(path, "type")
    if "const" in schema and value != schema["const"]:
        raise _error(path, "const")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise _error(path, "enum")

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for branch in all_of:
            if isinstance(branch, dict):
                _validate(root, branch, value, path)
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and not any(
        isinstance(branch, dict) and _matches(root, branch, value, path)
        for branch in any_of
    ):
        raise _error(path, "anyOf")
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matches = sum(
            isinstance(branch, dict) and _matches(root, branch, value, path)
            for branch in one_of
        )
        if matches != 1:
            raise _error(path, "oneOf")
    negated = schema.get("not")
    if isinstance(negated, dict) and _matches(root, negated, value, path):
        raise _error(path, "not")
    condition = schema.get("if")
    if isinstance(condition, dict):
        branch_name = "then" if _matches(root, condition, value, path) else "else"
        branch = schema.get(branch_name)
        if isinstance(branch, dict):
            _validate(root, branch, value, path)

    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for name in required:
                if isinstance(name, str) and name not in value:
                    raise _error(path, f"required.{{name}}")
        properties = schema.get("properties", {{}})
        if not isinstance(properties, dict):
            properties = {{}}
        additional = schema.get("additionalProperties", True)
        for name, child in value.items():
            child_schema = properties.get(name)
            child_path = f"{{path}}.{{name}}"
            if isinstance(child_schema, dict):
                _validate(root, child_schema, child, child_path)
            elif additional is False:
                raise _error(child_path, "additionalProperties")
            elif isinstance(additional, dict):
                _validate(root, additional, child, child_path)
        property_names = schema.get("propertyNames")
        if isinstance(property_names, dict):
            for name in value:
                _validate(root, property_names, name, f"{{path}}.<property>")
        maximum = schema.get("maxProperties")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _error(path, "maxProperties")

    if isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, child in enumerate(value):
                _validate(root, items, child, f"{{path}}[{{index}}]")
        maximum = schema.get("maxItems")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _error(path, "maxItems")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        if isinstance(minimum, int) and len(value) < minimum:
            raise _error(path, "minLength")
        if isinstance(maximum, int) and len(value) > maximum:
            raise _error(path, "maxLength")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            raise _error(path, "pattern")
        if schema.get("format") == "date-time" and not _is_rfc3339(value):
            raise _error(path, "format")

    if isinstance(value, (int, Decimal)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, Decimal)) and value < minimum:
            raise _error(path, "minimum")
        if isinstance(maximum, (int, Decimal)) and value > maximum:
            raise _error(path, "maximum")


def _validate_document(kind: str, value: JSONValue) -> dict[str, JSONValue]:
    if kind not in _SCHEMAS:
        raise ProtocolStructureError("unsupported_generated_document_kind")
    if not isinstance(value, dict):
        raise _error("$", "type")
    _validate_memory_limits(value)
    schema = _SCHEMAS[kind]
    _validate(schema, schema, value, "$")
    return value


def _validate_fragment(kind: str, pointer: str, value: JSONValue) -> None:
    _validate_memory_limits(value)
    root = _SCHEMAS[kind]
    _validate(root, _schema_pointer(root, pointer), value, "$")


def _copy_json(value: JSONValue) -> JSONValue:
    if isinstance(value, dict):
        return {{key: _copy_json(child) for key, child in value.items()}}
    if isinstance(value, list):
        return [_copy_json(child) for child in value]
    return value


def _to_json(value: object) -> JSONValue:
    if isinstance(value, _StructuralDTO):
        return value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        _validate_memory_limits(value)
        return {{str(key): _to_json(child) for key, child in value.items()}}
    if isinstance(value, list):
        _validate_memory_limits(value)
        return [_to_json(child) for child in value]
    if isinstance(value, (str, int, Decimal, bool)) or value is None:
        return value
    raise TypeError(f"unsupported generated DTO value: {{type(value).__name__}}")


def _encode_json_value(value: JSONValue) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise _wire_error("invalid_json_number")
        encoded = str(value)
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", encoded) is None:
            raise _wire_error("invalid_json_number")
        return encoded
    if isinstance(value, list):
        return "[" + ",".join(_encode_json_value(child) for child in value) + "]"
    if isinstance(value, dict):
        return "{{" + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + _encode_json_value(child)
            for key, child in value.items()
        ) + "}}"
    raise _wire_error("invalid_json_value")


class _StructuralDTO:
    """Base for generated structural DTOs; semantic validation is separate."""

    _JSON_FIELDS: ClassVar[dict[str, str]]
    _SCHEMA_KIND: ClassVar[str]
    _SCHEMA_POINTER: ClassVar[str]

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {{}}
        for attribute, wire_name in self._JSON_FIELDS.items():
            value = getattr(self, attribute)
            if value is not None:
                result[wire_name] = _to_json(value)
        if self._SCHEMA_POINTER:
            _validate_fragment(self._SCHEMA_KIND, self._SCHEMA_POINTER, result)
        else:
            _validate_document(self._SCHEMA_KIND, result)
        return result

    def validate_structural(self) -> None:
        """Revalidate this DTO against its generated structural schema."""

        self.to_dict()

    def to_json_bytes(self) -> bytes:
        """Serialize exact JSON numbers after structural and wire-limit checks."""

        encoded = _encode_json_value(self.to_dict()).encode("utf-8")
        _strict_loads_json(encoded)
        return encoded
'''


def _python_string_classes(schemas: SchemaSet) -> str:
    rows: list[str] = []
    seen: set[str] = set()
    for (kind, definition), class_name in STRING_REF_NAMES.items():
        if class_name in seen:
            continue
        seen.add(class_name)
        pointer = f"/$defs/{definition}"
        rows.extend(
            [
                f"class {class_name}(str):",
                '    """Validated schema-derived wire string."""',
                "",
                "    def __new__(cls, value: str) -> Self:",
                f'        _validate_fragment("{kind}", "{pointer}", value)',
                "        return str.__new__(cls, value)",
                "",
                "",
            ]
        )
    for (kind, field), class_name in DIRECT_STRING_NAMES.items():
        pointer = DIRECT_STRING_POINTERS[class_name]
        rows.extend(
            [
                f"class {class_name}(str):",
                '    """Validated schema-derived wire string."""',
                "",
                "    def __new__(cls, value: str) -> Self:",
                f'        _validate_fragment("{kind}", "{pointer}", value)',
                "        return str.__new__(cls, value)",
                "",
                "",
            ]
        )
    return "\n".join(rows)


def _python_enums(schemas: SchemaSet) -> str:
    rows: list[str] = []
    for name, values in _enums(schemas).items():
        rows.append(f"class {name}(StrEnum):")
        rows.append(f'    """Wire values generated for {name}."""')
        rows.append("")
        for value in values:
            rows.append(f"    {_enum_member(value)} = {value!r}")
        rows.extend(["", ""])
    return "\n".join(rows)


def _python_objects(schemas: SchemaSet) -> str:
    rows: list[str] = []
    for spec in _objects(schemas):
        properties = spec.schema.get("properties")
        required = spec.schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise SystemExit(f"object schema is malformed: {spec.name}")
        ordered = [
            *(field for field in properties if field in required),
            *(field for field in properties if field not in required),
        ]
        rows.extend(
            [
                "@dataclass(frozen=True, slots=True)",
                f"class {spec.name}(_StructuralDTO):",
                '    """Schema-derived structural DTO; semantic checks are not run."""',
                "",
            ]
        )
        for field in ordered:
            schema = properties[field]
            python_type = _python_type(spec.name, spec.kind, field, schema, schemas)
            optional = field not in required
            annotation = f"{python_type} | None" if optional else python_type
            default = " = None" if optional else ""
            rows.append(f"    {_snake(field)}: {annotation}{default}")
        rows.extend(["", "    _JSON_FIELDS: ClassVar[dict[str, str]] = {"])
        for field in ordered:
            rows.append(f'        "{_snake(field)}": "{field}",')
        rows.extend(
            [
                "    }",
                f'    _SCHEMA_KIND: ClassVar[str] = "{spec.kind}"',
                f"    _SCHEMA_POINTER: ClassVar[str] = {spec.pointer!r}",
                "",
                "    @classmethod",
            ]
        )
        rows.append(
            f"    def _from_dict(cls, value: dict[str, JSONValue]) -> {spec.name}:"
        )
        rows.append("        return cls(")
        for field in ordered:
            access = f'value["{field}"]'
            converted = _python_conversion(
                spec.name,
                spec.kind,
                field,
                properties[field],
                access,
                schemas,
            )
            if field not in required:
                converted = f"None if {field!r} not in value else {converted}"
            rows.append(f"            {_snake(field)}={converted},")
        rows.extend(["        )", "", ""])
    return "\n".join(rows)


def _python_parsers() -> str:
    rows = [
        "def semantic_validation_reference() -> str:",
        '    """Name the repository-only semantic validation reference."""',
        "",
        '    return "protocol.reference.validate (repository conformance only)"',
        "",
        "",
    ]
    for kind, class_name in ROOT_CLASS_NAMES.items():
        rows.extend(
            [
                f"def parse_{kind}(value: JSONValue) -> {class_name}:",
                f'    """Parse and structurally validate {kind} JSON.',
                "",
                "    Semantic validation remains separate.",
                '    """',
                "",
                f'    document = _validate_document("{kind}", value)',
                f"    return {class_name}._from_dict(document)",
                "",
                "",
                (f"def parse_{kind}_json(document: bytes | str) -> {class_name}:"),
                f'    """Strictly parse {kind} wire JSON before validation."""',
                "",
                f"    return parse_{kind}(_strict_loads_json(document))",
                "",
                "",
            ]
        )
    rows.extend(
        [
            "type StructuralParser = Callable[[JSONValue], _StructuralDTO]",
            "STRUCTURAL_PARSERS: Final[dict[str, StructuralParser]] = {",
        ]
    )
    for kind in ROOT_CLASS_NAMES:
        rows.append(f'    "{kind}": parse_{kind},')
    rows.append("}")
    return "\n".join(rows)


def _render_python(schemas: SchemaSet) -> str:
    header = _schema_header(schemas.digest, "#")
    prelude = f'''{header}"""PaloNexus protocol version 1 structural DTOs.

These generated models preserve JSON names and reject schema-invalid documents.
This module does not perform semantic validation. Authorization consumers must call the
Task 5-8 semantic/reference validators or the corresponding SDK validation API.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, DecimalException
from enum import Enum, StrEnum
from typing import ClassVar, Final, Self

type JSONPrimitive = str | int | Decimal | bool | None
type JSONValue = JSONPrimitive | list[JSONValue] | dict[str, JSONValue]
SCHEMA_DIGEST: Final[str] = "{schemas.digest}"
GENERATOR_VERSION: Final[str] = "{GENERATOR_VERSION}"

'''
    source = (
        prelude
        + _python_schema_runtime(schemas)
        + "\n\n"
        + _python_string_classes(schemas)
        + _python_enums(schemas)
        + _python_objects(schemas)
        + _python_parsers()
        + "\n"
    )
    return _format_python(source)


def _go_string_types() -> str:
    names: list[str] = []
    for name in [*STRING_REF_NAMES.values(), *DIRECT_STRING_NAMES.values()]:
        if name not in names:
            names.append(name)
    return "type JSONInteger int\n" + "\n".join(f"type {name} string" for name in names)


def _go_string_literal(value: str) -> str:
    parts = ['"']
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise SystemExit("Go string input contains a lone surrogate")
        if character == '"':
            parts.append(r"\"")
        elif character == "\\":
            parts.append(r"\\")
        elif character == "\n":
            parts.append(r"\n")
        elif character == "\r":
            parts.append(r"\r")
        elif character == "\t":
            parts.append(r"\t")
        elif codepoint < 0x20 or codepoint == 0x7F or codepoint in (0x2028, 0x2029):
            parts.append(f"\\u{codepoint:04x}")
        elif codepoint > 0xFFFF:
            parts.append(f"\\U{codepoint:08x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _go_enums(schemas: SchemaSet) -> str:
    rows: list[str] = []
    for name, values in _enums(schemas).items():
        rows.extend([f"type {name} string", "", "const ("])
        for value in values:
            suffix = _go_name(_enum_member(value).lower())
            rows.append(f"\t{name}{suffix} {name} = {_go_string_literal(value)}")
        rows.extend([")", ""])
    return "\n".join(rows)


def _go_objects(schemas: SchemaSet) -> str:
    rows: list[str] = []
    for spec in _objects(schemas):
        properties = spec.schema.get("properties")
        required = spec.schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise SystemExit(f"object schema is malformed: {spec.name}")
        rows.append(f"type {spec.name} struct {{")
        for field, schema in properties.items():
            go_type = _go_type(spec.name, spec.kind, field, schema, schemas)
            optional = field not in required
            if optional:
                go_type = f"*{go_type}"
            tag = f'json:"{field}'
            if optional:
                tag += ",omitempty"
            tag += '"'
            rows.append(f"\t{_go_name(field)} {go_type} `{tag}`")
        rows.extend(["}", ""])
    return "\n".join(rows)


def _go_schema_map(schemas: SchemaSet) -> str:
    rows = ["var encodedSchemas = map[string]string{"]
    for kind in sorted(schemas.canonical_json):
        rows.append(
            f"\t{_go_string_literal(kind)}: "
            f"{_go_string_literal(schemas.canonical_json[kind])},"
        )
    rows.append("}")
    return "\n".join(rows)


def _go_validation_runtime() -> str:
    return r"""
const (
	maxWireBytes         = 65_536
	maxNesting           = 32
	maxNodes             = 4_096
	maxCollectionItems   = 1_024
	maxStringBytes       = 8_192
	maxNumericTokenBytes = 512
)

func wireError(code string) error {
	return errors.New(code)
}

func (value *JSONInteger) UnmarshalJSON(document []byte) error {
	token := strings.TrimSpace(string(document))
	if len(token) == 0 || len(token) > maxNumericTokenBytes {
		return wireError("invalid_json_integer")
	}
	rational, ok := new(big.Rat).SetString(token)
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return wireError("invalid_json_integer")
	}
	integer := rational.Num().Int64()
	if strconv.IntSize == 32 && (integer < math.MinInt32 || integer > math.MaxInt32) {
		return wireError("invalid_json_integer")
	}
	*value = JSONInteger(integer)
	return nil
}

func (value JSONInteger) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(value), 10)), nil
}

func numericTokenMagnitudeValid(token []byte) bool {
	exponent := bytes.IndexAny(token, "eE")
	if exponent < 0 {
		return true
	}
	digits := token[exponent+1:]
	if len(digits) > 0 && (digits[0] == '+' || digits[0] == '-') {
		digits = digits[1:]
	}
	for len(digits) > 1 && digits[0] == '0' {
		digits = digits[1:]
	}
	if len(digits) > 5 {
		return false
	}
	value, err := strconv.Atoi(string(digits))
	return err == nil && value <= 10_000
}

func preflightWire(document []byte) error {
	if len(document) > maxWireBytes {
		return wireError("wire_too_large")
	}
	if !utf8.Valid(document) {
		return wireError("invalid_utf8")
	}
	depth := 0
	inString := false
	for index := 0; index < len(document); index++ {
		character := document[index]
		if inString {
			if character == '"' {
				inString = false
				continue
			}
			if character != '\\' {
				continue
			}
			if index+1 >= len(document) {
				return wireError("invalid_json")
			}
			if document[index+1] != 'u' {
				index++
				continue
			}
			if index+6 > len(document) {
				return wireError("invalid_utf8")
			}
			first, err := strconv.ParseUint(string(document[index+2:index+6]), 16, 16)
			if err != nil {
				return wireError("invalid_json")
			}
			index += 5
			if first >= 0xD800 && first <= 0xDBFF {
				if index+6 >= len(document) ||
					document[index+1] != '\\' ||
					document[index+2] != 'u' {
					return wireError("invalid_utf8")
				}
				second, err := strconv.ParseUint(
					string(document[index+3:index+7]),
					16,
					16,
				)
				if err != nil || second < 0xDC00 || second > 0xDFFF {
					return wireError("invalid_utf8")
				}
				index += 6
			} else if first >= 0xDC00 && first <= 0xDFFF {
				return wireError("invalid_utf8")
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxNesting {
				return wireError("nesting_too_deep")
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return wireError("invalid_json")
			}
		default:
			if character != '-' && (character < '0' || character > '9') {
				continue
			}
			end := index + 1
			for end < len(document) &&
				strings.ContainsRune("0123456789.eE+-", rune(document[end])) {
				end++
			}
			if end-index > maxNumericTokenBytes {
				return wireError("numeric_token_too_long")
			}
			if !numericTokenMagnitudeValid(document[index:end]) {
				return wireError("invalid_json_number")
			}
			index = end - 1
		}
	}
	if inString || depth != 0 {
		return wireError("invalid_json")
	}
	return nil
}

func decodeStrictValue(
	decoder *json.Decoder,
	depth int,
	nodes *int,
) (any, error) {
	if depth > maxNesting {
		return nil, wireError("nesting_too_deep")
	}
	*nodes = *nodes + 1
	if *nodes > maxNodes {
		return nil, wireError("node_limit_exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, wireError("invalid_json")
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if text, ok := token.(string); ok && len([]byte(text)) > maxStringBytes {
			return nil, wireError("string_too_large")
		}
		return token, nil
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		count := 0
		for decoder.More() {
			rawKey, err := decoder.Token()
			if err != nil {
				return nil, wireError("invalid_json")
			}
			key, ok := rawKey.(string)
			if !ok {
				return nil, wireError("invalid_json")
			}
			if len([]byte(key)) > maxStringBytes {
				return nil, wireError("string_too_large")
			}
			if _, exists := result[key]; exists {
				return nil, wireError("duplicate_json_key")
			}
			count++
			if count > maxCollectionItems {
				return nil, wireError("collection_limit_exceeded")
			}
			value, err := decodeStrictValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			return nil, wireError("invalid_json")
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			if len(result) >= maxCollectionItems {
				return nil, wireError("collection_limit_exceeded")
			}
			value, err := decodeStrictValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, wireError("invalid_json")
		}
		return result, nil
	default:
		return nil, wireError("invalid_json")
	}
}

func decodeStrict(document []byte) (any, error) {
	if err := preflightWire(document); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	nodes := 0
	value, err := decodeStrictValue(decoder, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, wireError("invalid_json")
	}
	return value, nil
}

var (
	schemasOnce sync.Once
	schemas     map[string]map[string]any
	schemasByID map[string]map[string]any
	schemasErr  error
)

func loadSchemas() (map[string]map[string]any, error) {
	schemasOnce.Do(func() {
		schemas = make(map[string]map[string]any, len(encodedSchemas))
		schemasByID = make(map[string]map[string]any, len(encodedSchemas))
		for kind, document := range encodedSchemas {
			var schema map[string]any
			if err := json.Unmarshal([]byte(document), &schema); err != nil {
				schemasErr = fmt.Errorf("generated schema %s is invalid: %w", kind, err)
				return
			}
			schemaID, ok := schema["$id"].(string)
			if !ok {
				schemasErr = fmt.Errorf("generated schema %s has no identifier", kind)
				return
			}
			schemas[kind] = schema
			schemasByID[schemaID] = schema
		}
	})
	return schemas, schemasErr
}

func structureError(path, keyword string) error {
	return fmt.Errorf("schema_invalid: %s (%s)", path, keyword)
}

func schemaPointer(document map[string]any, pointer string) (map[string]any, error) {
	var value any = document
	for _, raw := range strings.Split(pointer, "/") {
		if raw == "" {
			continue
		}
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("generated_schema_reference_invalid")
		}
		value, ok = object[token]
		if !ok {
			return nil, errors.New("generated_schema_reference_invalid")
		}
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("generated_schema_reference_invalid")
	}
	return result, nil
}

func resolveRef(root map[string]any, ref string) (map[string]any, map[string]any, error) {
	if strings.HasPrefix(ref, "#") {
		target, err := schemaPointer(root, strings.TrimPrefix(ref, "#"))
		return root, target, err
	}
	parts := strings.SplitN(ref, "#", 2)
	if len(parts) != 2 {
		return nil, nil, errors.New("generated_schema_reference_invalid")
	}
	if _, err := loadSchemas(); err != nil {
		return nil, nil, err
	}
	targetRoot, ok := schemasByID[parts[0]]
	if !ok {
		return nil, nil, errors.New("generated_schema_reference_invalid")
	}
	target, err := schemaPointer(targetRoot, parts[1])
	return targetRoot, target, err
}

func matchesSchema(root, schema map[string]any, value any, path string) bool {
	return validateSchema(root, schema, value, path) == nil
}

func jsonTypeMatches(expected string, value any) bool {
	switch expected {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		rational, ok := new(big.Rat).SetString(number.String())
		return ok && rational.IsInt()
	case "number":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, ok = new(big.Rat).SetString(number.String())
		return ok
	default:
		return true
	}
}

func equalJSON(left, right any) bool {
	leftNumber, leftIsNumber := left.(json.Number)
	rightNumber, rightIsNumber := right.(json.Number)
	if leftIsNumber || rightIsNumber {
		if !leftIsNumber || !rightIsNumber {
			return false
		}
		leftValue, leftOK := new(big.Rat).SetString(leftNumber.String())
		rightValue, rightOK := new(big.Rat).SetString(rightNumber.String())
		return leftOK && rightOK && leftValue.Cmp(rightValue) == 0
	}
	return reflect.DeepEqual(left, right)
}

func numericBound(value json.Number, rawBound any, minimum bool) bool {
	number, ok := new(big.Rat).SetString(value.String())
	if !ok {
		return false
	}
	var boundText string
	switch bound := rawBound.(type) {
	case float64:
		boundText = strconv.FormatFloat(bound, 'g', -1, 64)
	case json.Number:
		boundText = bound.String()
	default:
		return true
	}
	bound, ok := new(big.Rat).SetString(boundText)
	if !ok {
		return false
	}
	comparison := number.Cmp(bound)
	if minimum {
		return comparison >= 0
	}
	return comparison <= 0
}

var rfc3339Pattern = regexp.MustCompile(
	`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}` +
		`(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`,
)

func validRFC3339(value string) bool {
	if !rfc3339Pattern.MatchString(value) {
		return false
	}
	zone := value[len(value)-1:]
	zoneValue := "Z"
	if zone != "Z" {
		zoneValue = value[len(value)-6:]
		hour, hourErr := strconv.Atoi(zoneValue[1:3])
		minute, minuteErr := strconv.Atoi(zoneValue[4:6])
		if hourErr != nil || minuteErr != nil || hour > 23 || minute > 59 {
			return false
		}
	}
	seconds, secondsErr := strconv.Atoi(value[17:19])
	if secondsErr != nil || seconds > 60 {
		return false
	}
	baseSeconds := value[17:19]
	if seconds == 60 {
		baseSeconds = "59"
	}
	base := value[:17] + baseSeconds + zoneValue
	_, err := time.Parse("2006-01-02T15:04:05Z07:00", base)
	return err == nil
}

func validateSchema(root, schema map[string]any, value any, path string) error {
	if ref, ok := schema["$ref"].(string); ok {
		targetRoot, target, err := resolveRef(root, ref)
		if err != nil {
			return err
		}
		if err := validateSchema(targetRoot, target, value, path); err != nil {
			return err
		}
	}
	if expected, ok := schema["type"].(string); ok && !jsonTypeMatches(expected, value) {
		return structureError(path, "type")
	}
	if constant, ok := schema["const"]; ok && !equalJSON(value, constant) {
		return structureError(path, "const")
	}
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, candidate := range enum {
			if equalJSON(value, candidate) {
				found = true
				break
			}
		}
		if !found {
			return structureError(path, "enum")
		}
	}
	if branches, ok := schema["allOf"].([]any); ok {
		for _, rawBranch := range branches {
			if branch, ok := rawBranch.(map[string]any); ok {
				if err := validateSchema(root, branch, value, path); err != nil {
					return err
				}
			}
		}
	}
	if branches, ok := schema["anyOf"].([]any); ok {
		found := false
		for _, rawBranch := range branches {
			if branch, ok := rawBranch.(map[string]any); ok &&
				matchesSchema(root, branch, value, path) {
				found = true
				break
			}
		}
		if !found {
			return structureError(path, "anyOf")
		}
	}
	if branches, ok := schema["oneOf"].([]any); ok {
		count := 0
		for _, rawBranch := range branches {
			if branch, ok := rawBranch.(map[string]any); ok &&
				matchesSchema(root, branch, value, path) {
				count++
			}
		}
		if count != 1 {
			return structureError(path, "oneOf")
		}
	}
	if negated, ok := schema["not"].(map[string]any); ok &&
		matchesSchema(root, negated, value, path) {
		return structureError(path, "not")
	}
	if condition, ok := schema["if"].(map[string]any); ok {
		branchName := "else"
		if matchesSchema(root, condition, value, path) {
			branchName = "then"
		}
		if branch, ok := schema[branchName].(map[string]any); ok {
			if err := validateSchema(root, branch, value, path); err != nil {
				return err
			}
		}
	}

	if object, ok := value.(map[string]any); ok {
		if required, ok := schema["required"].([]any); ok {
			for _, rawName := range required {
				name, ok := rawName.(string)
				if !ok {
					continue
				}
				if _, present := object[name]; !present {
					return structureError(path, "required."+name)
				}
			}
		}
		properties, _ := schema["properties"].(map[string]any)
		additional, hasAdditional := schema["additionalProperties"]
		for name, child := range object {
			childPath := path + "." + name
			if rawChildSchema, exists := properties[name]; exists {
				if childSchema, ok := rawChildSchema.(map[string]any); ok {
					if err := validateSchema(root, childSchema, child, childPath); err != nil {
						return err
					}
				}
			} else if hasAdditional {
				if allow, ok := additional.(bool); ok && !allow {
					return structureError(childPath, "additionalProperties")
				}
				if childSchema, ok := additional.(map[string]any); ok {
					if err := validateSchema(root, childSchema, child, childPath); err != nil {
						return err
					}
				}
			}
		}
		if nameSchema, ok := schema["propertyNames"].(map[string]any); ok {
			for name := range object {
				if err := validateSchema(root, nameSchema, name, path+".<property>"); err != nil {
					return err
				}
			}
		}
		if maximum, ok := schema["maxProperties"].(float64); ok &&
			len(object) > int(maximum) {
			return structureError(path, "maxProperties")
		}
	}
	if array, ok := value.([]any); ok {
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for index, child := range array {
				if err := validateSchema(
					root,
					itemSchema,
					child,
					fmt.Sprintf("%s[%d]", path, index),
				); err != nil {
					return err
				}
			}
		}
		if maximum, ok := schema["maxItems"].(float64); ok &&
			len(array) > int(maximum) {
			return structureError(path, "maxItems")
		}
	}
	if text, ok := value.(string); ok {
		length := utf8.RuneCountInString(text)
		if minimum, ok := schema["minLength"].(float64); ok &&
			length < int(minimum) {
			return structureError(path, "minLength")
		}
		if maximum, ok := schema["maxLength"].(float64); ok &&
			length > int(maximum) {
			return structureError(path, "maxLength")
		}
		if pattern, ok := schema["pattern"].(string); ok {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return errors.New("generated_schema_pattern_invalid")
			}
			if !compiled.MatchString(text) {
				return structureError(path, "pattern")
			}
		}
		if format, ok := schema["format"].(string); ok &&
			format == "date-time" && !validRFC3339(text) {
			return structureError(path, "format")
		}
	}
	if number, ok := value.(json.Number); ok {
		if minimum, exists := schema["minimum"]; exists &&
			!numericBound(number, minimum, true) {
			return structureError(path, "minimum")
		}
		if maximum, exists := schema["maximum"]; exists &&
			!numericBound(number, maximum, false) {
			return structureError(path, "maximum")
		}
	}
	return nil
}

func validateDocument(kind string, document []byte) error {
	loaded, err := loadSchemas()
	if err != nil {
		return err
	}
	root, ok := loaded[kind]
	if !ok {
		return errors.New("unsupported_generated_document_kind")
	}
	value, err := decodeStrict(document)
	if err != nil {
		return err
	}
	if _, ok := value.(map[string]any); !ok {
		return structureError("$", "type")
	}
	return validateSchema(root, root, value, "$")
}
"""


def _go_parse_methods() -> str:
    rows: list[str] = []
    for kind, class_name in ROOT_CLASS_NAMES.items():
        rows.extend(
            [
                f"func (value *{class_name}) UnmarshalJSON(document []byte) error {{",
                f'\tif err := validateDocument("{kind}", document); err != nil {{',
                "\t\treturn err",
                "\t}",
                f"\ttype wire {class_name}",
                "\tdecoder := json.NewDecoder(bytes.NewReader(document))",
                "\tdecoder.DisallowUnknownFields()",
                "\tdecoder.UseNumber()",
                "\tvar parsed wire",
                "\tif err := decoder.Decode(&parsed); err != nil {",
                '\t\treturn structureError("$", "decode")',
                "\t}",
                f"\t*value = {class_name}(parsed)",
                "\treturn nil",
                "}",
                "",
                f"func (value {class_name}) structuralDocument() ([]byte, error) {{",
                f"\ttype wire {class_name}",
                "\treturn json.Marshal(wire(value))",
                "}",
                "",
                f"func (value {class_name}) ValidateStructural() error {{",
                "\tdocument, err := value.structuralDocument()",
                "\tif err != nil {",
                '\t\treturn wireError("invalid_json_value")',
                "\t}",
                f'\treturn validateDocument("{kind}", document)',
                "}",
                "",
                f"func (value {class_name}) MarshalJSON() ([]byte, error) {{",
                "\tdocument, err := value.structuralDocument()",
                "\tif err != nil {",
                '\t\treturn nil, wireError("invalid_json_value")',
                "\t}",
                f'\tif err := validateDocument("{kind}", document); err != nil {{',
                "\t\treturn nil, err",
                "\t}",
                "\treturn document, nil",
                "}",
                "",
                f"func Parse{class_name}(document []byte) ({class_name}, error) {{",
                f"\tvar value {class_name}",
                "\terr := value.UnmarshalJSON(document)",
                "\treturn value, err",
                "}",
                "",
            ]
        )
    return "\n".join(rows)


def _format_python(source: str) -> str:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--config",
            str(REPOSITORY_ROOT / "ruff.toml"),
            "--stdin-filename",
            PYTHON_OUTPUT.as_posix(),
            "-",
        ],
        input=source,
        text=True,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"ruff format failed:\n{result.stderr}")
    return result.stdout


def _format_go(source: str) -> str:
    try:
        result = subprocess.run(
            ["gofmt"],
            input=source,
            text=True,
            check=False,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("gofmt is required for deterministic generation") from exc
    if result.returncode != 0:
        raise SystemExit(f"gofmt failed:\n{result.stderr}")
    return result.stdout


def _render_go(schemas: SchemaSet) -> str:
    header = _schema_header(schemas.digest, "//")
    prelude = f'''{header}// Package protocol contains generated structural protocol DTOs.
//
// Parsing enforces JSON Schema structure only. Semantic authorization,
// time-order, approval-transition, and reconciliation trust checks remain in
// the SDK/reference validation layer.
package protocol

import (
\t"bytes"
\t"encoding/json"
\t"errors"
\t"fmt"
\t"io"
\t"math"
\t"math/big"
\t"reflect"
\t"regexp"
\t"strconv"
\t"strings"
\t"sync"
\t"time"
\t"unicode/utf8"
)

const SchemaDigest = "{schemas.digest}"
const GeneratorVersion = "{GENERATOR_VERSION}"
const SemanticValidationReference = "protocol/reference/validate.py"

'''
    source = (
        prelude
        + _go_string_types()
        + "\n\n"
        + _go_enums(schemas)
        + _go_objects(schemas)
        + _go_schema_map(schemas)
        + "\n"
        + _go_validation_runtime()
        + "\n"
        + _go_parse_methods()
    )
    return _format_go(source)


def _write_or_check(
    output_root: Path,
    outputs: dict[Path, str],
    *,
    check: bool,
) -> int:
    stale: list[Path] = []
    for relative, contents in outputs.items():
        destination = output_root / relative
        encoded = contents.encode("utf-8")
        if check:
            try:
                current = destination.read_bytes()
            except OSError:
                current = b""
            if current != encoded:
                stale.append(relative)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        temporary.write_bytes(encoded)
        temporary.replace(destination)
    if stale:
        for relative in stale:
            print(
                f"stale generated output: {relative.as_posix()}",
                file=sys.stderr,
            )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema-root",
        type=Path,
        default=DEFAULT_SCHEMA_ROOT,
        help="directory containing the six protocol version 1 schemas",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="repository-shaped output directory",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report stale outputs without modifying them",
    )
    arguments = parser.parse_args(argv)
    schemas = _read_schemas(arguments.schema_root)
    outputs = {
        PYTHON_OUTPUT: _render_python(schemas),
        GO_OUTPUT: _render_go(schemas),
    }
    return _write_or_check(
        arguments.output_root,
        outputs,
        check=arguments.check,
    )


if __name__ == "__main__":
    raise SystemExit(main())
