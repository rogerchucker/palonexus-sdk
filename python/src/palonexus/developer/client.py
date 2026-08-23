# SPDX-License-Identifier: MIT
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import RequestedCapabilityRule
from .credentials import CredentialStore

MAX_RESPONSE_BYTES = 64 * 1024
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_DEVICE_STATUS_TERMINAL_CODES = {
    "pending": "",
    "approved": "",
    "denied": "authorization_denied",
    "expired": "authorization_expired",
    "consumed": "authorization_consumed",
}
_DEVICE_STATUS_FIELDS = {
    "state",
    "expires_at",
    "interval_seconds",
    "terminal_code",
}
_DEVELOPER_RECEIPT_COMMON_FIELDS = {
    "schemaVersion",
    "receiptId",
    "opaqueDigest",
    "recordedAt",
    "verified",
    "tenantId",
    "runId",
    "rootId",
    "actionId",
    "payloadDigest",
    "targetRegistrationId",
    "targetRegistrationVersion",
    "effectIdempotencyKey",
    "effectId",
    "effectCreatedAt",
}
_DEVELOPER_RECEIPT_CURRENT_FIELDS = _DEVELOPER_RECEIPT_COMMON_FIELDS | {"capabilityId"}
_DEVELOPER_RECEIPT_GATEWAY_FIELDS = _DEVELOPER_RECEIPT_COMMON_FIELDS | {
    "gatewayDecisionId",
    "gatewayOutcome",
}
_DEVELOPER_DELIVERY_FIELDS = {
    "state",
    "attempts",
    "claimedBy",
    "claimToken",
    "claimedAt",
    "claimUntil",
    "capabilityId",
    "deliveredAt",
}
_DEVELOPER_DELIVERY_STATES = {
    "not_ready",
    "ready",
    "claimed",
    "delivered",
    "denied",
    "expired",
    "canceled",
    "failed_safe",
}


class DeveloperClientError(RuntimeError):
    """A fail-closed developer protocol error."""


class RequestRejected(DeveloperClientError):
    """An authenticated developer request was rejected by the server."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"server rejected request ({status_code})")
        self.status_code = status_code


class ProtocolError(DeveloperClientError):
    """A peer response violated the strict developer protocol."""


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON field")
        result[key] = value
    return result


def decode_strict_json(raw: bytes, allowed_fields: set[str]) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError("response JSON is empty or too large")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError, ProtocolError) as error:
        raise ProtocolError("response is not strict JSON") from error
    if not isinstance(value, dict) or set(value) - allowed_fields:
        raise ProtocolError("response contains an unknown field")
    return value


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise DeveloperClientError("auth URL must be an exact HTTPS origin")
    try:
        port = parsed.port
    except ValueError as error:
        raise DeveloperClientError("auth URL must be an exact HTTPS origin") from error
    if parsed.hostname is None:
        raise DeveloperClientError("auth URL must be an exact HTTPS origin")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    authority = host if port in (None, 443) else f"{host}:{port}"
    return f"https://{authority}"


def canonical_json(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError) as error:
        raise ProtocolError("value is not canonical JSON") from error


def build_device_proof(
    private_key: Ed25519PrivateKey,
    origin: str,
    method: str,
    escaped_path: str,
    canonical_body: bytes,
) -> str:
    digest = hashlib.sha256(canonical_body).digest()
    message = canonical_json(
        {
            "body_sha256": _b64url(digest),
            "method": method,
            "origin": _origin(origin),
            "path": escaped_path,
            "purpose": "palonexus.developer-device-redemption.v1",
        }
    )
    return _b64url(private_key.sign(message))


def generate_agent_credential() -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(public)}
    return {
        "private_key": _b64url(
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ),
        "public_key_jwk": canonical_json(public_jwk).decode("utf-8"),
        "device_jkt": _b64url(hashlib.sha256(canonical_json(public_jwk)).digest()),
    }


def _require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProtocolError(f"invalid {field}")
    return value


def _require_timestamp(value: object, field: str) -> str:
    raw = _require_string(value, field)
    if _RFC3339.fullmatch(raw) is None:
        raise ProtocolError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProtocolError(f"invalid {field}") from error
    if parsed.tzinfo is None:
        raise ProtocolError(f"invalid {field}")
    return raw


def _require_owner_subject(value: object, tenant_id: str) -> str:
    subject = _require_string(value, "owner_subject")
    pattern = (
        r"[a-z][a-z0-9-]{0,31}:" + re.escape(tenant_id) + r":[A-Za-z0-9._~-]{1,220}"
    )
    if re.fullmatch(pattern, subject) is None:
        raise ProtocolError("invalid owner_subject")
    return subject


def _require_poll_interval(value: object) -> int:
    if type(value) is not int or value < 1 or value > 60:
        raise ProtocolError("invalid polling interval")
    return value


def _require_positive_int(value: object, field: str) -> int:
    if type(value) is not int or value < 1 or value > 2_147_483_647:
        raise ProtocolError(f"invalid {field}")
    return value


def _validate_developer_action_response(response: dict[str, Any]) -> None:
    delivery = response.get("delivery")
    receipt = response.get("receipt")
    if delivery is None and receipt is None:
        return
    if not isinstance(delivery, dict):
        raise ProtocolError("developer action has an invalid delivery")
    if set(delivery) - _DEVELOPER_DELIVERY_FIELDS:
        raise ProtocolError("developer action delivery contains an unknown field")
    state = delivery.get("state")
    if state not in _DEVELOPER_DELIVERY_STATES:
        raise ProtocolError("developer action has an invalid delivery state")
    attempts = delivery.get("attempts")
    if attempts is not None and (type(attempts) is not int or not 0 <= attempts <= 3):
        raise ProtocolError("developer action has invalid delivery attempts")
    for field in ("claimedBy", "claimToken"):
        if field in delivery and len(_require_string(delivery.get(field), field)) > 256:
            raise ProtocolError(f"invalid {field}")
    for field in ("claimedAt", "claimUntil", "deliveredAt"):
        if field in delivery:
            _require_timestamp(delivery.get(field), field)
    delivery_capability_id = delivery.get("capabilityId")
    if delivery_capability_id is not None:
        if (
            state not in {"claimed", "delivered"}
            or len(_require_string(delivery_capability_id, "delivery capabilityId"))
            > 256
        ):
            raise ProtocolError("developer action has invalid delivery capability")
    delivered = state == "delivered"
    if receipt is None:
        if delivered:
            raise ProtocolError("delivered developer action has no receipt")
        return
    if not delivered or not isinstance(receipt, dict):
        raise ProtocolError("developer action has an invalid receipt")

    fields = set(receipt)
    current = fields == _DEVELOPER_RECEIPT_CURRENT_FIELDS
    historical = fields == _DEVELOPER_RECEIPT_GATEWAY_FIELDS
    if not current and not historical:
        raise ProtocolError("developer action receipt has an invalid evidence shape")
    if receipt.get("schemaVersion") != "palonexus.developer-receipt-reference/v1":
        raise ProtocolError("developer action receipt has an invalid schema")
    if receipt.get("verified") is not True:
        raise ProtocolError("developer action receipt is not verified")
    for field in (
        "receiptId",
        "tenantId",
        "runId",
        "rootId",
        "actionId",
        "targetRegistrationId",
        "effectIdempotencyKey",
        "effectId",
    ):
        if len(_require_string(receipt.get(field), field)) > 256:
            raise ProtocolError(f"invalid {field}")
    for field in ("opaqueDigest", "payloadDigest"):
        if re.fullmatch(r"[0-9a-f]{64}", str(receipt.get(field))) is None:
            raise ProtocolError(f"invalid {field}")
    _require_positive_int(
        receipt.get("targetRegistrationVersion"), "target registration version"
    )
    recorded_at = _require_timestamp(receipt.get("recordedAt"), "recordedAt")
    effect_at = _require_timestamp(receipt.get("effectCreatedAt"), "effectCreatedAt")
    if datetime.fromisoformat(
        effect_at.replace("Z", "+00:00")
    ) > datetime.fromisoformat(recorded_at.replace("Z", "+00:00")):
        raise ProtocolError("developer action receipt time is invalid")
    if current:
        capability_id = _require_string(receipt.get("capabilityId"), "capabilityId")
        if len(capability_id) > 256 or delivery_capability_id != capability_id:
            raise ProtocolError("invalid capabilityId")
    else:
        if delivery_capability_id is not None:
            raise ProtocolError("historical receipt has current capability evidence")
        if (
            len(_require_string(receipt.get("gatewayDecisionId"), "gatewayDecisionId"))
            > 256
            or receipt.get("gatewayOutcome") != "allow"
        ):
            raise ProtocolError("invalid historical gateway evidence")

    target = response.get("target")
    if not isinstance(target, dict):
        raise ProtocolError("developer action has an invalid target")
    correlations = {
        "tenantId": response.get("tenantId"),
        "runId": response.get("runId"),
        "rootId": response.get("rootId"),
        "actionId": response.get("actionId"),
        "payloadDigest": response.get("payloadDigest"),
        "targetRegistrationId": target.get("registrationId"),
        "targetRegistrationVersion": target.get("version"),
        "effectIdempotencyKey": response.get("effectIdempotencyKey"),
    }
    if any(receipt.get(field) != value for field, value in correlations.items()):
        raise ProtocolError("developer action receipt is not bound to the action")


def _decode_private_key(value: object) -> Ed25519PrivateKey:
    encoded = _require_string(value, "agent private key")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, TypeError) as error:
        raise ProtocolError("invalid agent private key") from error
    if (
        len(raw) != 32
        or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded
    ):
        raise ProtocolError("invalid agent private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


_REGISTRATION_RESPONSE_FIELDS = {
    "schema_version",
    "agent_id",
    "name",
    "tenant_id",
    "accountable_owner",
    "descriptor_digest",
    "key_thumbprint",
    "generation",
    "status",
    "capabilities",
    "descriptor_version",
    "runtime_profile",
    "composition_digest",
    "harness_adapter_contracts",
    "not_before",
    "expires_at",
}
_REVOCATION_RESPONSE_FIELDS = {
    "schema_version",
    "event_id",
    "tenant_id",
    "agent_id",
    "previous_generation",
    "generation",
    "actor",
    "revoked_at",
    "cascade_status",
    "cascade_applied_at",
}
_CEILING_RESPONSE_FIELDS = {
    "schemaVersion",
    "requestId",
    "version",
    "tenantId",
    "agentName",
    "agentGeneration",
    "descriptorDigest",
    "requestedBy",
    "requestedRules",
    "resolvedRules",
    "catalogVersion",
    "requestHash",
    "status",
    "expiresAt",
    "createdAt",
}
_RESOLVED_RULE_FIELDS = {
    "schemaVersion",
    "capabilityId",
    "capabilityVersion",
    "canonicalAction",
    "resource",
    "constraints",
    "target",
    "approvalMode",
}
_TARGET_REF_REQUIRED_FIELDS = {
    "registrationId",
    "version",
    "mappingHash",
    "target",
    "targetKind",
    "action",
    "audience",
    "downstreamScope",
}
_DECISION_FIELDS = {"decision", "expectedVersion", "actor", "reason", "at"}


def _validate_approval_url(value: object, agent_name: str, request_id: str) -> str:
    raw = _require_string(value, "approvalUrl")
    parsed = urlsplit(raw)
    expected_path = "/developer-agents/" + quote(agent_name, safe="")
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != expected_path
        or query != {"request": [request_id]}
    ):
        raise ProtocolError("approval URL is unsafe or not bound to the request")
    return raw


def _validate_registration_response(
    response: dict[str, Any],
    *,
    session: dict[str, str],
    name: str,
    descriptor_digest: str,
    key_thumbprint: str,
    authority_profile: dict[str, Any],
) -> dict[str, Any]:
    _validate_registered_agent_projection(response, session=session, name=name)
    if response.get("descriptor_digest") != descriptor_digest:
        raise ProtocolError("agent registration response is not bound to the request")
    if response.get("key_thumbprint") != key_thumbprint:
        raise ProtocolError("agent registration response is not bound to the request")
    if any(
        response.get(field) != expected for field, expected in authority_profile.items()
    ):
        raise ProtocolError(
            "agent registration response has a different authority profile"
        )
    return response


def _validate_registered_agent_projection(
    response: dict[str, Any], *, session: dict[str, str], name: str
) -> dict[str, Any]:
    if set(response) != _REGISTRATION_RESPONSE_FIELDS:
        raise ProtocolError("invalid agent registration response shape")
    owner_subject = session.get("owner_subject")
    owner_field = "owner_subject"
    if owner_subject is None:
        owner_subject = session.get("membership_id")
        owner_field = "membership_id"
    expected_strings = {
        "schema_version": "palonexus.developer-agent/v1",
        "name": name,
        "tenant_id": _require_string(session.get("tenant_id"), "tenant_id"),
        "accountable_owner": _require_string(owner_subject, owner_field),
        "status": "registered",
    }
    if any(response.get(field) != value for field, value in expected_strings.items()):
        raise ProtocolError("agent registration response is not bound to the request")
    if _require_string(response.get("agent_id"), "agent_id") != name:
        raise ProtocolError("agent registration response has an unexpected agent ID")
    _require_positive_int(response.get("generation"), "generation")
    for field in ("descriptor_digest", "key_thumbprint"):
        value = _require_string(response.get(field), field)
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ProtocolError("registered agent identity has an invalid digest")
    if response.get("capabilities") != []:
        raise ProtocolError("new agent registration unexpectedly contains authority")
    _registration_authority_profile(
        {
            "schema_version": "palonexus.agent-registration-profile/v1",
            **{
                field: response.get(field)
                for field in _REGISTRATION_PROFILE_FIELDS
                if field != "schema_version"
            },
        }
    )
    return response


_REGISTRATION_PROFILE_FIELDS = {
    "schema_version",
    "descriptor_version",
    "runtime_profile",
    "composition_digest",
    "harness_adapter_contracts",
    "not_before",
    "expires_at",
}


def _registration_authority_profile(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _REGISTRATION_PROFILE_FIELDS:
        raise ProtocolError("invalid agent registration profile")
    if value.get("schema_version") != "palonexus.agent-registration-profile/v1":
        raise ProtocolError("unsupported agent registration profile")
    descriptor_version = _require_string(
        value.get("descriptor_version"), "descriptor version"
    )
    if re.fullmatch(r"[a-z0-9][a-z0-9._:/-]{0,255}", descriptor_version) is None:
        raise ProtocolError("invalid descriptor version")
    runtime_profile = value.get("runtime_profile")
    if not isinstance(runtime_profile, dict) or not runtime_profile:
        raise ProtocolError("invalid runtime profile")
    canonical_json(runtime_profile)
    composition_digest = _require_string(
        value.get("composition_digest"), "composition digest"
    )
    if re.fullmatch(r"[0-9a-f]{64}", composition_digest) is None:
        raise ProtocolError("invalid composition digest")
    contracts = value.get("harness_adapter_contracts")
    if (
        not isinstance(contracts, list)
        or not 1 <= len(contracts) <= 64
        or any(
            not isinstance(contract, str)
            or contract != contract.strip()
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", contract) is None
            for contract in contracts
        )
        or len(set(contracts)) != len(contracts)
    ):
        raise ProtocolError("invalid harness adapter contracts")
    not_before = _require_timestamp(value.get("not_before"), "not_before")
    expires_at = _require_timestamp(value.get("expires_at"), "expires_at")
    parsed_not_before = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
    parsed_expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if parsed_expires_at <= parsed_not_before:
        raise ProtocolError("agent registration profile has an invalid validity window")
    return {
        "descriptor_version": descriptor_version,
        "runtime_profile": runtime_profile,
        "composition_digest": composition_digest,
        "harness_adapter_contracts": contracts,
        "not_before": not_before,
        "expires_at": expires_at,
    }


def _validate_revocation_response(
    response: dict[str, Any],
    *,
    session: dict[str, str],
    agent_id: str,
    expected_previous_generation: int,
) -> dict[str, Any]:
    if set(response) != _REVOCATION_RESPONSE_FIELDS:
        raise ProtocolError("invalid agent revocation response shape")
    tenant_id = _require_string(session.get("tenant_id"), "tenant_id")
    membership_id = _require_string(session.get("membership_id"), "membership_id")
    expected_event_id = f"revoke:{agent_id}:{expected_previous_generation}"
    if (
        response.get("schema_version") != "palonexus.developer-revocation/v1"
        or response.get("event_id") != expected_event_id
        or response.get("tenant_id") != tenant_id
        or response.get("agent_id") != agent_id
        or response.get("actor") != membership_id
    ):
        raise ProtocolError("agent revocation response is not bound to the request")
    previous_generation = _require_positive_int(
        response.get("previous_generation"), "previous_generation"
    )
    generation = _require_positive_int(response.get("generation"), "generation")
    if (
        previous_generation != expected_previous_generation
        or generation != previous_generation + 1
    ):
        raise ProtocolError("agent revocation response has an invalid generation")
    revoked_at = _require_timestamp(response.get("revoked_at"), "revoked_at")
    cascade_applied_at = _require_timestamp(
        response.get("cascade_applied_at"), "cascade_applied_at"
    )
    if response.get("cascade_status") != "applied":
        raise ProtocolError("agent revocation cascade is not durably applied")
    if datetime.fromisoformat(
        cascade_applied_at.replace("Z", "+00:00")
    ) < datetime.fromisoformat(revoked_at.replace("Z", "+00:00")):
        raise ProtocolError("agent revocation cascade predates revocation")
    return response


def _validate_ceiling_response(
    response: dict[str, Any],
    *,
    session: dict[str, str],
    agent_name: str,
    request_id: str,
    descriptor_digest: str | None = None,
    agent_generation: int | None = None,
    expected_requested_rules: object | None = None,
) -> dict[str, Any]:
    fields = set(response)
    if fields not in (
        _CEILING_RESPONSE_FIELDS,
        _CEILING_RESPONSE_FIELDS | {"decision"},
        _CEILING_RESPONSE_FIELDS | {"approvalUrl"},
        _CEILING_RESPONSE_FIELDS | {"decision", "approvalUrl"},
    ):
        raise ProtocolError("invalid ceiling response shape")
    if (
        response.get("schemaVersion") != "palonexus.ceiling-request/v1"
        or response.get("requestId") != request_id
        or response.get("tenantId")
        != _require_string(session.get("tenant_id"), "tenant_id")
        or response.get("agentName") != agent_name
    ):
        raise ProtocolError("ceiling response is not bound to the request")
    _require_positive_int(response.get("version"), "version")
    response_generation = _require_positive_int(
        response.get("agentGeneration"), "agentGeneration"
    )
    if agent_generation is not None and response_generation != agent_generation:
        raise ProtocolError("ceiling response is not bound to the request")
    _require_positive_int(response.get("catalogVersion"), "catalogVersion")
    digest = _require_string(response.get("descriptorDigest"), "descriptorDigest")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or (
        descriptor_digest is not None and digest != descriptor_digest
    ):
        raise ProtocolError("ceiling response has an invalid descriptor digest")
    request_hash = _require_string(response.get("requestHash"), "requestHash")
    if not re.fullmatch(r"[0-9a-f]{64}", request_hash):
        raise ProtocolError("ceiling response has an invalid request hash")
    _require_string(response.get("requestedBy"), "requestedBy")
    _require_timestamp(response.get("expiresAt"), "expiresAt")
    _require_timestamp(response.get("createdAt"), "createdAt")
    status = response.get("status")
    if status not in {"pending", "approved", "denied", "expired"}:
        raise ProtocolError("ceiling response has an invalid status")
    requested_rules = response.get("requestedRules")
    if not isinstance(requested_rules, list) or not requested_rules:
        raise ProtocolError("ceiling response has invalid requested rules")
    try:
        for rule in requested_rules:
            RequestedCapabilityRule.model_validate(rule)
    except ValueError as error:
        raise ProtocolError("ceiling response has invalid requested rules") from error
    if expected_requested_rules is not None and canonical_json(
        response["requestedRules"]
    ) != canonical_json(expected_requested_rules):
        raise ProtocolError("ceiling response is not bound to the request")
    resolved_rules = response.get("resolvedRules")
    if not isinstance(resolved_rules, list):
        raise ProtocolError("ceiling response has invalid resolved rules")
    for rule in resolved_rules:
        if not isinstance(rule, dict) or set(rule) != _RESOLVED_RULE_FIELDS:
            raise ProtocolError("ceiling response has invalid resolved rules")
        if rule.get("schemaVersion") != "1" or rule.get("approvalMode") not in {
            "automatic",
            "human_per_root_action",
        }:
            raise ProtocolError("ceiling response has invalid resolved rules")
        for field in ("capabilityId", "canonicalAction", "resource"):
            _require_string(rule.get(field), field)
        _require_positive_int(rule.get("capabilityVersion"), "capabilityVersion")
        if not isinstance(rule.get("constraints"), dict):
            raise ProtocolError("ceiling response has invalid resolved rules")
        target = rule.get("target")
        if not isinstance(target, dict) or set(target) not in (
            _TARGET_REF_REQUIRED_FIELDS,
            _TARGET_REF_REQUIRED_FIELDS | {"endpoint"},
        ):
            raise ProtocolError("ceiling response has invalid target reference")
        for field in _TARGET_REF_REQUIRED_FIELDS - {"version"}:
            _require_string(target.get(field), field)
        _require_positive_int(target.get("version"), "target version")
        if re.fullmatch(r"[0-9a-f]{64}", str(target["mappingHash"])) is None:
            raise ProtocolError("ceiling response has invalid target mapping hash")
        if "endpoint" in target:
            _require_string(target.get("endpoint"), "endpoint")
    if status == "pending" and "decision" in response:
        raise ProtocolError("pending ceiling response unexpectedly has a decision")
    if status in {"approved", "denied"}:
        decision = response.get("decision")
        if not isinstance(decision, dict) or set(decision) != _DECISION_FIELDS:
            raise ProtocolError("terminal ceiling response has an invalid decision")
        expected_decision = "approve" if status == "approved" else "deny"
        if (
            decision.get("decision") != expected_decision
            or decision.get("expectedVersion") != response["version"]
        ):
            raise ProtocolError("terminal ceiling response has an invalid decision")
        for field in ("actor", "reason"):
            _require_string(decision.get(field), field)
        _require_timestamp(decision.get("at"), "decision at")
    if "approvalUrl" in response:
        _validate_approval_url(response["approvalUrl"], agent_name, request_id)
    return response


def _validate_device_authorization_status(status: dict[str, Any]) -> str:
    if set(status) != _DEVICE_STATUS_FIELDS:
        raise ProtocolError("invalid device authorization status shape")
    state = status["state"]
    if type(state) is not str or state not in _DEVICE_STATUS_TERMINAL_CODES:
        raise ProtocolError("invalid device authorization state")
    _require_timestamp(status["expires_at"], "expires_at")
    _require_poll_interval(status["interval_seconds"])
    terminal_code = status["terminal_code"]
    if (
        type(terminal_code) is not str
        or terminal_code != _DEVICE_STATUS_TERMINAL_CODES[state]
    ):
        raise ProtocolError("invalid device authorization terminal code")
    return state


def _validate_device_session(
    token: dict[str, Any], expected_jkt: str
) -> dict[str, str]:
    if token.get("kind") != "developer_session":
        raise ProtocolError("invalid session kind")
    role = _require_string(token.get("role"), "role")
    if role not in {"owner", "admin", "member"}:
        raise ProtocolError("invalid role")
    device_jkt = _require_string(token.get("device_jkt"), "device_jkt")
    if device_jkt != expected_jkt:
        raise ProtocolError("session device key does not match")
    session_token = _require_string(token.get("session_token"), "session_token")
    if not session_token.startswith("pnx_dev_") or len(session_token) > 256:
        raise ProtocolError("invalid session_token")
    created_at = _require_timestamp(token.get("created_at"), "created_at")
    expires_at = _require_timestamp(token.get("expires_at"), "expires_at")
    if datetime.fromisoformat(
        expires_at.replace("Z", "+00:00")
    ) <= datetime.fromisoformat(created_at.replace("Z", "+00:00")):
        raise ProtocolError("invalid session time order")
    tenant_id = _require_string(token.get("tenant_id"), "tenant_id")
    return {
        "session_token": session_token,
        "session_id": _require_string(token.get("session_id"), "session_id"),
        "tenant_id": tenant_id,
        "membership_id": _require_string(token.get("membership_id"), "membership_id"),
        "owner_subject": _require_owner_subject(token.get("owner_subject"), tenant_id),
        "role": role,
        "device_jkt": device_jkt,
        "created_at": created_at,
        "expires_at": expires_at,
    }


class DeveloperClient:
    def __init__(
        self,
        auth_url: str,
        *,
        tenant_hint: str | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.origin = _origin(auth_url)
        if tenant_hint is not None and (
            not tenant_hint
            or tenant_hint != tenant_hint.strip()
            or len(tenant_hint) > 128
        ):
            raise DeveloperClientError("tenant hint is invalid")
        self.tenant_hint = tenant_hint
        self.http = httpx.Client(
            base_url=self.origin,
            transport=transport,
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: int | set[int] = 200,
        allowed_fields: set[str],
    ) -> dict[str, Any]:
        request_headers = {"Accept": "application/json"}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)
        try:
            with self.http.stream(
                method, path, content=body, headers=request_headers
            ) as response:
                expected_codes = {expected} if isinstance(expected, int) else expected
                if response.status_code not in expected_codes:
                    raise RequestRejected(response.status_code)
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_bytes(chunk_size=MAX_RESPONSE_BYTES + 1):
                    remaining = MAX_RESPONSE_BYTES + 1 - received
                    chunks.append(chunk[:remaining])
                    received += min(len(chunk), remaining)
                    if received > MAX_RESPONSE_BYTES:
                        raise ProtocolError("response is too large")
                raw = b"".join(chunks)
        except (DeveloperClientError, ProtocolError):
            raise
        except httpx.HTTPError:
            raise DeveloperClientError(
                "developer authorization service unavailable"
            ) from None
        return decode_strict_json(raw, allowed_fields)

    def login(
        self,
        store: CredentialStore,
        *,
        on_authorization: Callable[[dict[str, str]], None] | None = None,
    ) -> dict[str, str]:
        private_key = Ed25519PrivateKey.generate()
        public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(public)}
        jkt = _b64url(hashlib.sha256(canonical_json(public_jwk)).digest())
        verifier = secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode("utf-8")).digest())
        create_body = canonical_json(
            {"code_challenge": challenge, "device_public_jwk": public_jwk}
        )
        path = "/v1/developer/device-authorizations"
        if self.tenant_hint is not None:
            path += "?tenant=" + quote(self.tenant_hint, safe="")
        created = self._request(
            "POST",
            path,
            body=create_body,
            expected=201,
            allowed_fields={
                "transaction_id",
                "user_code",
                "verification_url",
                "expires_at",
                "interval_seconds",
            },
        )
        transaction_id = _require_string(
            created.get("transaction_id"), "transaction_id"
        )
        user_code = _require_string(created.get("user_code"), "user_code")
        verification_url = _require_string(
            created.get("verification_url"), "verification_url"
        )
        expected_verification_url = (
            self.origin
            + "/developer/device-authorizations/"
            + quote(user_code, safe="")
        )
        if verification_url != expected_verification_url:
            raise ProtocolError("verification URL is not bound to the authorization")
        interval = _require_poll_interval(created.get("interval_seconds"))
        expires_raw = _require_timestamp(created.get("expires_at"), "expires_at")
        expires_at = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
        authorization = {
            "user_code": user_code,
            "verification_url": verification_url,
        }
        if on_authorization is not None:
            on_authorization(authorization)

        status_path = "/v1/developer/device-authorizations/" + quote(
            transaction_id, safe=""
        )
        while datetime.now(UTC) < expires_at:
            status = self._request(
                "GET",
                status_path,
                headers={"X-Palonexus-Transaction-Verifier": verifier},
                allowed_fields={
                    "state",
                    "expires_at",
                    "interval_seconds",
                    "terminal_code",
                },
            )
            state = _validate_device_authorization_status(status)
            if state == "approved":
                break
            if state in {"denied", "expired", "consumed"}:
                raise DeveloperClientError(f"device authorization {state}")
            if state != "pending":
                raise ProtocolError("invalid device authorization state")
            time.sleep(interval)
        else:
            raise DeveloperClientError("device authorization expired")

        token_path = status_path + "/token"
        token_body = canonical_json({"verifier": verifier})
        token = self._request(
            "POST",
            token_path,
            body=token_body,
            headers={
                "X-Palonexus-Device-Proof": build_device_proof(
                    private_key, self.origin, "POST", token_path, token_body
                )
            },
            allowed_fields={
                "kind",
                "session_id",
                "tenant_id",
                "account_id",
                "membership_id",
                "owner_subject",
                "role",
                "device_jkt",
                "created_at",
                "expires_at",
                "session_token",
            },
        )
        session = _validate_device_session(token, jkt)
        session["issuer_origin"] = self.origin
        if self.tenant_hint is not None and session["tenant_id"] != self.tenant_hint:
            try:
                self.logout(session)
            except DeveloperClientError as error:
                raise DeveloperClientError(
                    "wrong-tenant developer session cleanup failed"
                ) from error
            raise DeveloperClientError(
                "device authorization was approved for a different tenant"
            )
        session["device_private_key"] = _b64url(
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        store.save("session", session)
        return authorization

    def logout(self, credential: dict[str, str]) -> bool:
        token = _require_string(credential.get("session_token"), "session token")
        session_id = _require_string(credential.get("session_id"), "session ID")
        issuer_origin = _require_string(
            credential.get("issuer_origin"), "issuer origin"
        )
        if _origin(issuer_origin) != issuer_origin or issuer_origin != self.origin:
            raise ProtocolError("session issuer origin does not match")
        try:
            response = self._request(
                "DELETE",
                "/v1/developer/sessions/" + quote(session_id, safe=""),
                headers={"Authorization": "Bearer " + token},
                allowed_fields={"status", "session_id"},
            )
        except RequestRejected as error:
            # An expired or already-revoked developer session no longer
            # authorizes this request, so Cloud Auth answers 401. That is the
            # idempotent logout outcome: no remote authority remains and the
            # caller may safely clear its local credential. Other status codes
            # still fail closed because they do not prove inactivity.
            if error.status_code == 401:
                return False
            raise
        if set(response) != {"status", "session_id"}:
            raise ProtocolError("invalid logout response shape")
        if response["status"] != "revoked" or response["session_id"] != session_id:
            raise ProtocolError("invalid logout confirmation")
        return True

    def register_agent(
        self,
        session: dict[str, str],
        agent: dict[str, str],
        descriptor: dict[str, Any],
    ) -> dict[str, Any]:
        private = _decode_private_key(agent.get("private_key"))
        try:
            jwk = json.loads(
                _require_string(agent.get("public_key_jwk"), "agent public key")
            )
        except json.JSONDecodeError as error:
            raise ProtocolError("invalid agent public key") from error
        if (
            not isinstance(jwk, dict)
            or set(jwk) != {"kty", "crv", "x"}
            or jwk.get("kty") != "OKP"
            or jwk.get("crv") != "Ed25519"
        ):
            raise ProtocolError("invalid agent public key")
        thumbprint = hashlib.sha256(canonical_json(jwk)).hexdigest()
        name = _require_string(descriptor.get("name"), "agent name")
        digest = _require_string(
            descriptor.get("descriptor_digest"), "descriptor digest"
        )
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ProtocolError("invalid descriptor digest")
        authority_profile = _registration_authority_profile(
            descriptor.get("authority_profile")
        )
        message = canonical_json(
            {
                "authority_profile": authority_profile,
                "descriptor_digest": digest,
                "key_thumbprint": thumbprint,
                "name": name,
                "purpose": "palonexus.developer-agent-registration.v1",
            }
        )
        request = {
            "schema_version": "palonexus.developer-agent/v1",
            "name": name,
            "descriptor_digest": digest,
            "public_key_jwk": jwk,
            **authority_profile,
            "proof": {
                "alg": "EdDSA",
                "key_thumbprint": thumbprint,
                "signature": _b64url(private.sign(message)),
            },
        }
        body = canonical_json(request)
        response = self._request(
            "POST",
            "/v1/developer/agents",
            body=body,
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token"),
                "Idempotency-Key": hashlib.sha256(body).hexdigest(),
            },
            expected=201,
            allowed_fields=_REGISTRATION_RESPONSE_FIELDS,
        )
        return _validate_registration_response(
            response,
            session=session,
            name=name,
            descriptor_digest=digest,
            key_thumbprint=thumbprint,
            authority_profile=authority_profile,
        )

    def registered_agent(
        self, session: dict[str, str], agent_name: str
    ) -> dict[str, Any]:
        """Resolve the immutable owner-bound registration projection."""
        name = _require_string(agent_name, "agent name")
        response = self._request(
            "GET",
            "/v1/developer/agents/" + quote(name, safe=""),
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token")
            },
            allowed_fields=_REGISTRATION_RESPONSE_FIELDS,
        )
        return _validate_registered_agent_projection(
            response, session=session, name=name
        )

    def revoke_agent(
        self,
        session: dict[str, str],
        agent_name: str,
        agent_id: str,
        *,
        expected_previous_generation: int,
    ) -> dict[str, Any]:
        name = _require_string(agent_name, "agent name")
        stable_agent_id = _require_string(agent_id, "agent ID")
        if name != stable_agent_id:
            raise ProtocolError("stored agent identity is not bound to its name")
        previous_generation = _require_positive_int(
            expected_previous_generation, "previous generation"
        )
        _require_string(session.get("tenant_id"), "tenant_id")
        _require_string(session.get("membership_id"), "membership_id")
        path = "/v1/developer/agents/" + quote(name, safe="")
        response = self._request(
            "DELETE",
            path,
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token"),
                "Idempotency-Key": hashlib.sha256(
                    ("DELETE " + path).encode("ascii")
                ).hexdigest(),
            },
            allowed_fields=_REVOCATION_RESPONSE_FIELDS,
        )
        return _validate_revocation_response(
            response,
            session=session,
            agent_id=stable_agent_id,
            expected_previous_generation=previous_generation,
        )

    def request_authority(
        self,
        session: dict[str, str],
        agent_name: str,
        request_id: str,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        if set(request_body) != {
            "schemaVersion",
            "agentGeneration",
            "descriptorDigest",
            "expiresAt",
            "rules",
        }:
            raise ProtocolError("invalid ceiling request shape")
        name = _require_string(agent_name, "agent name")
        stable_id = _require_string(request_id, "request ID")
        body = canonical_json(request_body)
        response = self._request(
            "POST",
            f"/v1/developer/agents/{quote(name, safe='')}/ceiling-requests",
            body=body,
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token"),
                "Idempotency-Key": stable_id,
            },
            expected=201,
            allowed_fields=_CEILING_RESPONSE_FIELDS | {"decision", "approvalUrl"},
        )
        return _validate_ceiling_response(
            response,
            session=session,
            agent_name=name,
            request_id=stable_id,
            descriptor_digest=str(request_body["descriptorDigest"]),
            agent_generation=int(request_body["agentGeneration"]),
            expected_requested_rules=request_body["rules"],
        )

    def agent_status(
        self, session: dict[str, str], name: str, request_id: str
    ) -> dict[str, Any]:
        agent_name = _require_string(name, "agent name")
        stable_id = _require_string(request_id, "request ID")
        response = self._request(
            "GET",
            f"/v1/developer/agents/{quote(agent_name, safe='')}"
            f"/ceiling-requests/{quote(stable_id, safe='')}",
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token")
            },
            allowed_fields=_CEILING_RESPONSE_FIELDS | {"decision"},
        )
        return _validate_ceiling_response(
            response,
            session=session,
            agent_name=agent_name,
            request_id=stable_id,
        )

    @staticmethod
    def mounted_proof(
        private: Ed25519PrivateKey,
        *,
        mode: str,
        tenant_id: str,
        agent_id: str,
        agent_generation: int,
        method: str,
        path: str,
        body: bytes,
        enrollment_id: str | None = None,
        runtime_id: str | None = None,
    ) -> str:
        value = {
            "purpose": "palonexus.developer-mounted-proof.v1",
            "mode": mode,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "agent_generation": agent_generation,
            "method": method,
            "escaped_path": path,
            "body_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "issued_at": int(time.time()),
            "nonce": secrets.token_urlsafe(18),
        }
        value["enrollment_id" if mode == "enrollment_proof" else "runtime_id"] = (
            enrollment_id if mode == "enrollment_proof" else runtime_id
        )
        value["signature"] = _b64url(private.sign(canonical_json(value)))
        return _b64url(canonical_json(value))

    def create_runtime_enrollment(
        self,
        session: dict[str, str],
        agent: dict[str, str],
        descriptor: dict[str, Any],
        guard: dict[str, str],
        *,
        idempotency_key: str,
        artifact_identity: str,
        runtime_instance_id: str,
        guard_version: str,
    ) -> dict[str, Any]:
        agent_private = _decode_private_key(agent.get("private_key"))
        guard_jwk = json.loads(
            _require_string(guard.get("public_key_jwk"), "guard public key")
        )
        generation = _require_positive_int(
            int(agent.get("agent_generation", "0")), "agent generation"
        )
        signed = {
            "purpose": "palonexus.developer-runtime-enrollment.v1",
            "agent_id": _require_string(agent.get("agent_id"), "agent ID"),
            "agent_generation": generation,
            "descriptor_digest": _require_string(
                descriptor.get("descriptor_digest"), "descriptor digest"
            ),
            "artifact_identity": artifact_identity,
            "runtime_instance_id": runtime_instance_id,
            "guard_version": guard_version,
            "guard_public_key_jwk": guard_jwk,
        }
        proof = {
            **signed,
            "signature": _b64url(agent_private.sign(canonical_json(signed))),
        }
        request = {
            "schema_version": "palonexus.runtime-enrollment/v1",
            **signed,
            "agent_proof": proof,
        }
        return self._request(
            "POST",
            "/v1/developer/runtime-enrollments",
            body=canonical_json(request),
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token"),
                "Idempotency-Key": idempotency_key,
            },
            expected={200, 201},
            allowed_fields={
                "schema_version",
                "enrollment_id",
                "agent_id",
                "agent_generation",
                "descriptor_digest",
                "artifact_identity",
                "runtime_instance_id",
                "guard_version",
                "status",
                "expires_at",
            },
        )

    def redeem_runtime(
        self, session: dict[str, str], agent: dict[str, str], enrollment: dict[str, Any]
    ) -> dict[str, Any]:
        path = (
            "/v1/developer/runtime-enrollments/"
            + quote(
                _require_string(enrollment.get("enrollment_id"), "enrollment ID"),
                safe="",
            )
            + "/redeem"
        )
        body = canonical_json({})
        private = _decode_private_key(agent.get("private_key"))
        proof = self.mounted_proof(
            private,
            mode="enrollment_proof",
            tenant_id=_require_string(session.get("tenant_id"), "tenant ID"),
            agent_id=_require_string(agent.get("agent_id"), "agent ID"),
            agent_generation=int(agent["agent_generation"]),
            method="POST",
            path=path,
            body=body,
            enrollment_id=enrollment["enrollment_id"],
        )
        return self._request(
            "POST",
            path,
            body=body,
            headers={"X-Palonexus-Developer-Proof": proof},
            allowed_fields={
                "schema_version",
                "runtime_id",
                "agent_id",
                "agent_generation",
                "descriptor_digest",
                "artifact_identity",
                "runtime_instance_id",
                "guard_version",
                "status",
                "issued_at",
                "expires_at",
            },
        )

    def create_developer_run(
        self,
        session: dict[str, Any],
        agent: dict[str, Any],
        guard: dict[str, Any],
        runtime: dict[str, Any],
        *,
        input_digest: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        path = "/v1/developer/runs"
        body = canonical_json(
            {
                "schemaVersion": "palonexus.developer-run-request/v1",
                "inputDigest": input_digest,
                "idempotencyKey": idempotency_key,
            }
        )
        proof = self.mounted_proof(
            _decode_private_key(guard.get("private_key")),
            mode="runtime_proof",
            tenant_id=session["tenant_id"],
            agent_id=agent["agent_id"],
            agent_generation=int(agent["agent_generation"]),
            method="POST",
            path=path,
            body=body,
            runtime_id=runtime["runtime_id"],
        )
        response = self._request(
            "POST",
            path,
            body=body,
            headers={"X-Palonexus-Developer-Proof": proof},
            expected={200, 201},
            allowed_fields={
                "schemaVersion",
                "tenantId",
                "runId",
                "rootId",
                "agentName",
                "agentGeneration",
                "runtimeLeaseId",
                "descriptorDigest",
                "inputDigest",
                "artifactIdentity",
                "requestedBy",
                "idempotencyKey",
                "requestHash",
                "ceilingRequestId",
                "ceilingVersion",
                "effectiveGrantRef",
                "status",
                "canceledAt",
                "createdAt",
            },
        )
        if "canceledAt" in response:
            _require_timestamp(response["canceledAt"], "canceledAt")
        return response

    def create_developer_action(
        self,
        session: dict[str, Any],
        agent: dict[str, Any],
        guard: dict[str, Any],
        runtime: dict[str, Any],
        run: dict[str, Any],
        *,
        action: str,
        resource: str,
        constraints: dict[str, Any],
        payload: dict[str, Any],
        idempotency_key: str,
        effect_idempotency_key: str,
    ) -> dict[str, Any]:
        path = f"/v1/developer/runs/{quote(run['runId'], safe='')}/actions"
        body = canonical_json(
            {
                "schemaVersion": "palonexus.developer-action-request/v1",
                "canonicalAction": action,
                "resource": resource,
                "constraints": constraints,
                "payload": payload,
                "payloadDigest": hashlib.sha256(canonical_json(payload)).hexdigest(),
                "idempotencyKey": idempotency_key,
                "effectIdempotencyKey": effect_idempotency_key,
            }
        )
        proof = self.mounted_proof(
            _decode_private_key(guard.get("private_key")),
            mode="runtime_proof",
            tenant_id=session["tenant_id"],
            agent_id=agent["agent_id"],
            agent_generation=int(agent["agent_generation"]),
            method="POST",
            path=path,
            body=body,
            runtime_id=runtime["runtime_id"],
        )
        response = self._request(
            "POST",
            path,
            body=body,
            headers={"X-Palonexus-Developer-Proof": proof},
            expected={200, 201},
            allowed_fields={
                "schemaVersion",
                "tenantId",
                "runId",
                "rootId",
                "actionId",
                "version",
                "agentName",
                "requestedBy",
                "agentGeneration",
                "runtimeLeaseId",
                "runtimeGuardObserved",
                "runtimeGuardEvidenceId",
                "runtimeGuardLeaseId",
                "runtimeGuardGeneration",
                "proxyId",
                "proxyGeneration",
                "proxyProofKeyThumbprint",
                "canonicalAction",
                "resource",
                "constraints",
                "payload",
                "payloadDigest",
                "idempotencyKey",
                "effectIdempotencyKey",
                "requestHash",
                "ceilingRequestId",
                "ceilingVersion",
                "target",
                "approval",
                "delivery",
                "receipt",
                "createdAt",
                "terminalAt",
            },
        )
        _validate_developer_action_response(response)
        return response

    def get_developer_action(
        self, session: dict[str, str], run_id: str, action_id: str
    ) -> dict[str, Any]:
        path = (
            f"/v1/developer/runs/{quote(run_id, safe='')}/actions/"
            f"{quote(action_id, safe='')}"
        )
        response = self._request(
            "GET",
            path,
            headers={
                "Authorization": "Bearer "
                + _require_string(session.get("session_token"), "session token")
            },
            allowed_fields={
                "schemaVersion",
                "tenantId",
                "runId",
                "rootId",
                "actionId",
                "version",
                "agentName",
                "requestedBy",
                "agentGeneration",
                "runtimeLeaseId",
                "runtimeGuardObserved",
                "runtimeGuardEvidenceId",
                "runtimeGuardLeaseId",
                "runtimeGuardGeneration",
                "proxyId",
                "proxyGeneration",
                "proxyProofKeyThumbprint",
                "canonicalAction",
                "resource",
                "constraints",
                "payload",
                "payloadDigest",
                "idempotencyKey",
                "effectIdempotencyKey",
                "requestHash",
                "ceilingRequestId",
                "ceilingVersion",
                "target",
                "approval",
                "delivery",
                "receipt",
                "createdAt",
                "terminalAt",
            },
        )
        _validate_developer_action_response(response)
        return response
