# SPDX-License-Identifier: MIT
"""Signed runtime assurance evidence for guarded developer runs."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import uuid
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VERSION = "palonexus.harness.assurance/v1"
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECOND = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_LAYERS = (
    ("identity.session", "harness-identity-session", "harness_adapter"),
    ("run.ownership", "harness-run-ownership", "harness_adapter"),
    ("tool.discovery", "pnxs-tool-discovery", "harness_adapter"),
    ("tool.invocation", "pnxs-tool-invocation", "harness_adapter"),
    ("mcp.access", "runtime-guard-mcp-access", "runtime_guard"),
    ("policy.decision", "control-plane-authz", "control_plane"),
    ("authority.delegation", "agent-idp-exact-delegation", "agent_idp_sts"),
    ("credential.exchange", "agent-idp-sts-exchange", "agent_idp_sts"),
    ("target.enforcement", "registered-target-verifier", "registered_target"),
)


def _canonical(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError) as error:
        raise ValueError("runtime evidence is not canonical JSON") from error


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: object, *, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid {field}")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise ValueError(f"invalid {field}") from error
    if len(decoded) != 32 or _b64url(decoded) != value:
        raise ValueError(f"invalid {field}")
    return decoded


def _public_x(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"invalid {field}")
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(f"invalid {field}") from error
    if not isinstance(parsed, dict) or set(parsed) != {"crv", "kty", "x"}:
        raise ValueError(f"invalid {field}")
    if parsed["crv"] != "Ed25519" or parsed["kty"] != "OKP":
        raise ValueError(f"invalid {field}")
    x = parsed["x"]
    if not isinstance(x, str):
        raise ValueError(f"invalid {field}")
    _decode(x, field=field)
    return x


def _new_credential() -> dict[str, str]:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(public_raw)}
    return {
        "private_key": _b64url(private_raw),
        "public_key_jwk": _canonical(public).decode("utf-8"),
    }


def ensure_runtime_evidence_credential(guard: dict[str, str]) -> dict[str, str]:
    """Return a guard credential with a distinct harness-receipt signing key."""

    value = dict(guard)
    _decode(value.get("private_key"), field="guard private key")
    _public_x(value.get("public_key_jwk"), field="guard public key")
    private = value.get("harness_receipt_private_key")
    public = value.get("harness_receipt_public_key_jwk")
    if private is None and public is None:
        receipt = _new_credential()
        value["harness_receipt_private_key"] = receipt["private_key"]
        value["harness_receipt_public_key_jwk"] = receipt["public_key_jwk"]
    elif private is None or public is None:
        raise ValueError("incomplete harness receipt credential")
    _decode(value.get("harness_receipt_private_key"), field="receipt private key")
    _public_x(value.get("harness_receipt_public_key_jwk"), field="receipt public key")
    if value["public_key_jwk"] == value["harness_receipt_public_key_jwk"]:
        raise ValueError("runtime guard and harness receipt keys must be distinct")
    return value


def _key_id(prefix: str, x: str) -> str:
    return prefix + hashlib.sha256(x.encode("ascii")).hexdigest()[:32]


def _jwk(x: str, key_id: str) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "kid": key_id,
        "use": "sig",
        "alg": "EdDSA",
    }


def _binding(
    *, x: str, key_id: str, signer_class: str, purpose: str, token: bool
) -> dict[str, Any]:
    return {
        "keyId": key_id,
        "algorithm": "Ed25519",
        "publicKeyJwk": _jwk(x, key_id),
        "signerClass": signer_class,
        "purpose": purpose,
        "grantsAuthority": False,
        "tokenRequestPermitted": token,
    }


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _HEX_DIGEST.fullmatch(value) is None:
        raise ValueError(f"invalid {field}")
    return value


def _require_time(value: str, field: str) -> str:
    if _UTC_SECOND.fullmatch(value) is None:
        raise ValueError(f"invalid {field}")
    return value


def build_runtime_attestation(
    *,
    tenant_id: str,
    agent_id: str,
    runtime_id: str,
    descriptor_digest: str,
    runtime_profile: dict[str, Any],
    guard: dict[str, str],
    created_at: str,
    expires_at: str,
    evidence_id: str | None = None,
    manifest_id: str | None = None,
    freshness_nonce: str | None = None,
) -> dict[str, Any]:
    guard = ensure_runtime_evidence_credential(guard)
    descriptor_digest = _require_digest(descriptor_digest, "descriptor digest")
    profile_digest = _require_digest(
        runtime_profile.get("digest"), "runtime profile digest"
    )
    profile_id = runtime_profile.get("id") or runtime_profile.get("kind")
    if not all(
        isinstance(item, str) and item
        for item in (tenant_id, agent_id, runtime_id, profile_id)
    ):
        raise ValueError("incomplete runtime evidence identity")
    if (
        type(runtime_profile.get("version")) is not int
        or runtime_profile["version"] < 1
    ):
        raise ValueError("invalid runtime profile version")
    created_at = _require_time(created_at, "created time")
    expires_at = _require_time(expires_at, "expiry time")
    evidence_id = evidence_id or secrets.token_hex(32)
    if _HEX_DIGEST.fullmatch(evidence_id) is None:
        raise ValueError("invalid runtime evidence ID")
    manifest_id = manifest_id or str(uuid.uuid4())
    freshness_nonce = freshness_nonce or secrets.token_hex(16)
    if not manifest_id or not freshness_nonce:
        raise ValueError("invalid runtime evidence nonce")

    guard_x = _public_x(guard["public_key_jwk"], field="guard public key")
    receipt_x = _public_x(
        guard["harness_receipt_public_key_jwk"], field="receipt public key"
    )
    guard_key_id = _key_id("pnxs-runtime-guard-", guard_x)
    receipt_key_id = _key_id("pnxs-harness-receipt-", receipt_x)
    required = [
        {
            "order": order,
            "layerId": layer,
            "adapterId": adapter,
            "signerClass": signer,
            "requiredWhen": "always",
        }
        for order, (layer, adapter, signer) in enumerate(_LAYERS, start=1)
    ]
    adapter_version = "1.0.0"
    enforcement = [
        {
            "layerId": layer,
            "adapterId": adapter,
            "version": adapter_version,
            "digest": _digest(
                {
                    "purpose": "palonexus.runtime-enforcement-adapter.v1",
                    "descriptorDigest": descriptor_digest,
                    "runtimeProfileDigest": profile_digest,
                    "layerId": layer,
                    "adapterId": adapter,
                    "signerClass": signer,
                }
            ),
            "signerClass": signer,
        }
        for layer, adapter, signer in _LAYERS
    ]
    framework = {
        "layerId": "framework.lifecycle",
        "adapterId": "pnxs-plain-python",
        "version": adapter_version,
        "digest": _digest(
            {
                "purpose": "palonexus.runtime-framework-adapter.v1",
                "descriptorDigest": descriptor_digest,
                "runtimeProfileDigest": profile_digest,
            }
        ),
        "signerClass": "harness_adapter",
    }
    manifest = {
        "version": VERSION,
        "manifestId": manifest_id,
        "tenantId": tenant_id,
        "agentId": agent_id,
        "profileId": profile_id,
        "runtimeSessionId": runtime_id,
        "harnessPackageDigest": "sha256:" + descriptor_digest,
        # A plain-Python runtime has no container. The registered runtime-profile
        # digest is the immutable runtime environment identity for this field.
        "containerImageDigest": "sha256:" + profile_digest,
        "frameworkAdapter": framework,
        "enforcementAdapters": enforcement,
        "requiredReceipts": required,
        "requiredLayerManifestHash": _digest(required),
        "harnessReceiptKey": _binding(
            x=receipt_x,
            key_id=receipt_key_id,
            signer_class="harness_adapter",
            purpose="evidence_receipt",
            token=False,
        ),
        "guardWorkloadKey": _binding(
            x=guard_x,
            key_id=guard_key_id,
            signer_class="runtime_guard",
            purpose="workload_proof_and_evidence",
            token=True,
        ),
        "proofConfirmationMethod": "ed25519-jwk-thumbprint",
        "createdAt": created_at,
        "expiresAt": expires_at,
        "freshnessNonce": freshness_nonce,
        "workloadIdentityEvidenceDigest": _digest(
            {
                "tenantId": tenant_id,
                "agentId": agent_id,
                "runtimeSessionId": runtime_id,
                "guardPublicKeyJwk": _jwk(guard_x, guard_key_id),
            }
        ),
    }
    unsigned = {
        "version": VERSION,
        "attestationId": "runtime-guard:" + evidence_id,
        "manifest": manifest,
        "manifestHash": _digest(manifest),
        "attestedAt": created_at,
        "signerKeyId": guard_key_id,
        "signatureAlgorithm": "Ed25519",
    }
    private = Ed25519PrivateKey.from_private_bytes(
        _decode(guard["private_key"], field="guard private key")
    )
    return {**unsigned, "signature": _b64url(private.sign(_canonical(unsigned)))}


def build_preexchange_evidence(
    *,
    attestation: dict[str, Any],
    guard: dict[str, str],
    run_id: str,
    root_action_id: str,
    action: str,
    resource: str,
    payload: dict[str, Any],
    descriptor_digest: str,
    occurred_at: str,
    batch_id: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    guard = ensure_runtime_evidence_credential(guard)
    descriptor_digest = _require_digest(descriptor_digest, "descriptor digest")
    occurred_at = _require_time(occurred_at, "receipt time")
    if not all(
        isinstance(item, str) and item
        for item in (run_id, root_action_id, action, resource)
    ):
        raise ValueError("incomplete pre-exchange evidence context")
    if not isinstance(payload, dict):
        raise ValueError("invalid action payload")
    manifest = attestation.get("manifest")
    if not isinstance(manifest, dict) or attestation.get("manifestHash") != _digest(
        manifest
    ):
        raise ValueError("invalid runtime attestation")
    required = manifest.get("requiredReceipts")
    if not isinstance(required, list) or [
        (item.get("layerId"), item.get("adapterId"), item.get("signerClass"))
        for item in required[:5]
    ] != list(_LAYERS[:5]):
        raise ValueError("runtime manifest does not carry the pre-exchange contract")

    receipt_private = Ed25519PrivateKey.from_private_bytes(
        _decode(guard["harness_receipt_private_key"], field="receipt private key")
    )
    guard_private = Ed25519PrivateKey.from_private_bytes(
        _decode(guard["private_key"], field="guard private key")
    )
    base_context = {
        "tenantId": manifest["tenantId"],
        "agentId": manifest["agentId"],
        "runtimeSessionId": manifest["runtimeSessionId"],
        "runId": run_id,
        "rootActionId": root_action_id,
        "canonicalAction": action,
        "resource": resource,
        "payloadDigest": _digest(payload),
        "descriptorDigest": descriptor_digest,
    }
    reasons = {
        "identity.session": "runtime_identity_observed",
        "run.ownership": "runtime_run_ownership_observed",
        "tool.discovery": "declared_tool_discovered",
        "tool.invocation": "guarded_tool_invocation_observed",
        "mcp.access": "runtime_guard_mcp_access_observed",
    }
    receipts: list[dict[str, Any]] = []
    prior: str | None = None
    for sequence, (layer, adapter, signer_class) in enumerate(_LAYERS[:5], start=1):
        binding_name = (
            "guardWorkloadKey"
            if signer_class == "runtime_guard"
            else "harnessReceiptKey"
        )
        private = guard_private if signer_class == "runtime_guard" else receipt_private
        unsigned = {
            "version": VERSION,
            "receiptId": str(uuid.uuid4()),
            "tenantId": manifest["tenantId"],
            "agentId": manifest["agentId"],
            "runId": run_id,
            "taskId": root_action_id,
            "rootActionId": root_action_id,
            "attestationId": attestation["attestationId"],
            "manifestHash": attestation["manifestHash"],
            "layerId": layer,
            "adapterId": adapter,
            "signerClass": signer_class,
            "policyVersion": "pnxs-runtime-assurance/v1",
            "catalogVersion": "1",
            "decision": "not_applicable",
            "priorReceiptHash": prior,
            "inputDigest": _digest(
                {**base_context, "layerId": layer, "phase": "input"}
            ),
            "outputDigest": _digest(
                {**base_context, "layerId": layer, "outcome": "observed"}
            ),
            "outcome": "observed",
            "reasonCode": reasons[layer],
            "sequence": sequence,
            "occurredAt": occurred_at,
            "signerKeyId": manifest[binding_name]["keyId"],
            "signatureAlgorithm": "Ed25519",
        }
        signed = {**unsigned, "signature": _b64url(private.sign(_canonical(unsigned)))}
        receipt = {**signed, "receiptHash": _digest(signed)}
        receipts.append(receipt)
        prior = receipt["receiptHash"]
    return {
        "version": VERSION,
        "batchId": batch_id or str(uuid.uuid4()),
        "tenantId": manifest["tenantId"],
        "submitterSignerClass": "runtime_guard",
        "receipts": receipts,
        "submittedAt": occurred_at,
        "idempotencyKey": idempotency_key or str(uuid.uuid4()),
    }


__all__ = [
    "build_preexchange_evidence",
    "build_runtime_attestation",
    "ensure_runtime_evidence_credential",
]
