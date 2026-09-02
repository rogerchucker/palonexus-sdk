# SPDX-License-Identifier: MIT
from __future__ import annotations

import base64
import copy
import hashlib
import json

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from palonexus.developer.client import (
    DeveloperClient,
    canonical_json,
    generate_agent_credential,
)
from palonexus.developer.evidence import (
    build_preexchange_evidence,
    build_runtime_attestation,
    ensure_runtime_evidence_credential,
)


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify(public_jwk: dict[str, str], payload: dict, signature: str) -> None:
    Ed25519PublicKey.from_public_bytes(_decode(public_jwk["x"])).verify(
        _decode(signature), canonical_json(payload)
    )


def _attestation() -> tuple[dict, dict]:
    guard = ensure_runtime_evidence_credential(generate_agent_credential())
    attestation = build_runtime_attestation(
        tenant_id="tenant-a",
        agent_id="release-agent",
        runtime_id="runtime-a",
        descriptor_digest="a" * 64,
        runtime_profile={"id": "plain-python", "version": 1, "digest": "b" * 64},
        guard=guard,
        created_at="2026-08-12T12:00:00Z",
        expires_at="2026-08-12T13:00:00Z",
        evidence_id="c" * 64,
        manifest_id="manifest-a",
        freshness_nonce="d" * 32,
    )
    return guard, attestation


def test_runtime_attestation_uses_distinct_guard_and_receipt_keys() -> None:
    guard, attestation = _attestation()
    manifest = attestation["manifest"]

    assert guard["public_key_jwk"] != guard["harness_receipt_public_key_jwk"]
    assert attestation["attestationId"] == "runtime-guard:" + "c" * 64
    assert manifest["runtimeSessionId"] == "runtime-a"
    assert len(manifest["requiredReceipts"]) == 9
    assert [item["order"] for item in manifest["requiredReceipts"]] == list(
        range(1, 10)
    )
    assert (
        manifest["requiredLayerManifestHash"]
        == "sha256:"
        + hashlib.sha256(canonical_json(manifest["requiredReceipts"])).hexdigest()
    )
    unsigned = copy.deepcopy(attestation)
    signature = unsigned.pop("signature")
    _verify(manifest["guardWorkloadKey"]["publicKeyJwk"], unsigned, signature)


def test_preexchange_evidence_is_a_signed_contiguous_five_receipt_prefix() -> None:
    guard, attestation = _attestation()
    batch = build_preexchange_evidence(
        attestation=attestation,
        guard=guard,
        run_id="run-a",
        root_action_id="root-a",
        action="mcp:change-control/assess/abc",
        resource="release:2026.08.30",
        payload={"release": "2026.08.30"},
        descriptor_digest="a" * 64,
        occurred_at="2026-08-12T12:00:01Z",
        batch_id="batch-a",
        idempotency_key="evidence-a",
    )

    assert batch["submitterSignerClass"] == "runtime_guard"
    receipts = batch["receipts"]
    assert [item["sequence"] for item in receipts] == [1, 2, 3, 4, 5]
    assert [item["layerId"] for item in receipts] == [
        "identity.session",
        "run.ownership",
        "tool.discovery",
        "tool.invocation",
        "mcp.access",
    ]
    prior = None
    for receipt in receipts:
        assert receipt["taskId"] == receipt["rootActionId"] == "root-a"
        assert receipt["priorReceiptHash"] == prior
        hash_payload = copy.deepcopy(receipt)
        receipt_hash = hash_payload.pop("receiptHash")
        assert (
            receipt_hash
            == "sha256:" + hashlib.sha256(canonical_json(hash_payload)).hexdigest()
        )
        signature_payload = copy.deepcopy(hash_payload)
        signature = signature_payload.pop("signature")
        binding = (
            attestation["manifest"]["guardWorkloadKey"]
            if receipt["signerClass"] == "runtime_guard"
            else attestation["manifest"]["harnessReceiptKey"]
        )
        _verify(binding["publicKeyJwk"], signature_payload, signature)
        prior = receipt_hash


def test_runtime_assurance_posts_use_runtime_proof_and_idempotency() -> None:
    guard, attestation = _attestation()
    batch = build_preexchange_evidence(
        attestation=attestation,
        guard=guard,
        run_id="run-a",
        root_action_id="root-a",
        action="mcp:change-control/assess/abc",
        resource="release:2026.08.30",
        payload={"release": "2026.08.30"},
        descriptor_digest="a" * 64,
        occurred_at="2026-08-12T12:00:01Z",
        batch_id="batch-a",
        idempotency_key="evidence-a",
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("runtime-attestations"):
            return httpx.Response(
                201,
                json={
                    "attestationId": attestation["attestationId"],
                    "runtimeSessionId": "runtime-a",
                    "manifestHash": attestation["manifestHash"],
                    "verificationState": "verified",
                    "duplicate": False,
                },
            )
        return httpx.Response(
            201,
            json={
                "batchId": "batch-a",
                "receiptCount": 5,
                "finalReceiptHash": batch["receipts"][-1]["receiptHash"],
                "achievedLevel": "A1",
                "deliveryState": "unconfirmed",
                "duplicate": False,
            },
        )

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    session = {"tenant_id": "tenant-a"}
    agent = {"agent_id": "release-agent", "agent_generation": "1"}
    runtime = {"runtime_id": "runtime-a"}

    client.submit_runtime_attestation(
        session, agent, guard, runtime, attestation, idempotency_key="attest-a"
    )
    client.submit_runtime_evidence(
        session, agent, guard, runtime, batch, idempotency_key="evidence-a"
    )

    assert [request.url.path for request in seen] == [
        "/v1/developer/runtime-attestations",
        "/v1/developer/runtime-evidence",
    ]
    assert [request.headers["Idempotency-Key"] for request in seen] == [
        "attest-a",
        "evidence-a",
    ]
    assert all(request.headers["X-Palonexus-Developer-Proof"] for request in seen)
    assert json.loads(seen[0].content) == attestation
    assert json.loads(seen[1].content) == batch
