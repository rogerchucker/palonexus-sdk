# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from palonexus.developer.client import (
    DeveloperClient,
    ProtocolError,
    generate_agent_credential,
)
from palonexus.developer.credentials import CredentialStore
from palonexus.developer.subagents import GovernedSubagentRuntime, SubagentTemplate

SPAWN_REQUEST_ID = "subagent-spawn:0123456789abcdef0123456789abcdef"


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        self.values[(service, username)] = value

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def _status(state: str) -> dict[str, object]:
    terminal_allowed = state in {"allowed", "provisioned", "active"}
    return {
        "schemaVersion": "palonexus.authority-subagent-spawn/v1",
        "version": 1,
        "spawnRequestId": SPAWN_REQUEST_ID,
        "tenantId": "tenant-a",
        "rootRunId": "run-a",
        "parentAgentId": "agent-a",
        "parentAgentGeneration": 1,
        "parentRuntimeLeaseId": "runtime-a",
        "parentGrantId": "grant-a",
        "childTaskId": "task-a",
        "templateId": "reviewer",
        "templateVersion": "1.0.0",
        "delegationDepth": 1,
        "remainingDelegationDepth": 4,
        "status": state,
        "approvalMode": "human_approval_required",
        "approvalStatus": (
            "pending"
            if state == "pending_approval"
            else "approved"
            if terminal_allowed
            else "denied"
        ),
        "decisionId": "decision-a",
        "decisionOutcome": (
            "pending"
            if state == "pending_approval"
            else "allow"
            if terminal_allowed
            else "deny"
        ),
        "reasonCodes": [
            "HUMAN_APPROVAL_REQUIRED"
            if state == "pending_approval"
            else (
                "HUMAN_APPROVAL_ALLOWED"
                if terminal_allowed
                else "HUMAN_APPROVAL_DENIED"
            )
        ],
        "requestDigest": "a" * 64,
        "expiresAt": "2026-08-30T20:00:00Z",
    }


def _runtime(
    client: DeveloperClient, store: CredentialStore
) -> GovernedSubagentRuntime:
    return GovernedSubagentRuntime(
        client=client,
        store=store,
        session={"tenant_id": "tenant-a"},
        agent={"agent_id": "agent-a", "agent_generation": "1"},
        guard=generate_agent_credential(),
        runtime={"runtime_id": "runtime-a"},
        run={"runId": "run-a"},
        templates={
            "reviewer": SubagentTemplate(
                name="reviewer",
                version="1.0.0",
                digest="b" * 64,
                runtime_profile="python-sandbox",
                sandbox_profile="network-restricted",
                attestation_requirement_digest="c" * 64,
                requested_ttl_seconds=600,
                requested_authority={
                    "capability_ids": ["evidence.read"],
                    "action_classes": ["read"],
                    "action_ids": ["evidence.fetch"],
                    "effects": ["record.read"],
                    "resources": ["evidence:release-demo"],
                    "target_registration_ids": ["evidence-store"],
                    "constraints_digest": "d" * 64,
                    "maximum_token_ttl_seconds": 120,
                    "requires_human_approval": False,
                },
                budget_reservation={
                    "cost_microunits": 0,
                    "model_tokens": 0,
                    "steps": 1,
                    "tool_calls": 1,
                    "external_effects": 0,
                    "jobs": 0,
                },
            )
        },
    )


def test_pending_spawn_is_restart_safe_and_denial_never_reposts(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            body = json.loads(request.content)
            assert "prospectivePublicJwk" in body
            assert body["capacityReservation"] == {
                "direct_child_slots": 1,
                "concurrent_descendant_slots": 1,
            }
            assert b"private_key" not in request.content
            return httpx.Response(201, json=_status("pending_approval"))
        return httpx.Response(200, json=_status("denied"))

    store = CredentialStore(keyring_backend=MemoryKeyring(), state_dir=tmp_path)
    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    first = _runtime(client, store).request(
        description="Retry a denied parent operation",
        subagent_type="reviewer",
        parent_action_id="parent-action-a",
    )
    resumed = _runtime(client, store).request(
        description="Retry a denied parent operation",
        subagent_type="reviewer",
        parent_action_id="parent-action-a",
    )

    assert first["status"] == "spawn_approval_required"
    assert resumed == {
        "status": "spawn_denied",
        "spawn_request_id": SPAWN_REQUEST_ID,
        "reason_codes": ["HUMAN_APPROVAL_DENIED"],
    }
    assert [request.method for request in requests] == ["POST", "GET"]
    assert requests[1].url.raw_path.endswith(
        f"/subagent-spawns/{SPAWN_REQUEST_ID}".encode()
    )
    assert b"%" not in requests[1].url.raw_path


def test_allowed_spawn_provisions_and_activates_with_prospective_key(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []
    prospective_thumbprint = ""

    def result(status: str, **extra: object) -> dict[str, object]:
        return {
            "schemaVersion": "palonexus.subagent-provision-result/v1",
            "spawnRequestId": SPAWN_REQUEST_ID,
            "status": status,
            "authorization": {
                "schema_version": "palonexus.subagent-provisioning-authorization/v1",
                "spawn_request_id": SPAWN_REQUEST_ID,
                "tenant_id": "tenant-a",
                "parent_agent_id": "agent-a",
                "parent_runtime_lease_id": "runtime-a",
                "prospective_key_thumbprint": prospective_thumbprint,
            },
            "keyProofMessage": "palonexus subagent proof message",
            **extra,
        }

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal prospective_thumbprint
        requests.append(request)
        if request.url.path.endswith("/runs/run-a/subagent-spawns"):
            prospective_thumbprint = json.loads(request.content)[
                "prospectiveKeyThumbprint"
            ]
            return httpx.Response(201, json=_status("pending_approval"))
        if request.url.path.endswith(f"/subagent-spawns/{SPAWN_REQUEST_ID}"):
            assert request.url.raw_path.endswith(
                f"/subagent-spawns/{SPAWN_REQUEST_ID}".encode()
            )
            assert b"%3A" not in request.url.raw_path
            allowed = _status("allowed")
            allowed.update({"childGrantId": "grant-child", "childGrantHash": "e" * 64})
            return httpx.Response(200, json=allowed)
        body = json.loads(request.content)
        assert request.url.raw_path.endswith(
            f"/subagent-spawns/{SPAWN_REQUEST_ID}/provision".encode()
        )
        assert b"%" not in request.url.raw_path
        assert "private_key" not in body
        if body["operation"] == "challenge":
            return httpx.Response(200, json=result("proof_required"))
        if body["operation"] == "provision":
            assert isinstance(body["keyProof"], str) and body["keyProof"]
            return httpx.Response(
                200,
                json=result(
                    "provisioned",
                    activationProofMessage="palonexus subagent activation message",
                    identityLease={
                        "schema_version": "palonexus.subagent-identity-lease/v1",
                        "identity_lease_id": "lease-child",
                        "tenant_id": "tenant-a",
                        "subagent_id": "agent-child",
                        "agent_generation": 1,
                        "spawn_request_id": SPAWN_REQUEST_ID,
                        "parent_agent_id": "agent-a",
                        "parent_identity_lease_id": "runtime-a",
                        "key_thumbprint": prospective_thumbprint,
                        "status": "provisioned",
                    },
                ),
            )
        assert body["operation"] == "activate"
        assert body["identityLeaseId"] == "lease-child"
        return httpx.Response(
            200,
            json=result(
                "active",
                runId="run-child",
                identityLease={
                    "schema_version": "palonexus.subagent-identity-lease/v1",
                    "identity_lease_id": "lease-child",
                    "tenant_id": "tenant-a",
                    "subagent_id": "agent-child",
                    "agent_generation": 1,
                    "spawn_request_id": SPAWN_REQUEST_ID,
                    "parent_agent_id": "agent-a",
                    "parent_identity_lease_id": "runtime-a",
                    "key_thumbprint": prospective_thumbprint,
                    "status": "active",
                },
            ),
        )

    store = CredentialStore(keyring_backend=MemoryKeyring(), state_dir=tmp_path)
    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    first = _runtime(client, store).request(
        description="Review release evidence",
        subagent_type="reviewer",
        parent_action_id="parent-action-a",
    )
    resumed = _runtime(client, store).request(
        description="Review release evidence",
        subagent_type="reviewer",
        parent_action_id="parent-action-a",
    )

    assert first["status"] == "spawn_approval_required"
    assert resumed == {
        "status": "active",
        "spawn_request_id": SPAWN_REQUEST_ID,
        "reason_codes": ["HUMAN_APPROVAL_ALLOWED"],
        "child_agent_id": "agent-child",
        "child_agent_generation": 1,
        "child_run_id": "run-child",
        "identity_lease_id": "lease-child",
    }
    assert [request.method for request in requests] == [
        "POST",
        "GET",
        "POST",
        "POST",
        "POST",
    ]
    assert all(b"%" not in request.url.raw_path for request in requests[1:])


@pytest.mark.parametrize(
    "request_id",
    [
        "spawn-a",
        "subagent-spawn:0123456789abcdef0123456789abcde",
        "subagent-spawn:0123456789abcdef0123456789abcdeg",
        "subagent-spawn:0123456789ABCDEF0123456789ABCDEF",
        "subagent-spawn%3A0123456789abcdef0123456789abcdef",
    ],
)
def test_subagent_routes_reject_noncanonical_spawn_ids(request_id: str) -> None:
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(
            lambda request: pytest.fail(f"unexpected request: {request.url}")
        ),
    )
    session = {"tenant_id": "tenant-a"}
    agent = {"agent_id": "agent-a", "agent_generation": "1"}
    guard = generate_agent_credential()
    runtime = {"runtime_id": "runtime-a"}

    with pytest.raises(ProtocolError, match="invalid subagent spawn request ID"):
        client.get_developer_subagent_spawn(session, agent, guard, runtime, request_id)
    with pytest.raises(ProtocolError, match="invalid subagent spawn request ID"):
        client.provision_developer_subagent(
            session,
            agent,
            guard,
            runtime,
            request_id,
            command={"operation": "challenge"},
            prospective_key_thumbprint="thumbprint-a",
        )
