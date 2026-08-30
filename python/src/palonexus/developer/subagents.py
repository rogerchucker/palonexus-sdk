# SPDX-License-Identifier: MIT
"""Restart-safe governed subagent requests for supported agent frameworks."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .client import (
    DeveloperClient,
    ProtocolError,
    canonical_json,
    generate_agent_credential,
)
from .credentials import CredentialStore

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class SubagentTemplate:
    name: str
    version: str
    digest: str
    runtime_profile: str
    sandbox_profile: str
    attestation_requirement_digest: str
    requested_ttl_seconds: int
    requested_authority: Mapping[str, Any]
    budget_reservation: Mapping[str, int]
    harness_adapter_id: str = "deep-agents"
    harness_adapter_version: int = 1

    def __post_init__(self) -> None:
        strings = (
            self.name,
            self.version,
            self.runtime_profile,
            self.sandbox_profile,
            self.harness_adapter_id,
        )
        if (
            any(_ID.fullmatch(item) is None for item in strings)
            or _DIGEST.fullmatch(self.digest) is None
            or _DIGEST.fullmatch(self.attestation_requirement_digest) is None
            or self.requested_ttl_seconds < 1
            or self.harness_adapter_version < 1
            or not isinstance(self.requested_authority, Mapping)
            or not isinstance(self.budget_reservation, Mapping)
        ):
            raise ValueError("invalid governed subagent template")


class GovernedSubagentRuntime:
    """Own prospective-key custody and exact restart-safe spawn correlation."""

    def __init__(
        self,
        *,
        client: DeveloperClient,
        store: CredentialStore,
        session: dict[str, Any],
        agent: dict[str, Any],
        guard: dict[str, Any],
        runtime: dict[str, Any],
        run: dict[str, Any],
        templates: Mapping[str, SubagentTemplate],
    ) -> None:
        if not templates or any(
            name != template.name for name, template in templates.items()
        ):
            raise ValueError("governed subagent templates are invalid")
        self._client = client
        self._store = store
        self._session = session
        self._agent = agent
        self._guard = guard
        self._runtime = runtime
        self._run = run
        self._templates = dict(templates)

    def request(
        self, *, description: str, subagent_type: str, parent_action_id: str
    ) -> dict[str, Any]:
        template = self._templates.get(subagent_type)
        if (
            template is None
            or not isinstance(description, str)
            or not description.strip()
            or description != description.strip()
            or len(description.encode("utf-8")) > 4096
            or not isinstance(parent_action_id, str)
            or _ID.fullmatch(parent_action_id) is None
        ):
            raise ProtocolError("invalid governed subagent request")
        intent = canonical_json(
            {
                "runId": self._run["runId"],
                "description": description,
                "subagentType": subagent_type,
                "parentActionId": parent_action_id,
                "templateDigest": template.digest,
            }
        )
        intent_digest = hashlib.sha256(intent).hexdigest()
        idempotency_key = "spawn-" + intent_digest[:32]
        state_name = "subagent-intent:" + idempotency_key
        state = self._store.load(state_name)
        if state is None:
            credential = generate_agent_credential()
            state = {
                "intent_digest": intent_digest,
                "private_key": credential["private_key"],
                "public_key_jwk": credential["public_key_jwk"],
                "key_thumbprint": credential["device_jkt"],
                "spawn_request_id": "",
            }
            if not self._store.create_if_absent(state_name, state):
                state = self._store.load(state_name)
        if state is None or state.get("intent_digest") != intent_digest:
            raise ProtocolError("governed subagent custody state conflicts")
        activation_json = state.get("activation_json")
        if activation_json:
            try:
                activation = json.loads(activation_json)
            except (TypeError, json.JSONDecodeError):
                raise ProtocolError(
                    "governed subagent activation state is invalid"
                ) from None
            if not isinstance(activation, dict):
                raise ProtocolError("governed subagent activation state is invalid")
            return self._framework_outcome(activation)
        request_id = state.get("spawn_request_id", "")
        if request_id:
            status = self._client.get_developer_subagent_spawn(
                self._session,
                self._agent,
                self._guard,
                self._runtime,
                request_id,
            )
        else:
            try:
                public_jwk = json.loads(state["public_key_jwk"])
            except (KeyError, TypeError, json.JSONDecodeError):
                raise ProtocolError(
                    "governed subagent custody state is invalid"
                ) from None
            child_task_id = "task-" + intent_digest[:32]
            command = {
                "childTaskId": child_task_id,
                "parentActionId": parent_action_id,
                "templateId": template.name,
                "templateVersion": template.version,
                "templateDigest": template.digest,
                "harnessAdapterId": template.harness_adapter_id,
                "harnessAdapterVersion": template.harness_adapter_version,
                "runtimeProfile": template.runtime_profile,
                "sandboxProfile": template.sandbox_profile,
                "attestationRequirementDigest": template.attestation_requirement_digest,
                "prospectivePublicJwk": public_jwk,
                "prospectiveKeyThumbprint": state["key_thumbprint"],
                "purposeDigest": hashlib.sha256(
                    canonical_json({"description": description})
                ).hexdigest(),
                "requestedTtlSeconds": template.requested_ttl_seconds,
                "requestedAuthority": dict(template.requested_authority),
                "budgetReservation": dict(template.budget_reservation),
                "capacityReservation": {
                    "directChildSlots": 1,
                    "concurrentDescendantSlots": 1,
                },
            }
            status = self._client.create_developer_subagent_spawn(
                self._session,
                self._agent,
                self._guard,
                self._runtime,
                self._run,
                command=command,
                idempotency_key=idempotency_key,
            )
            state["spawn_request_id"] = status["spawnRequestId"]
            self._store.save(state_name, state)
        if status.get("status") in {"allowed", "provisioned", "active"}:
            status = self._activate(status, state)
            state["activation_json"] = json.dumps(
                status, sort_keys=True, separators=(",", ":")
            )
            self._store.save(state_name, state)
        return self._framework_outcome(status)

    def _activate(
        self, status: Mapping[str, Any], state: Mapping[str, Any]
    ) -> dict[str, Any]:
        request_id = str(status["spawnRequestId"])
        thumbprint = str(state["key_thumbprint"])
        challenge = self._client.provision_developer_subagent(
            self._session,
            self._agent,
            self._guard,
            self._runtime,
            request_id,
            command={"operation": "challenge"},
            prospective_key_thumbprint=thumbprint,
        )
        proof = _sign_proof(str(state["private_key"]), challenge["keyProofMessage"])
        provisioned = self._client.provision_developer_subagent(
            self._session,
            self._agent,
            self._guard,
            self._runtime,
            request_id,
            command={"operation": "provision", "keyProof": proof},
            prospective_key_thumbprint=thumbprint,
        )
        lease = provisioned.get("identityLease")
        activation_message = provisioned.get("activationProofMessage")
        if not isinstance(lease, dict) or not isinstance(activation_message, str):
            raise ProtocolError("subagent provisioning omitted activation authority")
        activation_proof = _sign_proof(
            str(state["private_key"]), activation_message
        )
        activated = self._client.provision_developer_subagent(
            self._session,
            self._agent,
            self._guard,
            self._runtime,
            request_id,
            command={
                "operation": "activate",
                "identityLeaseId": lease["identity_lease_id"],
                "keyProof": activation_proof,
            },
            prospective_key_thumbprint=thumbprint,
        )
        active_lease = activated.get("identityLease")
        if not isinstance(active_lease, dict) or active_lease.get("status") != "active":
            raise ProtocolError("subagent activation did not return an active identity")
        return {
            **dict(status),
            "status": "active",
            "childAgentId": active_lease["subagent_id"],
            "childAgentGeneration": active_lease["agent_generation"],
            "childRunId": activated.get("runId"),
            "identityLeaseId": active_lease["identity_lease_id"],
        }

    @staticmethod
    def _framework_outcome(status: Mapping[str, Any]) -> dict[str, Any]:
        state = status.get("status")
        if state == "pending_approval":
            code = "spawn_approval_required"
        elif state == "denied":
            code = "spawn_denied"
        else:
            code = str(state)
        return {
            "status": code,
            "spawn_request_id": status["spawnRequestId"],
            "reason_codes": list(status.get("reasonCodes", ())),
            **(
                {
                    "child_agent_id": status["childAgentId"],
                    "child_agent_generation": status["childAgentGeneration"],
                    "child_run_id": status["childRunId"],
                    "identity_lease_id": status["identityLeaseId"],
                }
                if state == "active"
                else {}
            ),
        }


def _sign_proof(private_key_b64: str, message: str) -> str:
    try:
        raw = base64.urlsafe_b64decode(
            private_key_b64 + "=" * (-len(private_key_b64) % 4)
        )
        signature = Ed25519PrivateKey.from_private_bytes(raw).sign(
            message.encode("utf-8")
        )
    except (ValueError, TypeError):
        raise ProtocolError("governed subagent custody key is invalid") from None
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


__all__ = ["GovernedSubagentRuntime", "SubagentTemplate"]
