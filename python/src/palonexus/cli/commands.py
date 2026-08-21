# SPDX-License-Identifier: MIT
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from argparse import Namespace
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from packaging.version import InvalidVersion, Version

from palonexus.developer.client import (
    DeveloperClient,
    DeveloperClientError,
    _origin,
    _registration_authority_profile,
    canonical_json,
    decode_strict_json,
    generate_agent_credential,
)
from palonexus.developer.contracts import RequestedCapabilityRule
from palonexus.developer.credentials import (
    CredentialStore,
    CredentialStoreUnavailable,
)
from palonexus.developer.runner import Runner
from palonexus.developer.scaffold import (
    ScaffoldError,
    initialize_plain_python,
    preflight_plain_python,
)
from palonexus.developer.version import version_metadata


class CommandError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def credential_store(*, allow_file_fallback: bool = False) -> CredentialStore:
    return CredentialStore(allow_file_fallback=allow_file_fallback)


def login(args: Namespace) -> int:
    auth_url = args.auth_url or os.environ.get(
        "PNXS_AUTH_URL", "https://auth.palonexus.cloud"
    )
    client = DeveloperClient(auth_url, tenant_hint=args.tenant)
    store = credential_store(allow_file_fallback=args.allow_file_credential_store)

    def display(authorization: dict[str, str]) -> None:
        print(f"Code: {authorization['user_code']}")
        print(f"Verify: {authorization['verification_url']}")

    try:
        client.login(store, on_authorization=display)
    except (DeveloperClientError, CredentialStoreUnavailable) as error:
        raise CommandError(f"login failed: {error}") from error
    return 0


def agents_init(args: Namespace) -> int:
    try:
        project = Path(args.path)
        version = installed_sdk_version()
        preflight_plain_python(project, args.name, version)
        store = credential_store(allow_file_fallback=args.allow_file_credential_store)
        credential_name = "agent:" + args.name
        created = store.create_if_absent(credential_name, generate_agent_credential())
        try:
            initialize_plain_python(project, args.name, version)
        except ScaffoldError:
            if created:
                store.delete(credential_name)
            raise
    except (CredentialStoreUnavailable, ScaffoldError) as error:
        raise CommandError(f"initialization failed: {error}") from error
    return 0


def installed_sdk_version() -> str:
    try:
        raw = metadata.version("palonexus")
    except metadata.PackageNotFoundError as error:
        raise ScaffoldError("installed palonexus version is unavailable") from error
    try:
        return str(Version(raw))
    except InvalidVersion as error:
        raise ScaffoldError("installed palonexus version is invalid") from error


_DESCRIPTOR_MAX_BYTES = 64 * 1024
_REGISTRATION_PROFILE_MAX_BYTES = 16 * 1024
_CEILING_BODY_FIELDS = {
    "schemaVersion",
    "agentGeneration",
    "descriptorDigest",
    "expiresAt",
    "rules",
}


def _reject_yaml_duplicates(node: Any, label: str = "agent descriptor") -> None:
    if isinstance(node, yaml.MappingNode):
        keys: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode) or not isinstance(
                key_node.value, str
            ):
                raise CommandError(f"{label} is invalid")
            if key_node.value in keys:
                raise CommandError(f"{label} contains a duplicate field")
            keys.add(key_node.value)
            _reject_yaml_duplicates(value_node, label)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _reject_yaml_duplicates(item, label)


def _strict_keys(value: object, expected: set[str]) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or not all(isinstance(key, str) for key in value)
    ):
        raise CommandError("agent descriptor is invalid")
    return value


def _project_descriptor(
    path: Path = Path("palonexus-agent.yaml"),
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CommandError("palonexus-agent.yaml is required") from error
    if not raw or len(raw) > _DESCRIPTOR_MAX_BYTES:
        raise CommandError("agent descriptor is empty or too large")
    try:
        text = raw.decode("utf-8")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        if node is None:
            raise CommandError("agent descriptor is invalid")
        _reject_yaml_duplicates(node)
        value = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise CommandError("agent descriptor is invalid") from error
    root = _strict_keys(
        value,
        {
            "schemaVersion",
            "name",
            "version",
            "entrypoint",
            "inputSchema",
            "outputSchema",
            "actions",
        },
    )
    if root["schemaVersion"] != "palonexus.agent/v1":
        raise CommandError("agent descriptor schema is unsupported")
    name = root["name"]
    version = root["version"]
    if not isinstance(name, str) or not isinstance(version, str) or not version:
        raise CommandError("agent descriptor identity is invalid")
    entrypoint = _strict_keys(root["entrypoint"], {"module", "symbol"})
    if any(
        not isinstance(entrypoint[field], str) or not entrypoint[field]
        for field in ("module", "symbol")
    ):
        raise CommandError("agent descriptor entrypoint is invalid")
    actions = root["actions"]
    if not isinstance(actions, list) or len(actions) != 1:
        raise CommandError("the MVP descriptor requires exactly one action")
    action_value = actions[0]
    if not isinstance(action_value, dict):
        raise CommandError("agent descriptor action is invalid")
    expected_action = {
        "action",
        "resource",
        "target",
        "approval",
        "constraints",
        "argumentSchema",
    }
    action = _strict_keys(action_value, expected_action)
    if action["approval"] != "exact-action":
        raise CommandError("the MVP action requires exact-action approval")
    try:
        rule = RequestedCapabilityRule.model_validate(
            {
                "schema_version": "palonexus.requested-capability/v1",
                "canonical_action": action["action"],
                "resource": action["resource"],
                "constraints": action.get("constraints", {}),
                "logical_target_id": action["target"],
            }
        ).model_dump(mode="json")
    except ValueError as error:
        raise CommandError("agent descriptor action is invalid") from error
    input_schema = root["inputSchema"]
    output_schema = root["outputSchema"]
    action_schema = action["argumentSchema"]
    for schema in (input_schema, output_schema, action_schema):
        if not isinstance(schema, dict):
            raise CommandError("agent descriptor schema is invalid")
        try:
            canonical_json(schema)
        except DeveloperClientError as error:
            raise CommandError("agent descriptor schema is invalid") from error
    if canonical_json(output_schema) != canonical_json(action_schema):
        raise CommandError("agent output and action schemas must match")
    return {
        "name": name,
        "version": version,
        "descriptor_digest": hashlib.sha256(raw).hexdigest(),
        "rules": [rule],
        "input_schema": input_schema,
        "output_schema": output_schema,
        "action_schema": action_schema,
        "module": entrypoint["module"],
        "symbol": entrypoint["symbol"],
        "action": action["action"],
        "resource": action["resource"],
        "constraints": action["constraints"],
    }


def _project_registration_profile(
    path: Path = Path("palonexus-registration.yaml"),
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CommandError("palonexus-registration.yaml is required") from error
    if not raw or len(raw) > _REGISTRATION_PROFILE_MAX_BYTES:
        raise CommandError("agent registration profile is empty or too large")
    try:
        text = raw.decode("utf-8")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        if node is None:
            raise CommandError("agent registration profile is invalid")
        _reject_yaml_duplicates(node, "agent registration profile")
        profile = yaml.safe_load(text)
        validated = _registration_authority_profile(profile)
    except (UnicodeDecodeError, yaml.YAMLError, DeveloperClientError) as error:
        raise CommandError("agent registration profile is invalid") from error
    return {**profile, **validated}


def _project_client(
    args: Namespace,
) -> tuple[
    DeveloperClient,
    CredentialStore,
    dict[str, str],
    dict[str, str],
    dict[str, Any],
]:
    try:
        store = credential_store(
            allow_file_fallback=getattr(args, "allow_file_credential_store", False)
        )
        session = store.load("session")
        descriptor = _project_descriptor()
        agent = store.load("agent:" + str(descriptor["name"]))
    except CredentialStoreUnavailable as error:
        raise CommandError(f"credential access failed: {error}") from error
    if session is None:
        raise CommandError("pnxs login is required")
    if agent is None:
        raise CommandError("pnxs agents init is required")
    try:
        client = DeveloperClient(
            os.environ.get("PNXS_API_URL", "https://api.palonexus.cloud")
        )
    except DeveloperClientError as error:
        raise CommandError(f"tenant API configuration failed: {error}") from error
    return client, store, session, agent, descriptor


def _print_json(value: dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def agents_register(args: Namespace) -> int:
    client, store, session, agent, descriptor = _project_client(args)
    try:
        descriptor["authority_profile"] = _project_registration_profile()
        result = client.register_agent(session, agent, descriptor)
        agent["agent_id"] = str(result["agent_id"])
        agent["agent_generation"] = str(result["generation"])
        agent["registered_descriptor_digest"] = str(result["descriptor_digest"])
        store.save("agent:" + str(descriptor["name"]), agent)
    except (DeveloperClientError, CredentialStoreUnavailable, KeyError) as error:
        raise CommandError(f"agent registration failed: {error}") from error
    _print_json(result)
    return 0


def _new_ceiling_request(
    agent: dict[str, str], descriptor: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    registered_digest = agent.get("registered_descriptor_digest")
    if not registered_digest or registered_digest != descriptor["descriptor_digest"]:
        raise CommandError(
            "register this exact agent descriptor before requesting authority"
        )
    try:
        generation = int(agent["agent_generation"])
    except (KeyError, ValueError) as error:
        raise CommandError("stored agent registration is invalid") from error
    expires_at = (
        (datetime.now(UTC) + timedelta(hours=24))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return str(uuid.uuid4()), {
        "schemaVersion": "palonexus.ceiling-request/v1",
        "agentGeneration": generation,
        "descriptorDigest": descriptor["descriptor_digest"],
        "expiresAt": expires_at,
        "rules": descriptor["rules"],
    }


def _stored_or_new_ceiling_request(
    store: CredentialStore, agent: dict[str, str], descriptor: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    request_id = agent.get("ceiling_request_id")
    encoded_body = agent.get("ceiling_request_body")
    if (request_id is None) != (encoded_body is None):
        raise CommandError("stored authority request is incomplete")
    if request_id is None or encoded_body is None:
        request_id, body = _new_ceiling_request(agent, descriptor)
        agent["ceiling_request_id"] = request_id
        agent["ceiling_request_body"] = canonical_json(body).decode("utf-8")
        store.save("agent:" + str(descriptor["name"]), agent)
        return request_id, body
    body = decode_strict_json(encoded_body.encode("utf-8"), _CEILING_BODY_FIELDS)
    if body.get("descriptorDigest") != descriptor["descriptor_digest"]:
        raise CommandError("stored authority request belongs to another descriptor")
    return request_id, body


def agents_request_authority(args: Namespace) -> int:
    client, store, session, agent, descriptor = _project_client(args)
    _require_locally_active_agent(agent)
    try:
        request_id, body = _stored_or_new_ceiling_request(store, agent, descriptor)
        result = client.request_authority(
            session, str(descriptor["name"]), request_id, body
        )
    except (DeveloperClientError, CredentialStoreUnavailable) as error:
        raise CommandError(f"authority request failed: {error}") from error
    _print_json(result)
    return 0


def agents_status(args: Namespace) -> int:
    client, _store, session, agent, descriptor = _project_client(args)
    request_id = agent.get("ceiling_request_id")
    if not request_id:
        raise CommandError("no authority request exists for this agent")
    try:
        result = client.agent_status(session, str(descriptor["name"]), request_id)
    except DeveloperClientError as error:
        raise CommandError(f"agent status failed: {error}") from error
    _print_json(result)
    return 0


def _require_locally_active_agent(agent: dict[str, str]) -> None:
    if agent.get("status") == "revoked":
        raise CommandError("agent authority is locally revoked")


def _revocation_previous_generation(
    agent: dict[str, str], descriptor: dict[str, Any]
) -> tuple[str, int]:
    name = str(descriptor["name"])
    agent_id = agent.get("agent_id")
    registered_digest = agent.get("registered_descriptor_digest")
    if agent_id != name or not registered_digest:
        raise CommandError("register this agent before revoking it")
    try:
        generation = int(agent["agent_generation"])
    except (KeyError, ValueError) as error:
        raise CommandError("stored agent registration is invalid") from error
    if generation < 1 or generation > 2_147_483_647:
        raise CommandError("stored agent registration is invalid")
    status = agent.get("status")
    if status != "revoked":
        if status not in (None, "registered"):
            raise CommandError("stored agent lifecycle is invalid")
        return agent_id, generation
    try:
        previous_generation = int(agent["revocation_previous_generation"])
    except (KeyError, ValueError) as error:
        raise CommandError("stored agent revocation is incomplete") from error
    expected_event = f"revoke:{agent_id}:{previous_generation}"
    if (
        previous_generation < 1
        or generation != previous_generation + 1
        or agent.get("revocation_event_id") != expected_event
        or agent.get("revocation_cascade_status") != "applied"
    ):
        raise CommandError("stored agent revocation is incomplete")
    return agent_id, previous_generation


def agents_revoke(args: Namespace) -> int:
    client, store, session, agent, descriptor = _project_client(args)
    agent_id, previous_generation = _revocation_previous_generation(agent, descriptor)
    try:
        result = client.revoke_agent(
            session,
            str(descriptor["name"]),
            agent_id,
            expected_previous_generation=previous_generation,
        )
        agent.update(
            agent_generation=str(result["generation"]),
            status="revoked",
            revocation_previous_generation=str(result["previous_generation"]),
            revocation_event_id=str(result["event_id"]),
            revoked_at=str(result["revoked_at"]),
            revocation_cascade_status=str(result["cascade_status"]),
            revocation_cascade_applied_at=str(result["cascade_applied_at"]),
        )
        store.save("agent:" + str(descriptor["name"]), agent)
    except (DeveloperClientError, CredentialStoreUnavailable, KeyError) as error:
        raise CommandError(f"agent revocation failed: {error}") from error
    _print_json(result)
    return 0


def _strict_input(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw, object_pairs_hook=lambda pairs: _strict_json_pairs(pairs)
        )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise CommandError("run input must be strict JSON") from error
    if not isinstance(value, dict):
        raise CommandError("run input must be a JSON object")
    return value, hashlib.sha256(canonical_json(value)).hexdigest()


def _strict_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def run_agent(args: Namespace) -> int:
    client, store, session, agent, descriptor = _project_client(args)
    _require_locally_active_agent(agent)
    input_value, input_digest = _strict_input(Path(args.input))
    guard = store.load("guard:" + str(descriptor["name"]))
    try:
        if guard is None:
            guard = generate_agent_credential()
            store.save("guard:" + str(descriptor["name"]), guard)
        artifact = "sha256:" + descriptor["descriptor_digest"]
        # Enrollment proofs are one-time. Each process start creates a fresh
        # enrollment/runtime instance rather than retaining a consumed key.
        enrollment_key = str(uuid.uuid4())
        runtime_instance_id = str(uuid.uuid4())
        enrollment = client.create_runtime_enrollment(
            session,
            agent,
            descriptor,
            guard,
            idempotency_key=enrollment_key,
            artifact_identity=artifact,
            runtime_instance_id=runtime_instance_id,
            guard_version="pnxs/0.1.0",
        )
        runtime = client.redeem_runtime(session, agent, enrollment)
        run_key = str(uuid.uuid4())
        run = client.create_developer_run(
            session,
            agent,
            guard,
            runtime,
            input_digest=input_digest,
            idempotency_key=run_key,
        )
        persisted: dict[str, Any] = {}

        def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
            if not persisted:
                action = client.create_developer_action(
                    session,
                    agent,
                    guard,
                    runtime,
                    run,
                    action=envelope["action"],
                    resource=envelope["resource"],
                    constraints=descriptor["constraints"],
                    payload=envelope["payload"],
                    idempotency_key=str(uuid.uuid4()),
                    effect_idempotency_key=str(uuid.uuid4()),
                )
                persisted.update(action)
                store.save(
                    "action:" + persisted["actionId"],
                    {"run_id": run["runId"], "agent": descriptor["name"]},
                )
            if args.detach:
                return {"status": "pending", "action_id": persisted["actionId"]}
            while True:
                current = client.get_developer_action(
                    session, run["runId"], persisted["actionId"]
                )
                state = current.get("delivery", {}).get("state")
                if state == "delivered":
                    return {
                        "status": "approved",
                        "receipt": current["receipt"],
                        "result": current.get("result", {}),
                    }
                if state in {"denied", "canceled", "failed_safe"}:
                    return {"status": "denied", "reason": state}
                if state == "expired":
                    return {"status": "expired", "reason": state}
                time.sleep(2)

        runner = Runner(
            guard_invoke=invoke, child_environment={"PATH": os.environ.get("PATH", "")}
        )
        result = runner.run(
            project=Path.cwd(),
            agent_file=Path(args.agent_file),
            descriptor=descriptor,
            input_value=input_value,
            run_id=run["runId"],
            descriptor_digest=descriptor["descriptor_digest"],
            input_digest=input_digest,
            runtime_lease_id=runtime["runtime_id"],
            detach=args.detach,
        )
        if args.detach:
            if not persisted or result.pending_action_id != persisted["actionId"]:
                raise RuntimeError("detached action was not durably persisted")
            _print_json(
                {
                    "run_id": run["runId"],
                    "action_id": result.pending_action_id,
                    "status": "pending",
                }
            )
            return 0
    except (
        DeveloperClientError,
        CredentialStoreUnavailable,
        KeyError,
        ValueError,
        RuntimeError,
    ) as error:
        raise CommandError(f"guarded run failed: {error}") from error
    _print_json(
        {
            "run_id": run["runId"],
            "output": result.output,
            "receipt": result.receipt,
            "runtimeGuarded": "observed",
            "runtimeIsolated": "not_configured",
            "codeProvenance": "developer_declared",
        }
    )
    return 0


def actions_wait(args: Namespace) -> int:
    client, store, session, _agent, _descriptor = _project_client(args)
    reference = store.load("action:" + args.action_id)
    if not isinstance(reference, dict) or not isinstance(reference.get("run_id"), str):
        raise CommandError("no persisted run reference exists for this action")
    run_id = reference["run_id"]
    while True:
        current = client.get_developer_action(session, run_id, args.action_id)
        state = current.get("delivery", {}).get("state")
        if state in {"delivered", "denied", "expired", "canceled", "failed_safe"}:
            _print_json(current)
            return 0 if state == "delivered" else 4
        time.sleep(2)


def logout(args: Namespace) -> int:
    store = credential_store(allow_file_fallback=args.allow_file_credential_store)
    try:
        credential = store.load("session")
        if credential is not None:
            stored_origin = _origin(credential.get("issuer_origin", ""))
            configured_origin = args.auth_url or os.environ.get("PNXS_AUTH_URL")
            if (
                configured_origin is not None
                and _origin(configured_origin) != stored_origin
            ):
                raise DeveloperClientError(
                    "configured auth URL conflicts with the session issuer"
                )
            DeveloperClient(stored_origin).logout(credential)
            store.delete("session")
    except (DeveloperClientError, CredentialStoreUnavailable) as error:
        raise CommandError(f"logout failed: {error}") from error
    return 0


def version(_args: Namespace) -> int:
    print(json.dumps(version_metadata(), sort_keys=True, separators=(",", ":")))
    return 0


def unavailable(_args: Namespace) -> int:
    raise CommandError(
        "unavailable: command backing is delivered in a later MVP deliverable", 69
    )
