# SPDX-License-Identifier: MIT
from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import multiprocessing
import os
import ssl
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import palonexus.cli.commands as cli_commands
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from palonexus.cli.commands import CommandError
from palonexus.cli.main import build_parser, main
from palonexus.developer.client import (
    MAX_RESPONSE_BYTES,
    CLIIncompatible,
    DeveloperClient,
    DeveloperClientError,
    ProtocolError,
    RequestRejected,
    _validate_device_session,
    build_device_proof,
    canonical_json,
    decode_strict_json,
    generate_agent_credential,
)
from palonexus.developer.context import CapabilityDenied
from palonexus.developer.credentials import CredentialStore, CredentialStoreUnavailable
from palonexus.developer.scaffold import ScaffoldError


def test_r3_example_declares_denied_attempt_without_requesting_its_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Path(__file__).parents[2] / "examples" / "r3-governed-agent"
    monkeypatch.chdir(project)

    descriptor = cli_commands._project_descriptor()

    assert len(descriptor["actions"]) == 3
    assert len(descriptor["rules"]) == 1
    assert descriptor["rules"][0]["canonical_action"].startswith(
        "mcp:change-control-mcp/assess_release/"
    )
    assert descriptor["actions"][1]["request_authority"] is False
    assert descriptor["actions"][2]["action"] == "subagent:spawn"
    assert descriptor["actions"][2]["request_authority"] is False
    assert descriptor["subagents"][0]["name"] == "evidence-checker"


class _UnavailableProcessKeyring:
    def get_password(self, service: str, username: str) -> None:
        raise RuntimeError("keyring unavailable")

    def set_password(self, service: str, username: str, value: str) -> None:
        raise RuntimeError("keyring unavailable")

    def delete_password(self, service: str, username: str) -> None:
        raise RuntimeError("keyring unavailable")


def _fallback_create_worker(
    state_dir: str, name: str, value: str, queue: object
) -> None:
    store = CredentialStore(
        keyring_backend=_UnavailableProcessKeyring(),
        state_dir=Path(state_dir),
        allow_file_fallback=True,
    )
    created = store.create_if_absent(name, {"private_key": value})
    queue.put(created)  # type: ignore[attr-defined]


def _fallback_mutation_worker(state_dir: str, operation: str, name: str) -> None:
    store = CredentialStore(
        keyring_backend=_UnavailableProcessKeyring(),
        state_dir=Path(state_dir),
        allow_file_fallback=True,
    )
    if operation == "save":
        store.save(name, {"value": name})
    else:
        store.delete(name)


def _claim_id(public_jwk: dict[str, str]) -> str:
    request_value = {
        "schema_version": "palonexus.developer-agent-claim-request/v1",
        "descriptor_digest": "a" * 64,
        "public_key_jwk": public_jwk,
    }
    request_body = canonical_json(request_value)
    request_digest = hashlib.sha256(
        canonical_json(
            {
                "body": request_value,
                "idempotency_key": hashlib.sha256(request_body).hexdigest(),
            }
        )
    ).hexdigest()
    return (
        "claim-"
        + hashlib.sha256(
            canonical_json(
                {
                    "tenant_id": "tenant-a",
                    "agent_id": "r3-reviewer",
                    "accountable_owner": "okta:tenant-a:robin-singh",
                    "request_digest": request_digest,
                }
            )
        ).hexdigest()[:32]
    )


def test_pnxs_is_the_only_console_script_and_parser_surface_is_exact() -> None:
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert '[project.scripts]\npnxs = "palonexus.cli.main:entrypoint"' in text
    assert "pnx =" not in text

    parser = build_parser()
    accepted = (
        ["--version"],
        ["login"],
        [
            "agents",
            "init",
            ".",
            "--name",
            "example",
        ],
        ["agents", "register"],
        ["agent", "attach", "example"],
        ["register", "example"],
        [
            "agents",
            "add",
            "--from",
            ".",
            "--name",
            "example",
            "--tenant",
            "tenant-a",
            "--yes",
        ],
        ["agents", "request-authority"],
        ["agents", "status"],
        ["agents", "revoke"],
        ["run", "agent.py", "--input", "fixture.json"],
        ["actions", "wait", "action-1"],
        ["logout"],
        ["version"],
        ["version", "--json"],
    )
    for argv in accepted:
        assert parser.parse_args(argv).handler is not None
    for argv in (["pnx"], ["agents", "delete"], ["publish"]):
        with pytest.raises(SystemExit):
            parser.parse_args(argv)
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "agents",
                "init",
                ".",
                "--name",
                "example",
                "--sdk-wheel",
                "palonexus.whl",
            ]
        )


def test_agent_attach_uses_owner_bound_challenge_and_never_sends_private_key() -> None:
    credential = generate_agent_credential()
    public_jwk = json.loads(credential["public_key_jwk"])
    thumbprint = hashlib.sha256(canonical_json(public_jwk)).hexdigest()
    challenge = {
        "schema_version": "palonexus.developer-agent-claim-challenge/v1",
        "challenge_id": _claim_id(public_jwk),
        "agent_id": "r3-reviewer",
        "tenant_id": "tenant-a",
        "accountable_owner": "okta:tenant-a:robin-singh",
        "generation": 1,
        "descriptor_digest": "a" * 64,
        "key_thumbprint": thumbprint,
        "nonce": "n" * 43,
        "expires_at": "2026-08-25T12:05:00Z",
        "status": "pending",
    }
    receipt = {
        "schema_version": "palonexus.developer-agent-claim/v1",
        "claim_id": challenge["challenge_id"],
        "agent_id": "r3-reviewer",
        "tenant_id": "tenant-a",
        "accountable_owner": "okta:tenant-a:robin-singh",
        "descriptor_digest": "a" * 64,
        "key_thumbprint": thumbprint,
        "generation": 1,
        "status": "attached",
        "claimed_at": "2026-08-25T12:00:02Z",
    }
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/claim-challenges"):
            body = json.loads(request.content)
            assert body == {
                "schema_version": "palonexus.developer-agent-claim-request/v1",
                "descriptor_digest": "a" * 64,
                "public_key_jwk": public_jwk,
            }
            return httpx.Response(201, json=challenge)
        body = json.loads(request.content)
        assert body["challenge_id"] == challenge["challenge_id"]
        assert body["nonce"] == challenge["nonce"]
        message = canonical_json(
            {
                "accountable_owner": challenge["accountable_owner"],
                "agent_id": challenge["agent_id"],
                "challenge_id": challenge["challenge_id"],
                "descriptor_digest": challenge["descriptor_digest"],
                "expires_at": challenge["expires_at"],
                "generation": challenge["generation"],
                "key_thumbprint": challenge["key_thumbprint"],
                "nonce": challenge["nonce"],
                "purpose": "palonexus.developer-agent-claim.v1",
                "tenant_id": challenge["tenant_id"],
            }
        )
        signature = base64.urlsafe_b64decode(
            body["proof"]["signature"] + "=" * (-len(body["proof"]["signature"]) % 4)
        )
        Ed25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(
                credential["private_key"] + "=" * (-len(credential["private_key"]) % 4)
            )
        ).public_key().verify(signature, message)
        return httpx.Response(200, json=receipt)

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    result = client.attach_agent(
        {
            "session_token": "pnx_dev_session",
            "tenant_id": "tenant-a",
            "membership_id": "member-robin",
            "owner_subject": "okta:tenant-a:robin-singh",
        },
        credential,
        {"name": "r3-reviewer", "descriptor_digest": "a" * 64},
        cli_version="0.2.3",
    )

    assert result == receipt
    assert len(seen) == 2
    assert all("private" not in request.content.decode().lower() for request in seen)
    assert all(
        request.headers["palonexus-cli-contract"] == "palonexus.pnxs/v1"
        for request in seen
    )


def test_agent_attach_recovers_commit_after_process_lost_local_save() -> None:
    credential = generate_agent_credential()
    public_jwk = json.loads(credential["public_key_jwk"])
    thumbprint = hashlib.sha256(canonical_json(public_jwk)).hexdigest()
    challenge_id = _claim_id(public_jwk)
    receipt = {
        "schema_version": "palonexus.developer-agent-claim/v1",
        "claim_id": challenge_id,
        "agent_id": "r3-reviewer",
        "tenant_id": "tenant-a",
        "accountable_owner": "okta:tenant-a:robin-singh",
        "descriptor_digest": "a" * 64,
        "key_thumbprint": thumbprint,
        "generation": 1,
        "status": "attached",
        "claimed_at": "2026-08-25T12:00:02Z",
    }
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method + " " + request.url.path)
        if request.method == "POST":
            return httpx.Response(
                409,
                json={
                    "error": {
                        "code": "developer_agent_claim_conflict",
                        "message": "already attached",
                    }
                },
            )
        assert request.url.path.endswith("/" + challenge_id)
        return httpx.Response(200, json=receipt)

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    result = client.attach_agent(
        {
            "session_token": "pnx_dev_session",
            "tenant_id": "tenant-a",
            "membership_id": "member-robin",
            "owner_subject": "okta:tenant-a:robin-singh",
        },
        credential,
        {"name": "r3-reviewer", "descriptor_digest": "a" * 64},
        cli_version="0.2.3",
    )

    assert result == receipt
    assert [item.split()[0] for item in seen] == ["POST", "GET"]


def test_agent_attach_command_persists_only_the_returned_binding(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    credential = generate_agent_credential()
    saved: dict[str, dict[str, str]] = {}
    receipt = {
        "schema_version": "palonexus.developer-agent-claim/v1",
        "claim_id": "claim-" + "1" * 32,
        "agent_id": "r3-reviewer",
        "tenant_id": "tenant-a",
        "accountable_owner": "okta:tenant-a:robin-singh",
        "descriptor_digest": "a" * 64,
        "key_thumbprint": "b" * 64,
        "generation": 1,
        "status": "attached",
        "claimed_at": "2026-08-25T12:00:02Z",
    }

    class Store:
        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            assert name == "agent:tenant-a:r3-reviewer"
            assert "private_key" in value
            return True

        def load(self, name: str) -> dict[str, str] | None:
            assert name == "agent:tenant-a:r3-reviewer"
            return dict(credential)

        def save(self, name: str, value: dict[str, str]) -> None:
            saved[name] = dict(value)

    class Client:
        def require_cli_compatibility(self, *args: object) -> dict[str, str]:
            return _compatibility_response()

        def attach_agent(self, session, agent, descriptor, *, cli_version):
            assert session["owner_subject"] == receipt["accountable_owner"]
            assert descriptor["name"] == "r3-reviewer"
            assert agent == credential
            assert cli_version == "0.2.3"
            return receipt

    monkeypatch.setattr(
        "palonexus.cli.commands._claim_project_client",
        lambda _: (
            Client(),
            Store(),
            {
                "tenant_id": "tenant-a",
                "owner_subject": "okta:tenant-a:robin-singh",
            },
            {"name": "r3-reviewer", "descriptor_digest": "a" * 64},
        ),
    )
    monkeypatch.setattr("palonexus.cli.commands.installed_sdk_version", lambda: "0.2.3")
    monkeypatch.setattr(
        "palonexus.cli.commands._require_standalone_registration_cli", lambda: None
    )

    assert main(["agent", "attach", "r3-reviewer"]) == 0
    stored = saved["agent:tenant-a:r3-reviewer"]
    assert stored["agent_id"] == "r3-reviewer"
    assert stored["agent_generation"] == "1"
    assert stored["registered_descriptor_digest"] == "a" * 64
    assert stored["claim_id"] == receipt["claim_id"]
    assert credential["private_key"] not in capsys.readouterr().out


def test_top_level_register_requires_exact_local_agent_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "palonexus.cli.commands._project_descriptor",
        lambda: {"name": "r3-reviewer", "descriptor_digest": "a" * 64},
    )
    assert main(["register", "another-agent"]) == 1
    assert "does not match" in capsys.readouterr().err


def test_cli_subprocess_detach_then_restart_wait_uses_exact_grammar(
    tmp_path: Path,
) -> None:
    descriptor = """schemaVersion: palonexus.agent/v1
name: demo
version: 0.1.0
entrypoint: {module: agent, symbol: review_release}
inputSchema: {type: object}
outputSchema: &output {type: object}
actions:
  - action: release.assessment.publish
    resource: release/demo
    target: release-assessments
    approval: exact-action
    constraints: {}
    argumentSchema: *output
"""
    (tmp_path / "palonexus-agent.yaml").write_text(descriptor)
    (tmp_path / "palonexus-registration.yaml").write_text(
        """schema_version: palonexus.agent-registration-profile/v1
descriptor_version: palonexus.agent-descriptor/v1
runtime_profile:
  id: plain-python
  version: 1
  digest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
composition_digest: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
harness_adapter_contracts: [palonexus.harness-adapter/v1]
not_before: "2026-08-01T00:00:00Z"
expires_at: "2030-08-01T00:00:00Z"
"""
    )
    (tmp_path / "agent.py").write_text(
        "def review_release(change, context):\n"
        " outcome = context.actions.invoke(\n"
        "  'release.assessment.publish', 'release/demo', change)\n"
        " return outcome.result\n"
    )
    (tmp_path / "input.json").write_text('{"risk":"low"}')
    agent = generate_agent_credential()
    agent.update(
        agent_id="demo",
        agent_generation="1",
        registered_descriptor_digest=hashlib.sha256(descriptor.encode()).hexdigest(),
    )
    state = tmp_path / "state" / "palonexus"
    state.mkdir(parents=True, mode=0o700)
    (state / "credentials.json").write_text(
        json.dumps(
            {
                "session": {"session_token": "pnx_dev_test", "tenant_id": "tenant-a"},
                "agent:demo": agent,
            }
        )
    )
    os.chmod(state / "credentials.json", 0o600)

    class API(BaseHTTPRequestHandler):
        enrollments = []
        action_count = 0
        attestation_count = 0
        evidence_count = 0

        def log_message(self, *_args):
            pass

        def _json(self, value, status=200):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if self.path == "/v1/developer/runtime-enrollments":
                API.enrollments.append(
                    (
                        self.headers.get("Idempotency-Key"),
                        json.loads(body)["runtime_instance_id"],
                    )
                )
                self._json({"enrollment_id": f"enrollment-{len(API.enrollments)}"}, 201)
            elif self.path.endswith("/redeem"):
                self._json(
                    {
                        "runtime_id": "runtime-" + self.path.split("/")[4],
                        "expires_at": "2030-08-12T13:00:00Z",
                    }
                )
            elif self.path == "/v1/developer/runs":
                self._json({"runId": "run-1", "rootId": "root-1"}, 201)
            elif self.path == "/v1/developer/runtime-attestations":
                API.attestation_count += 1
                value = json.loads(body)
                self._json(
                    {
                        "attestationId": value["attestationId"],
                        "runtimeSessionId": value["manifest"]["runtimeSessionId"],
                        "manifestHash": value["manifestHash"],
                        "verificationState": "verified",
                        "duplicate": False,
                    },
                    201,
                )
            elif self.path == "/v1/developer/runtime-evidence":
                API.evidence_count += 1
                value = json.loads(body)
                self._json(
                    {
                        "batchId": value["batchId"],
                        "receiptCount": len(value["receipts"]),
                        "finalReceiptHash": value["receipts"][-1]["receiptHash"],
                        "achievedLevel": "A1",
                        "deliveryState": "unconfirmed",
                        "duplicate": False,
                    },
                    201,
                )
            elif self.path.endswith("/actions"):
                API.action_count += 1
                self._json(
                    {
                        "actionId": f"action-{API.action_count}",
                        "requestedBy": "member-1",
                    },
                    201,
                )
            else:
                self._json({"error": "unknown"}, 404)

        def do_GET(self):
            payload_digest = hashlib.sha256(canonical_json({"risk": "low"})).hexdigest()
            self._json(
                {
                    "tenantId": "tenant-a",
                    "runId": "run-1",
                    "rootId": "root-1",
                    "actionId": "action-1",
                    "requestedBy": "member-1",
                    "payloadDigest": payload_digest,
                    "effectIdempotencyKey": "effect-1",
                    "target": {
                        "registrationId": "release-assessments",
                        "version": 2,
                    },
                    "delivery": {
                        "state": "delivered",
                        "capabilityId": "capability-1",
                    },
                    "receipt": {
                        "schemaVersion": "palonexus.developer-receipt-reference/v1",
                        "receiptId": "receipt-1",
                        "opaqueDigest": "a" * 64,
                        "recordedAt": "2026-08-12T12:02:00Z",
                        "verified": True,
                        "capabilityId": "capability-1",
                        "tenantId": "tenant-a",
                        "runId": "run-1",
                        "rootId": "root-1",
                        "actionId": "action-1",
                        "payloadDigest": payload_digest,
                        "targetRegistrationId": "release-assessments",
                        "targetRegistrationVersion": 2,
                        "effectIdempotencyKey": "effect-1",
                        "effectId": "effect-1",
                        "effectCreatedAt": "2026-08-12T12:01:59Z",
                    },
                }
            )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = {
        **os.environ,
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "PNXS_API_URL": f"https://localhost:{server.server_port}",
        "SSL_CERT_FILE": str(cert_path),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
    }
    executable = str(Path(sys.executable).parent / "pnxs")
    run = subprocess.run(
        [
            executable,
            "run",
            "agent.py",
            "--input",
            "input.json",
            "--detach",
            "--json",
            "--allow-file-credential-store",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert run.returncode == 0 and json.loads(run.stdout) == {
        "action_id": "action-1",
        "run_id": "run-1",
        "status": "pending",
    }
    second = subprocess.run(
        [
            executable,
            "run",
            "agent.py",
            "--input",
            "input.json",
            "--detach",
            "--json",
            "--allow-file-credential-store",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert (
        second.returncode == 0 and json.loads(second.stdout)["action_id"] == "action-2"
    )
    assert (
        len(API.enrollments) == 2
        and API.enrollments[0][0] != API.enrollments[1][0]
        and API.enrollments[0][1] != API.enrollments[1][1]
    )
    assert API.attestation_count == 2
    assert API.evidence_count == 2
    wait = subprocess.run(
        [
            executable,
            "actions",
            "wait",
            "action-1",
            "--json",
            "--allow-file-credential-store",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert (
        wait.returncode == 0
        and json.loads(wait.stdout)["delivery"]["state"] == "delivered"
    )
    resume = subprocess.run(
        [
            executable,
            "actions",
            "resume",
            "action-1",
            "--json",
            "--allow-file-credential-store",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    server.shutdown()
    thread.join(timeout=2)
    assert resume.returncode == 0, resume.stderr
    assert json.loads(resume.stdout) == {
        "action_id": "action-1",
        "output": {},
        "receipt": {
            "capabilityId": "capability-1",
            "effectCreatedAt": "2026-08-12T12:01:59Z",
            "effectId": "effect-1",
            "effectIdempotencyKey": "effect-1",
            "opaqueDigest": "a" * 64,
            "payloadDigest": hashlib.sha256(
                canonical_json({"risk": "low"})
            ).hexdigest(),
            "receiptId": "receipt-1",
            "recordedAt": "2026-08-12T12:02:00Z",
            "rootId": "root-1",
            "runId": "run-1",
            "schemaVersion": "palonexus.developer-receipt-reference/v1",
            "targetRegistrationId": "release-assessments",
            "targetRegistrationVersion": 2,
            "tenantId": "tenant-a",
            "verified": True,
            "actionId": "action-1",
        },
        "run_id": "run-1",
        "status": "completed",
    }


def test_strict_json_rejects_duplicate_unknown_and_oversized_documents() -> None:
    assert decode_strict_json(b'{"state":"pending"}', {"state"}) == {"state": "pending"}
    for raw in (
        b'{"state":"pending","state":"approved"}',
        b'{"state":"pending","unknown":true}',
        b'{"state":"pending"} trailing',
        b'{"state":"' + (b"a" * 70_000) + b'"}',
    ):
        with pytest.raises(ProtocolError):
            decode_strict_json(raw, {"state"})


def test_http_responses_are_streamed_to_max_plus_one_and_always_closed() -> None:
    class TrackingStream(httpx.SyncByteStream):
        def __init__(self) -> None:
            self.consumed = 0
            self.closed = False

        def __iter__(self):
            for _ in range(MAX_RESPONSE_BYTES + 100):
                self.consumed += 1
                yield b"x"

        def close(self) -> None:
            self.closed = True

    stream = TrackingStream()
    client = DeveloperClient(
        "https://auth.example",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream)),
    )
    with pytest.raises(ProtocolError, match="too large"):
        client._request("GET", "/bounded", allowed_fields={"status"})
    assert stream.consumed == MAX_RESPONSE_BYTES + 1
    assert stream.closed


def test_http_errors_are_secret_free_and_streaming_response_is_closed() -> None:
    secret = "pnx_dev_transport-secret"

    class FailingStream(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b'{"status":'
            raise httpx.ReadError(secret)

        def close(self) -> None:
            self.closed = True

    stream = FailingStream()
    client = DeveloperClient(
        "https://auth.example",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream)),
    )
    with pytest.raises(DeveloperClientError) as caught:
        client._request("GET", "/failure", allowed_fields={"status"})
    assert secret not in str(caught.value)
    assert stream.closed


def test_device_proof_matches_independent_fixed_vector() -> None:
    seed = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    body = b'{"verifier":"golden-verifier"}'
    proof = build_device_proof(
        private_key,
        "https://auth.palonexus.cloud",
        "POST",
        "/v1/developer/device-authorizations/tx%2Fgolden/token",
        body,
    )
    assert proof == (
        "YsaoY7Bcu79DkZC-APpRSQ23DwyMLgUEqCIUjPl_9KyE62ZKVE9gmvk4gZfcEkgIQbVuXhcUGbjjOCFTDMhzDA"
    )

    expected_message = (
        b'{"body_sha256":"LT9m3e9rOdJeldheMnqN7VLwtlThpJWHL2rFgf9XlHc",'
        b'"method":"POST","origin":"https://auth.palonexus.cloud",'
        b'"path":"/v1/developer/device-authorizations/tx%2Fgolden/token",'
        b'"purpose":"palonexus.developer-device-redemption.v1"}'
    )
    signature = base64.urlsafe_b64decode(proof + "==")
    private_key.public_key().verify(signature, expected_message)


@pytest.mark.parametrize(
    "verification_url",
    (
        "https://evil.example/developer/device-authorizations/CODE-DEMO",
        "https://user@auth.example/developer/device-authorizations/CODE-DEMO",
        "https://auth.example/developer/device-authorizations/CODE-DEMO?next=evil",
        "https://auth.example/developer/device-authorizations/CODE-DEMO#fragment",
        "https://auth.example/v1/developer/device/CODE-DEMO",
        "https://auth.example/developer/device-authorizations/OTHER-CODE",
        "https://auth.example/developer/device-authorizations/CODE-DEMO/",
    ),
)
def test_device_login_rejects_verification_url_not_exactly_bound_to_user_code(
    verification_url: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) != 1:
            raise AssertionError("poll attempted after invalid verification URL")
        return httpx.Response(
            201,
            json={
                "transaction_id": "tx-demo",
                "user_code": "CODE-DEMO",
                "verification_url": verification_url,
                "expires_at": "2099-08-12T12:00:00Z",
                "interval_seconds": 1,
            },
        )

    client = DeveloperClient(
        "https://auth.example", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ProtocolError, match="verification URL"):
        client.login(_MemoryKeyring())  # type: ignore[arg-type]
    assert len(requests) == 1


def test_developer_client_normalizes_its_exact_https_origin() -> None:
    client = DeveloperClient("https://AUTH.EXAMPLE:443/")
    assert client.origin == "https://auth.example"


def test_device_login_uses_strict_wire_contract_and_keeps_secrets_in_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    stored: dict[str, dict[str, str]] = {}
    expected_jkt = ""
    owner_subject = "okta:tenant-demo:~" + "a" * 218 + "~"

    class Store:
        def save(self, name: str, value: dict[str, str]) -> None:
            stored[name] = value

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal expected_jkt
        requests.append(request)
        if len(requests) == 1:
            payload = json.loads(request.content)
            assert sorted(payload) == ["code_challenge", "device_public_jwk"]
            assert sorted(payload["device_public_jwk"]) == ["crv", "kty", "x"]
            expected_jkt = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(
                        json.dumps(
                            payload["device_public_jwk"],
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            return httpx.Response(
                201,
                json={
                    "transaction_id": "tx-demo",
                    "user_code": "CODE-DEMO",
                    "verification_url": "https://auth.example/developer/device-authorizations/CODE-DEMO",
                    "expires_at": "2099-08-12T12:00:00Z",
                    "interval_seconds": 1,
                },
            )
        if len(requests) == 2:
            assert request.headers["X-Palonexus-Transaction-Verifier"]
            return httpx.Response(
                200,
                json={
                    "state": "approved",
                    "expires_at": "2099-08-12T12:00:00Z",
                    "interval_seconds": 1,
                    "terminal_code": "",
                },
            )
        assert request.url.raw_path == (
            b"/v1/developer/device-authorizations/tx-demo/token"
        )
        assert request.headers["X-Palonexus-Device-Proof"]
        assert json.loads(request.content) == {
            "verifier": requests[1].headers["X-Palonexus-Transaction-Verifier"]
        }
        return httpx.Response(
            200,
            json={
                "kind": "developer_session",
                "session_id": "session-demo",
                "tenant_id": "tenant-demo",
                "account_id": "account-server-only",
                "membership_id": "membership-demo",
                "owner_subject": owner_subject,
                "role": "member",
                "device_jkt": expected_jkt,
                "created_at": "2026-08-12T12:00:00Z",
                "expires_at": "2026-08-12T20:00:00Z",
                "session_token": "pnx_dev_session-secret",
            },
        )

    monkeypatch.setattr("palonexus.developer.client.time.sleep", lambda _: None)
    client = DeveloperClient(
        "https://auth.example", transport=httpx.MockTransport(handler)
    )
    shown: list[dict[str, str]] = []
    assert client.login(Store(), on_authorization=shown.append) == shown[0]
    assert shown == [
        {
            "user_code": "CODE-DEMO",
            "verification_url": "https://auth.example/developer/device-authorizations/CODE-DEMO",
        }
    ]
    assert stored["session"]["session_token"] == "pnx_dev_session-secret"
    assert stored["session"]["owner_subject"] == owner_subject
    assert stored["session"]["issuer_origin"] == "https://auth.example"
    assert "device_private_key" in stored["session"]
    wire = b"\n".join(request.content for request in requests)
    assert b"pnx_dev_session-secret" not in wire
    assert stored["session"]["device_private_key"].encode() not in wire


def test_device_login_revokes_session_when_approved_tenant_misses_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    expected_jkt = ""

    class Store:
        def save(self, _name: str, _value: dict[str, str]) -> None:
            raise AssertionError("wrong-tenant session reached credential custody")

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal expected_jkt
        requests.append(request)
        if len(requests) == 1:
            payload = json.loads(request.content)
            expected_jkt = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(
                        json.dumps(
                            payload["device_public_jwk"],
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            return httpx.Response(
                201,
                json={
                    "transaction_id": "tx-demo",
                    "user_code": "CODE-DEMO",
                    "verification_url": "https://auth.example/developer/device-authorizations/CODE-DEMO",
                    "expires_at": "2099-08-12T12:00:00Z",
                    "interval_seconds": 1,
                },
            )
        if len(requests) == 2:
            return httpx.Response(
                200,
                json={
                    "state": "approved",
                    "expires_at": "2099-08-12T12:00:00Z",
                    "interval_seconds": 1,
                    "terminal_code": "",
                },
            )
        if len(requests) == 3:
            return httpx.Response(
                200,
                json={
                    "kind": "developer_session",
                    "session_id": "session-wrong-tenant",
                    "tenant_id": "tenant-other",
                    "account_id": "account-server-only",
                    "membership_id": "membership-demo",
                    "owner_subject": "okta:tenant-other:robin.singh",
                    "role": "member",
                    "device_jkt": expected_jkt,
                    "created_at": "2026-08-12T12:00:00Z",
                    "expires_at": "2026-08-12T20:00:00Z",
                    "session_token": "pnx_dev_session-secret",
                },
            )
        assert request.method == "DELETE"
        assert request.url.path == "/v1/developer/sessions/session-wrong-tenant"
        return httpx.Response(
            200,
            json={"status": "revoked", "session_id": "session-wrong-tenant"},
        )

    monkeypatch.setattr("palonexus.developer.client.time.sleep", lambda _: None)
    client = DeveloperClient(
        "https://auth.example",
        tenant_hint="tenant-demo",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(DeveloperClientError, match="approved for a different tenant"):
        client.login(Store())  # type: ignore[arg-type]
    assert requests[0].url.query == b"tenant=tenant-demo"
    assert len(requests) == 4


@pytest.mark.parametrize(
    "response",
    (
        {"status": "active", "session_id": "session-demo"},
        {"status": "revoked", "session_id": "other-session"},
        {"status": "revoked"},
        {"status": "revoked", "session_id": "session-demo", "extra": True},
    ),
)
def test_logout_requires_exact_revocation_confirmation(
    response: dict[str, object],
) -> None:
    client = DeveloperClient(
        "https://auth.example",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    with pytest.raises(ProtocolError):
        client.logout(
            {
                "session_token": "pnx_dev_session-secret",
                "session_id": "session-demo",
                "issuer_origin": "https://auth.example",
            }
        )


def test_logout_treats_unauthorized_session_as_already_inactive() -> None:
    client = DeveloperClient(
        "https://auth.example",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(401, json={"error": "unauthorized"})
        ),
    )
    assert (
        client.logout(
            {
                "session_token": "pnx_dev_session-secret",
                "session_id": "session-demo",
                "issuer_origin": "https://auth.example",
            }
        )
        is False
    )


def test_logout_uses_stored_issuer_and_rejects_conflict_before_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    credential = {
        "session_token": "pnx_dev_session-secret",
        "session_id": "session-demo",
        "issuer_origin": "https://issuer.example",
    }
    calls: list[str] = []
    deleted: list[str] = []

    class Store:
        def load(self, name: str) -> dict[str, str]:
            assert name == "session"
            return credential

        def delete(self, name: str) -> None:
            deleted.append(name)

    class Client:
        def __init__(self, origin: str) -> None:
            calls.append(origin)

        def logout(self, value: dict[str, str]) -> bool:
            assert value is credential
            return False

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr("palonexus.cli.commands.DeveloperClient", Client)
    monkeypatch.delenv("PNXS_AUTH_URL", raising=False)
    assert main(["logout"]) == 0
    assert calls == ["https://issuer.example"]
    assert deleted == ["session"]
    assert capsys.readouterr().out == "Already signed out. Local session cleared.\n"

    calls.clear()
    deleted.clear()
    assert main(["logout", "--auth-url", "https://other.example"]) == 1
    assert calls == []
    assert deleted == []

    monkeypatch.setenv("PNXS_AUTH_URL", "https://other.example")
    assert main(["logout"]) == 1
    assert calls == []
    assert deleted == []


@pytest.mark.parametrize(
    "invalid_status",
    (
        {"state": "approved", "interval_seconds": 1, "terminal_code": ""},
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
        },
        {
            "state": "approved",
            "expires_at": 1,
            "interval_seconds": 1,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": "1",
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": True,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 0,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 61,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": None,
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12 12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00",
            "interval_seconds": 1,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-02-30T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "",
        },
        {
            "state": "approved",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "authorization_denied",
        },
        {
            "state": "pending",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "authorization_pending",
        },
        {
            "state": "denied",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "",
        },
        {
            "state": "expired",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "authorization_denied",
        },
        {
            "state": "consumed",
            "expires_at": "2099-08-12T12:00:00Z",
            "interval_seconds": 1,
            "terminal_code": "authorization_expired",
        },
    ),
)
def test_device_login_rejects_malformed_status_before_redemption(
    invalid_status: dict[str, object],
) -> None:
    requests: list[httpx.Request] = []

    class Store:
        def save(self, name: str, value: dict[str, str]) -> None:
            raise AssertionError(
                f"credential saved after invalid status: {name} {value}"
            )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                201,
                json={
                    "transaction_id": "tx-malformed-status",
                    "user_code": "CODE-DEMO",
                    "verification_url": "https://auth.example/developer/device-authorizations/CODE-DEMO",
                    "expires_at": "2099-08-12T12:00:00Z",
                    "interval_seconds": 1,
                },
            )
        if len(requests) == 2:
            return httpx.Response(200, json=invalid_status)
        raise AssertionError("token redemption attempted after invalid status")

    client = DeveloperClient(
        "https://auth.example", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ProtocolError):
        client.login(Store())
    assert len(requests) == 2


def test_redeemed_session_is_bound_to_the_local_device_key() -> None:
    jkt = base64.urlsafe_b64encode(b"j" * 32).rstrip(b"=").decode()
    valid = {
        "kind": "developer_session",
        "session_id": "session-demo",
        "tenant_id": "tenant-demo",
        "account_id": "account-server-only",
        "membership_id": "membership-demo",
        "owner_subject": "okta:tenant-demo:robin.singh",
        "role": "member",
        "device_jkt": jkt,
        "created_at": "2026-08-12T12:00:00Z",
        "expires_at": "2026-08-12T20:00:00Z",
        "session_token": "pnx_dev_session-secret",
    }
    session = _validate_device_session(valid, jkt)
    assert session["device_jkt"] == jkt
    assert session["owner_subject"] == "okta:tenant-demo:robin.singh"
    for field, replacement in (
        ("kind", "member"),
        ("role", "operator"),
        ("device_jkt", base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()),
        ("session_token", "ordinary-bearer"),
        ("expires_at", "not-a-time"),
    ):
        mutated = {**valid, field: replacement}
        with pytest.raises(ProtocolError):
            _validate_device_session(mutated, jkt)


class _MemoryKeyring:
    def __init__(self, *, fail: bool = False) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.fail = fail

    def get_password(self, service: str, username: str) -> str | None:
        if self.fail:
            raise RuntimeError("keyring unavailable")
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        if self.fail:
            raise RuntimeError("keyring unavailable")
        self.values[(service, username)] = value

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def test_keyring_is_primary_and_file_fallback_is_explicit_mode_0600(
    tmp_path: Path,
) -> None:
    primary = _MemoryKeyring()
    store = CredentialStore(keyring_backend=primary, state_dir=tmp_path)
    store.save("session", {"token": "secret"})
    assert store.load("session") == {"token": "secret"}
    assert not list(tmp_path.glob("*.json"))

    unavailable = CredentialStore(
        keyring_backend=_MemoryKeyring(fail=True), state_dir=tmp_path
    )
    with pytest.raises(CredentialStoreUnavailable):
        unavailable.save("session", {"token": "secret"})

    fallback = CredentialStore(
        keyring_backend=_MemoryKeyring(fail=True),
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    fallback.save("session", {"token": "secret"})
    credential_file = tmp_path / "credentials.json"
    assert credential_file.stat().st_mode & 0o777 == 0o600
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert (tmp_path / ".credentials.lock").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / ".credentials.lock").read_bytes() == b""
    assert fallback.load("session") == {"token": "secret"}


def test_credential_create_if_absent_preserves_exact_existing_value() -> None:
    primary = _MemoryKeyring()
    service = CredentialStore.service
    primary.values[(service, "agent:existing")] = (
        '{"private_key":"existing-byte-exact-secret"}'
    )
    store = CredentialStore(keyring_backend=primary)
    assert not store.create_if_absent(
        "agent:existing", {"private_key": "replacement-secret"}
    )
    assert primary.values[(service, "agent:existing")] == (
        '{"private_key":"existing-byte-exact-secret"}'
    )
    assert store.create_if_absent("agent:new", {"private_key": "new-secret"})


def test_file_fallback_create_if_absent_preserves_existing_value(
    tmp_path: Path,
) -> None:
    class ReadableUnavailableKeyring:
        def get_password(self, service: str, username: str) -> None:
            return None

        def set_password(self, service: str, username: str, value: str) -> None:
            raise RuntimeError("keyring unavailable")

        def delete_password(self, service: str, username: str) -> None:
            raise RuntimeError("keyring unavailable")

    backend = ReadableUnavailableKeyring()
    store = CredentialStore(
        keyring_backend=backend,
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    assert store.create_if_absent("agent:existing", {"private_key": "existing-secret"})
    before = store.fallback_path.read_bytes()
    assert not store.create_if_absent(
        "agent:existing", {"private_key": "replacement-secret"}
    )
    assert store.fallback_path.read_bytes() == before


def test_recovered_keyring_does_not_replace_existing_fallback_credential(
    tmp_path: Path,
) -> None:
    fallback = CredentialStore(
        keyring_backend=_UnavailableProcessKeyring(),
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    original = {"private_key": "fallback-original-secret"}
    assert fallback.create_if_absent("agent:recover", original)
    exact_fallback = fallback.fallback_path.read_bytes()

    recovered = _MemoryKeyring()
    store = CredentialStore(
        keyring_backend=recovered,
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    assert not store.create_if_absent(
        "agent:recover", {"private_key": "replacement-secret"}
    )
    assert recovered.values == {}
    assert fallback.fallback_path.read_bytes() == exact_fallback
    assert store.load("agent:recover") == original


def test_divergent_keyring_and_fallback_fail_closed_without_secret_leak(
    tmp_path: Path,
) -> None:
    fallback_secret = "fallback-divergent-secret"
    keyring_secret = "keyring-divergent-secret"
    unavailable = CredentialStore(
        keyring_backend=_UnavailableProcessKeyring(),
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    unavailable.save("agent:conflict", {"private_key": fallback_secret})
    recovered = _MemoryKeyring()
    recovered.values[(CredentialStore.service, "agent:conflict")] = json.dumps(
        {"private_key": keyring_secret}, separators=(",", ":")
    )
    store = CredentialStore(
        keyring_backend=recovered,
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    for operation in (
        lambda: store.create_if_absent(
            "agent:conflict", {"private_key": "replacement-secret"}
        ),
        lambda: store.load("agent:conflict"),
    ):
        with pytest.raises(CredentialStoreUnavailable) as caught:
            operation()
        message = str(caught.value)
        assert fallback_secret not in message
        assert keyring_secret not in message
        assert "replacement-secret" not in message


def test_identical_keyring_and_fallback_are_existing_not_replaced(
    tmp_path: Path,
) -> None:
    value = {"private_key": "same-secret"}
    unavailable = CredentialStore(
        keyring_backend=_UnavailableProcessKeyring(),
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    unavailable.save("agent:same", value)
    recovered = _MemoryKeyring()
    recovered.values[(CredentialStore.service, "agent:same")] = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    )
    store = CredentialStore(
        keyring_backend=recovered,
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    assert not store.create_if_absent(
        "agent:same", {"private_key": "replacement-secret"}
    )
    assert store.load("agent:same") == value


def test_keyring_create_if_absent_is_serialized_across_threads() -> None:
    class SlowKeyring(_MemoryKeyring):
        def get_password(self, service: str, username: str) -> str | None:
            value = super().get_password(service, username)
            time.sleep(0.02)
            return value

    backend = SlowKeyring()
    first = CredentialStore(keyring_backend=backend)
    second = CredentialStore(keyring_backend=backend)
    barrier = threading.Barrier(2)
    results: list[bool] = []

    def create(store: CredentialStore, value: str) -> None:
        barrier.wait()
        results.append(store.create_if_absent("agent:same", {"private_key": value}))

    threads = [
        threading.Thread(target=create, args=(first, "first")),
        threading.Thread(target=create, args=(second, "second")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert sorted(results) == [False, True]
    stored = json.loads(backend.values[(CredentialStore.service, "agent:same")])
    assert stored["private_key"] in {"first", "second"}


def test_fallback_create_if_absent_is_process_shared_and_preserves_names(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_fallback_create_worker,
            args=(str(tmp_path), "agent:same", value, queue),
        )
        for value in ("first", "second")
    ] + [
        context.Process(
            target=_fallback_create_worker,
            args=(str(tmp_path), f"agent:{index}", str(index), queue),
        )
        for index in range(4)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0
    results = [queue.get(timeout=2) for _ in processes]
    assert results.count(False) == 1
    values = json.loads((tmp_path / "credentials.json").read_text(encoding="utf-8"))
    assert set(values) == {"agent:same", *(f"agent:{index}" for index in range(4))}
    assert values["agent:same"]["private_key"] in {"first", "second"}


def test_fallback_save_and_delete_rmw_are_process_serialized(tmp_path: Path) -> None:
    initial = CredentialStore(
        keyring_backend=_UnavailableProcessKeyring(),
        state_dir=tmp_path,
        allow_file_fallback=True,
    )
    initial.save("delete-me", {"value": "old"})
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(
            target=_fallback_mutation_worker,
            args=(str(tmp_path), "save", f"name-{index}"),
        )
        for index in range(6)
    ] + [
        context.Process(
            target=_fallback_mutation_worker,
            args=(str(tmp_path), "delete", "delete-me"),
        )
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0
    values = json.loads(initial.fallback_path.read_text(encoding="utf-8"))
    assert set(values) == {f"name-{index}" for index in range(6)}


def test_login_output_contains_only_code_and_url_and_never_secret_material(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_values = {
        "session_token": "pnx_dev_super-secret",
        "private_key": "private-key-material",
        "verifier": "verifier-secret-material",
    }

    def fake_login(
        self: DeveloperClient,
        store: CredentialStore,
        *,
        on_authorization: object,
    ) -> dict[str, str]:
        store.save("session", secret_values)
        result = {
            "user_code": "ABCD-EFGH",
            "verification_url": "https://auth.example/developer/device-authorizations/ABCD-EFGH",
        }
        on_authorization(result)  # type: ignore[operator]
        return result

    monkeypatch.setattr(DeveloperClient, "login", fake_login)
    monkeypatch.setenv("PNXS_AUTH_URL", "https://auth.example")
    opened: list[tuple[str, int]] = []
    monkeypatch.setattr(
        "palonexus.cli.commands.webbrowser.open",
        lambda url, new=0: opened.append((url, new)) or True,
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.credential_store",
        lambda allow_file_fallback=False: CredentialStore(
            keyring_backend=_MemoryKeyring(), allow_file_fallback=allow_file_fallback
        ),
    )
    assert main(["login"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "Finish signing in in your browser.",
        "Open: https://auth.example/developer/device-authorizations/ABCD-EFGH",
        "Confirm code: ABCD-EFGH",
        "Sign in as the intended workforce user and approve this device.",
        "Keep this command running; it will continue automatically.",
        "Signed in.",
        "Next: pnxs agents register",
    ]
    assert opened == [
        (
            "https://auth.example/developer/device-authorizations/ABCD-EFGH",
            2,
        )
    ]
    combined = captured.out + captured.err + " ".join(os.environ.values())
    for secret in secret_values.values():
        assert secret not in combined


def test_login_can_continue_directly_to_agent_registration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Store:
        def save(self, _name: str, _value: dict[str, str]) -> None:
            return None

    def fake_login(
        self: DeveloperClient,
        store: Store,
        *,
        on_authorization: object,
    ) -> dict[str, str]:
        authorization = {
            "user_code": "ABCD-EFGH",
            "verification_url": "https://auth.example/developer/device-authorizations/ABCD-EFGH",
        }
        on_authorization(authorization)  # type: ignore[operator]
        return authorization

    registrations: list[str] = []

    def fake_register(args: object) -> int:
        registrations.append(str(getattr(args, "tenant")))
        print('{"agent_id":"release-risk-reviewer-r3","status":"registered"}')
        return 0

    monkeypatch.setattr(DeveloperClient, "login", fake_login)
    monkeypatch.setattr("palonexus.cli.commands.agents_register", fake_register)
    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())

    assert (
        main(
            [
                "login",
                "--tenant",
                "demo0",
                "--no-browser",
                "--register",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "Signed in. Registering the agent in this directory." in captured.err
    assert captured.out == (
        '{"agent_id":"release-risk-reviewer-r3","status":"registered"}\n'
    )
    assert registrations == ["demo0"]


def test_agents_init_custodies_agent_key_without_output_or_project_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    saved: dict[str, dict[str, str]] = {}
    project = tmp_path / "project"
    initialized: list[tuple[object, ...]] = []

    class Store:
        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            saved[name] = value
            return True

        def delete(self, name: str) -> None:
            saved.pop(name, None)

    monkeypatch.setattr(
        "palonexus.cli.commands.credential_store",
        lambda allow_file_fallback=False: Store(),
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.installed_sdk_version",
        lambda: "1.2.3",
        raising=False,
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.initialize_plain_python",
        lambda *args: initialized.append(args),
    )
    assert (
        main(
            [
                "agents",
                "init",
                str(project),
                "--name",
                "release-risk-reviewer",
                "--allow-file-credential-store",
            ]
        )
        == 0
    )
    assert sorted(saved) == ["agent:release-risk-reviewer"]
    assert sorted(saved["agent:release-risk-reviewer"]) == [
        "device_jkt",
        "private_key",
        "public_key_jwk",
    ]
    assert initialized == [(project, "release-risk-reviewer", "1.2.3")]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    for secret in saved["agent:release-risk-reviewer"].values():
        assert secret not in captured.out + captured.err


def test_agents_init_key_store_failure_leaves_no_partial_scaffold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"

    class Store:
        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            raise CredentialStoreUnavailable("unavailable")

        def delete(self, name: str) -> None:
            raise AssertionError(name)

    def partial_scaffold(*args: object) -> None:
        project.mkdir()
        (project / "partial").write_text("partial", encoding="utf-8")

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr(
        "palonexus.cli.commands.installed_sdk_version",
        lambda: "1.2.3",
        raising=False,
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.initialize_plain_python", partial_scaffold
    )
    assert (
        main(
            [
                "agents",
                "init",
                str(project),
                "--name",
                "release-risk-reviewer",
            ]
        )
        == 1
    )
    assert not project.exists()


def test_agents_init_preflight_preserves_existing_credential_on_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "existing.txt").write_text("occupied", encoding="utf-8")
    existing = {"private_key": "existing-byte-exact-secret"}
    stored = dict(existing)
    mutations: list[str] = []

    class Store:
        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            assert name == "agent:release-risk-reviewer"
            assert value
            return False

        def delete(self, name: str) -> None:
            mutations.append("delete")
            stored.clear()

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr(
        "palonexus.cli.commands.installed_sdk_version",
        lambda: "1.2.3",
        raising=False,
    )
    assert (
        main(
            [
                "agents",
                "init",
                str(project),
                "--name",
                "release-risk-reviewer",
            ]
        )
        == 1
    )
    assert mutations == []
    assert stored == existing
    assert (project / "existing.txt").read_text(encoding="utf-8") == "occupied"


def test_agents_init_preflight_failure_does_not_create_new_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "existing.txt").write_text("occupied", encoding="utf-8")
    calls: list[str] = []

    class Store:
        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            calls.append("create")
            return True

        def delete(self, name: str) -> None:
            calls.append("delete")

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr(
        "palonexus.cli.commands.installed_sdk_version",
        lambda: "1.2.3",
        raising=False,
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.generate_agent_credential",
        lambda: calls.append("generate") or {},
    )
    assert (
        main(
            [
                "agents",
                "init",
                str(project),
                "--name",
                "release-risk-reviewer",
            ]
        )
        == 1
    )
    assert calls == []


def test_agents_init_rolls_back_only_new_credential_on_generation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored: dict[str, dict[str, str]] = {}
    deleted: list[str] = []

    class Store:
        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            stored[name] = value
            return True

        def delete(self, name: str) -> None:
            deleted.append(name)
            stored.pop(name, None)

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr(
        "palonexus.cli.commands.installed_sdk_version",
        lambda: "1.2.3",
        raising=False,
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.initialize_plain_python",
        lambda *args: (_ for _ in ()).throw(ScaffoldError("generation failed")),
    )
    assert (
        main(
            [
                "agents",
                "init",
                str(tmp_path / "project"),
                "--name",
                "release-risk-reviewer",
            ]
        )
        == 1
    )
    assert stored == {}
    assert deleted == ["agent:release-risk-reviewer"]


@pytest.mark.parametrize("installed", [None, "not a version"])
def test_agents_init_rejects_missing_or_unsafe_installed_version_before_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed: str | None,
) -> None:
    calls: list[str] = []

    def resolve(_: str) -> str:
        if installed is None:
            raise importlib.metadata.PackageNotFoundError("palonexus")
        return installed

    monkeypatch.setattr(importlib.metadata, "version", resolve)
    monkeypatch.setattr(
        "palonexus.cli.commands.credential_store",
        lambda **_: calls.append("store") or object(),
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.generate_agent_credential",
        lambda: calls.append("credential") or {},
    )

    project = tmp_path / "project"
    assert main(["agents", "init", str(project), "--name", "agent"]) == 1
    assert calls == []
    assert not project.exists()


def test_version_json_is_strict_and_contains_release_identity(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "palonexus.cli.commands.version_metadata",
        lambda: {
            "version": "1.2.3",
            "source_revision": "a" * 40,
        },
    )
    assert main(["version", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "version": "1.2.3",
        "source_revision": "a" * 40,
    }


@pytest.mark.parametrize("argv", (["--version"], ["version"]))
def test_version_has_a_standard_human_readable_surface(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "palonexus.cli.commands.version_metadata",
        lambda: {"version": "1.2.3", "source_revision": "a" * 40},
    )

    assert main(argv) == 0
    assert capsys.readouterr().out == "pnxs 1.2.3\n"


def test_login_keyboard_interrupt_exits_cleanly_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        DeveloperClient,
        "login",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        "palonexus.cli.commands.credential_store",
        lambda **_: CredentialStore(keyring_backend=_MemoryKeyring()),
    )

    assert main(["login", "--no-browser"]) == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Login canceled.\n"


def _registration_response(
    descriptor_digest: str, key_thumbprint: str
) -> dict[str, object]:
    profile = _registration_profile()
    return {
        "schema_version": "palonexus.developer-agent/v1",
        "agent_id": "release-risk-reviewer",
        "name": "release-risk-reviewer",
        "tenant_id": "tenant-a",
        "accountable_owner": "okta:tenant-a:robin-singh",
        "descriptor_digest": descriptor_digest,
        "key_thumbprint": key_thumbprint,
        "generation": 1,
        "status": "registered",
        "capabilities": [],
        "descriptor_version": profile["descriptor_version"],
        "runtime_profile": profile["runtime_profile"],
        "composition_digest": profile["composition_digest"],
        "harness_adapter_contracts": profile["harness_adapter_contracts"],
        "not_before": profile["not_before"],
        "expires_at": profile["expires_at"],
    }


def _compatibility_response() -> dict[str, str]:
    return {
        "schema_version": "palonexus.developer-cli-compatibility/v1",
        "cli_contract": "palonexus.pnxs/v1",
        "minimum_cli_version": "0.2.2",
        "maximum_cli_version_exclusive": "0.3.0",
        "registration_contract": "palonexus.developer-agent/v1",
    }


def test_developer_cli_compatibility_is_exact_and_enforced_before_mutation() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_compatibility_response())

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    session = {"session_token": "pnx_dev_session"}
    assert client.require_cli_compatibility(session, "0.2.2") == (
        _compatibility_response()
    )
    assert seen[0].url == ("https://api.palonexus.cloud/v1/developer/compatibility")
    assert seen[0].headers["authorization"] == "Bearer pnx_dev_session"

    with pytest.raises(CLIIncompatible, match="uv tool upgrade palonexus"):
        client.require_cli_compatibility(session, "0.2.1")


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "palonexus.developer-cli-compatibility/v2"),
        ("cli_contract", "palonexus.pnxs/v2"),
        ("registration_contract", "palonexus.developer-agent/v2"),
    ],
)
def test_developer_cli_compatibility_rejects_unknown_contracts(
    field: str, value: str
) -> None:
    response = {**_compatibility_response(), field: value}
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    with pytest.raises(CLIIncompatible):
        client.require_cli_compatibility({"session_token": "pnx_dev_session"}, "0.2.2")


def _registration_profile() -> dict[str, object]:
    return {
        "schema_version": "palonexus.agent-registration-profile/v1",
        "descriptor_version": "0.2.0",
        "runtime_profile": {"kind": "plain-python"},
        "composition_digest": "b" * 64,
        "harness_adapter_contracts": ["palonexus.actions/v1"],
        "not_before": "2026-08-21T00:00:00Z",
        "expires_at": "2027-08-21T00:00:00Z",
    }


def _ceiling_response(descriptor_digest: str) -> dict[str, object]:
    return {
        "schemaVersion": "palonexus.ceiling-request/v1",
        "requestId": "request-1",
        "version": 1,
        "tenantId": "tenant-a",
        "agentName": "release-risk-reviewer",
        "agentGeneration": 1,
        "descriptorDigest": descriptor_digest,
        "requestedBy": "member-1",
        "requestedRules": [
            {
                "schema_version": "palonexus.requested-capability/v1",
                "canonical_action": "release.assessment.publish",
                "resource": "release/demo",
                "constraints": {},
                "logical_target_id": "release-assessments",
            }
        ],
        "resolvedRules": [],
        "catalogVersion": 4,
        "requestHash": "b" * 64,
        "status": "pending",
        "expiresAt": "2026-08-13T19:00:00Z",
        "createdAt": "2026-08-12T19:00:00Z",
    }


def _revocation_response() -> dict[str, object]:
    return {
        "schema_version": "palonexus.developer-revocation/v1",
        "event_id": "revoke:release-risk-reviewer:1",
        "tenant_id": "tenant-a",
        "agent_id": "release-risk-reviewer",
        "previous_generation": 1,
        "generation": 2,
        "actor": "member-1",
        "revoked_at": "2026-08-13T12:00:00Z",
        "cascade_status": "applied",
        "cascade_applied_at": "2026-08-13T12:00:01Z",
    }


def test_agent_revocation_uses_exact_delete_and_requires_durable_correlation() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=_revocation_response())

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    session = {
        "session_token": "pnx_dev_session-secret",
        "tenant_id": "tenant-a",
        "membership_id": "member-1",
    }

    result = client.revoke_agent(
        session,
        "release-risk-reviewer",
        "release-risk-reviewer",
        expected_previous_generation=1,
    )

    assert result == _revocation_response()
    assert len(requests) == 1
    assert requests[0].method == "DELETE"
    assert requests[0].url.path == ("/v1/developer/agents/release-risk-reviewer")
    assert requests[0].headers["authorization"] == ("Bearer pnx_dev_session-secret")
    assert (
        requests[0].headers["idempotency-key"]
        == hashlib.sha256(
            b"DELETE /v1/developer/agents/release-risk-reviewer"
        ).hexdigest()
    )
    assert requests[0].content == b""


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "extra": "unsafe"},
        lambda value: {
            key: item for key, item in value.items() if key != "cascade_applied_at"
        },
        lambda value: {**value, "tenant_id": "tenant-b"},
        lambda value: {**value, "agent_id": "other-agent"},
        lambda value: {**value, "actor": "member-2"},
        lambda value: {**value, "previous_generation": 2},
        lambda value: {**value, "generation": 3},
        lambda value: {**value, "event_id": "revoke:other:1"},
        lambda value: {**value, "cascade_status": "pending"},
        lambda value: {**value, "cascade_applied_at": "2026-08-13T11:59:59Z"},
    ],
)
def test_agent_revocation_rejects_unbound_or_non_durable_response(
    mutation: object,
) -> None:
    response = mutation(_revocation_response())  # type: ignore[operator]
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    with pytest.raises(ProtocolError):
        client.revoke_agent(
            {
                "session_token": "pnx_dev_session-secret",
                "tenant_id": "tenant-a",
                "membership_id": "member-1",
            },
            "release-risk-reviewer",
            "release-risk-reviewer",
            expected_previous_generation=1,
        )


def test_agent_revocation_rejects_duplicate_response_field() -> None:
    raw = canonical_json(_revocation_response()).replace(
        b'"generation":2', b'"generation":2,"generation":2'
    )
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=raw)),
    )
    with pytest.raises(ProtocolError, match="strict JSON"):
        client.revoke_agent(
            {
                "session_token": "pnx_dev_session-secret",
                "tenant_id": "tenant-a",
                "membership_id": "member-1",
            },
            "release-risk-reviewer",
            "release-risk-reviewer",
            expected_previous_generation=1,
        )


@pytest.mark.parametrize("missing", ["tenant_id", "membership_id"])
def test_agent_revocation_rejects_incomplete_stored_session_before_delete(
    missing: str,
) -> None:
    requests: list[httpx.Request] = []
    session = {
        "session_token": "pnx_dev_session-secret",
        "tenant_id": "tenant-a",
        "membership_id": "member-1",
    }
    del session[missing]
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request)
                or httpx.Response(200, json=_revocation_response())
            )
        ),
    )
    with pytest.raises(ProtocolError):
        client.revoke_agent(
            session,
            "release-risk-reviewer",
            "release-risk-reviewer",
            expected_previous_generation=1,
        )
    assert requests == []


def test_agent_revocation_error_does_not_echo_response_secrets() -> None:
    secret = "pnx_dev_response-secret"
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(503, json={"session_token": secret})
        ),
    )
    with pytest.raises(DeveloperClientError) as caught:
        client.revoke_agent(
            {
                "session_token": "pnx_dev_session-secret",
                "tenant_id": "tenant-a",
                "membership_id": "member-1",
            },
            "release-risk-reviewer",
            "release-risk-reviewer",
            expected_previous_generation=1,
        )
    assert secret not in str(caught.value)


def _write_revocation_project(path: Path) -> str:
    descriptor = """schemaVersion: palonexus.agent/v1
name: release-risk-reviewer
version: 0.1.0
entrypoint: {module: agent, symbol: review_release}
inputSchema: {type: object}
outputSchema: &output {type: object}
actions:
  - action: release.assessment.publish
    resource: release/demo
    target: release-assessments
    approval: exact-action
    constraints: {}
    argumentSchema: *output
"""
    (path / "palonexus-agent.yaml").write_text(descriptor, encoding="utf-8")
    (path / "agent.py").write_text(
        "def review_release(change, context):\n    return change\n",
        encoding="utf-8",
    )
    (path / "input.json").write_text("{}", encoding="utf-8")
    return hashlib.sha256(descriptor.encode()).hexdigest()


def test_agents_revoke_persists_kill_generation_and_retries_exact_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    descriptor_digest = _write_revocation_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    values: dict[str, dict[str, str]] = {
        "session": {
            "session_token": "pnx_dev_session-secret",
            "tenant_id": "tenant-a",
            "membership_id": "member-1",
        },
        "agent:release-risk-reviewer": {
            **generate_agent_credential(),
            "agent_id": "release-risk-reviewer",
            "agent_generation": "1",
            "registered_descriptor_digest": descriptor_digest,
        },
    }
    expected_generations: list[int] = []

    class Store:
        def load(self, name: str) -> dict[str, str] | None:
            value = values.get(name)
            return dict(value) if value is not None else None

        def save(self, name: str, value: dict[str, str]) -> None:
            values[name] = dict(value)

    class Client:
        def __init__(self, origin: str) -> None:
            assert origin == "https://api.palonexus.cloud"

        def revoke_agent(
            self,
            session: dict[str, str],
            agent_name: str,
            agent_id: str,
            *,
            expected_previous_generation: int,
        ) -> dict[str, object]:
            assert session == values["session"]
            assert agent_name == agent_id == "release-risk-reviewer"
            expected_generations.append(expected_previous_generation)
            return _revocation_response()

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr("palonexus.cli.commands.DeveloperClient", Client)

    assert main(["agents", "revoke"]) == 0
    assert main(["agents", "revoke"]) == 0

    assert expected_generations == [1, 1]
    agent = values["agent:release-risk-reviewer"]
    assert agent["agent_generation"] == "2"
    assert agent["status"] == "revoked"
    assert agent["revocation_previous_generation"] == "1"
    assert agent["revocation_event_id"] == "revoke:release-risk-reviewer:1"
    assert agent["revocation_cascade_status"] == "applied"
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [
        json.dumps(_revocation_response(), sort_keys=True, separators=(",", ":")),
        json.dumps(_revocation_response(), sort_keys=True, separators=(",", ":")),
    ]
    assert values["session"]["session_token"] not in captured.out
    assert agent["private_key"] not in captured.out


def test_revoked_local_agent_cannot_start_a_new_runtime_with_old_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    descriptor_digest = _write_revocation_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    values = {
        "session": {
            "session_token": "pnx_dev_session-secret",
            "tenant_id": "tenant-a",
            "membership_id": "member-1",
        },
        "agent:release-risk-reviewer": {
            **generate_agent_credential(),
            "agent_id": "release-risk-reviewer",
            "agent_generation": "2",
            "registered_descriptor_digest": descriptor_digest,
            "status": "revoked",
            "revocation_previous_generation": "1",
            "revocation_event_id": "revoke:release-risk-reviewer:1",
            "revocation_cascade_status": "applied",
        },
    }

    class Store:
        def load(self, name: str) -> dict[str, str] | None:
            return values.get(name)

    class Client:
        def __init__(self, _origin: str) -> None:
            pass

        def create_runtime_enrollment(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("revoked local agent reached runtime enrollment")

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr("palonexus.cli.commands.DeveloperClient", Client)

    assert main(["run", "agent.py", "--input", "input.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "agent authority is locally revoked\n"


def test_agent_registration_uses_exact_pop_contract_and_zero_authority() -> None:
    descriptor_digest = "a" * 64
    credential = generate_agent_credential()
    public_jwk = json.loads(credential["public_key_jwk"])
    thumbprint = hashlib.sha256(
        json.dumps(public_jwk, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            201, json=_registration_response(descriptor_digest, thumbprint)
        )

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    result = client.register_agent(
        {
            "session_token": "pnx_dev_session",
            "tenant_id": "tenant-a",
            "membership_id": "member-1",
            "owner_subject": "okta:tenant-a:robin-singh",
        },
        credential,
        {
            "name": "release-risk-reviewer",
            "descriptor_digest": descriptor_digest,
            "authority_profile": _registration_profile(),
        },
        cli_version="0.2.2",
    )

    assert result["capabilities"] == []
    assert len(seen) == 1
    assert seen[0].url == "https://api.palonexus.cloud/v1/developer/agents"
    assert seen[0].headers["authorization"] == "Bearer pnx_dev_session"
    assert seen[0].headers["palonexus-cli-contract"] == "palonexus.pnxs/v1"
    assert seen[0].headers["palonexus-cli-version"] == "0.2.2"
    assert (
        seen[0].headers["idempotency-key"]
        == hashlib.sha256(seen[0].content).hexdigest()
    )
    body = json.loads(seen[0].content)
    assert set(body) == {
        "schema_version",
        "name",
        "descriptor_digest",
        "public_key_jwk",
        "descriptor_version",
        "runtime_profile",
        "composition_digest",
        "harness_adapter_contracts",
        "not_before",
        "expires_at",
        "proof",
    }
    assert "private" not in json.dumps(body).lower()
    message = json.dumps(
        {
            "descriptor_digest": descriptor_digest,
            "key_thumbprint": thumbprint,
            "name": "release-risk-reviewer",
            "purpose": "palonexus.developer-agent-registration.v1",
            "authority_profile": {
                "descriptor_version": "0.2.0",
                "runtime_profile": {"kind": "plain-python"},
                "composition_digest": "b" * 64,
                "harness_adapter_contracts": ["palonexus.actions/v1"],
                "not_before": "2026-08-21T00:00:00Z",
                "expires_at": "2027-08-21T00:00:00Z",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = base64.urlsafe_b64decode(
        body["proof"]["signature"] + "=" * (-len(body["proof"]["signature"]) % 4)
    )
    Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(
            credential["private_key"] + "=" * (-len(credential["private_key"]) % 4)
        )
    ).public_key().verify(signature, message)


def test_agents_register_recovers_an_exact_server_commit_and_saves_local_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    response = _registration_response("a" * 64, "b" * 64)
    session = {
        "tenant_id": "tenant-a",
        "membership_id": "member-1",
        "owner_subject": "okta:tenant-a:robin-singh",
    }
    agent = {
        "private_key": "local-secret",
        "ceiling_request_id": "stale-request",
        "ceiling_request_body": json.dumps(
            {
                "schemaVersion": "palonexus.ceiling-request/v1",
                "agentGeneration": 1,
                "descriptorDigest": "c" * 64,
                "expiresAt": "2026-08-22T00:00:00Z",
                "rules": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    descriptor: dict[str, object] = {
        "name": "release-risk-reviewer",
        "descriptor_digest": "a" * 64,
    }
    saved: dict[str, dict[str, str]] = {}

    class Store:
        def save(self, name: str, value: dict[str, str]) -> None:
            saved[name] = dict(value)

    class Client:
        def require_cli_compatibility(self, *args: object) -> dict[str, str]:
            return _compatibility_response()

        def register_agent(self, *args: object, **kwargs: object) -> dict[str, object]:
            raise ProtocolError("response contains an unknown field")

        def reconcile_agent_registration(
            self,
            actual_session: dict[str, str],
            actual_agent: dict[str, str],
            actual_descriptor: dict[str, object],
        ) -> dict[str, object]:
            assert actual_session == session
            assert actual_agent == agent
            assert actual_descriptor["authority_profile"] == _registration_profile()
            return response

    monkeypatch.setattr(
        "palonexus.cli.commands._project_client",
        lambda _: (
            Client(),
            Store(),
            session,
            agent,
            descriptor,
            "agent:release-risk-reviewer",
        ),
    )
    monkeypatch.setattr(
        "palonexus.cli.commands._project_registration_profile",
        _registration_profile,
    )
    monkeypatch.setattr("palonexus.cli.commands.installed_sdk_version", lambda: "0.2.2")

    assert main(["agents", "register"]) == 0
    assert saved["agent:release-risk-reviewer"]["agent_id"] == ("release-risk-reviewer")
    assert saved["agent:release-risk-reviewer"]["agent_generation"] == "1"
    assert (
        saved["agent:release-risk-reviewer"]["registered_descriptor_digest"] == "a" * 64
    )
    assert "ceiling_request_id" not in saved["agent:release-risk-reviewer"]
    assert "ceiling_request_body" not in saved["agent:release-risk-reviewer"]
    captured = capsys.readouterr()
    assert "already completed" in captured.err
    assert json.loads(captured.out) == response
    assert "local-secret" not in captured.out + captured.err


def test_registration_preserves_an_exact_authority_request_continuation() -> None:
    body = json.dumps(
        {
            "schemaVersion": "palonexus.ceiling-request/v1",
            "agentGeneration": 1,
            "descriptorDigest": "a" * 64,
            "expiresAt": "2026-08-22T00:00:00Z",
            "rules": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    agent = {
        "ceiling_request_id": "current-request",
        "ceiling_request_body": body,
    }

    cli_commands._retire_stale_ceiling_request(agent, "a" * 64)

    assert agent == {
        "ceiling_request_id": "current-request",
        "ceiling_request_body": body,
    }


def test_agents_register_preserves_the_original_error_when_reconciliation_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = {"tenant_id": "tenant-a"}
    agent = {"private_key": "local-secret"}
    descriptor: dict[str, object] = {
        "name": "release-risk-reviewer",
        "descriptor_digest": "a" * 64,
    }

    class Store:
        def save(self, name: str, value: dict[str, str]) -> None:
            raise AssertionError((name, value))

    class Client:
        def require_cli_compatibility(self, *args: object) -> dict[str, str]:
            return _compatibility_response()

        def register_agent(self, *args: object, **kwargs: object) -> dict[str, object]:
            raise ProtocolError("registration response is malformed")

        def reconcile_agent_registration(self, *args: object) -> dict[str, object]:
            raise ProtocolError("registered agent does not match")

    monkeypatch.setattr(
        "palonexus.cli.commands._project_client",
        lambda _: (
            Client(),
            Store(),
            session,
            agent,
            descriptor,
            "agent:release-risk-reviewer",
        ),
    )
    monkeypatch.setattr(
        "palonexus.cli.commands._project_registration_profile",
        _registration_profile,
    )
    monkeypatch.setattr("palonexus.cli.commands.installed_sdk_version", lambda: "0.2.2")

    assert main(["agents", "register"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "CLI:" in captured.err
    assert captured.err.endswith(
        "agent registration failed: registration response is malformed\n"
    )


def test_register_conflict_directs_web_registration_to_explicit_attach(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    session = {"tenant_id": "tenant-a"}
    descriptor: dict[str, object] = {
        "name": "r3-reviewer",
        "descriptor_digest": "a" * 64,
    }

    class Client:
        def require_cli_compatibility(self, *args: object) -> dict[str, str]:
            return _compatibility_response()

        def register_agent(self, *args: object, **kwargs: object) -> dict[str, object]:
            raise RequestRejected(409)

        def reconcile_agent_registration(self, *args: object) -> dict[str, object]:
            raise RequestRejected(404)

    monkeypatch.setattr(
        "palonexus.cli.commands._project_client",
        lambda _: (
            Client(),
            object(),
            session,
            {},
            descriptor,
            "agent:tenant-a:r3-reviewer",
        ),
    )
    monkeypatch.setattr(
        "palonexus.cli.commands._project_registration_profile",
        _registration_profile,
    )
    monkeypatch.setattr(
        "palonexus.cli.commands._project_descriptor", lambda: descriptor
    )
    monkeypatch.setattr("palonexus.cli.commands.installed_sdk_version", lambda: "0.2.3")

    assert main(["register", "r3-reviewer"]) == 1
    assert "pnxs agent attach r3-reviewer" in capsys.readouterr().err


def test_agents_add_registers_a_second_identity_without_copying_source_repo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    template = (
        Path(__file__).parents[1]
        / "src/palonexus/developer/templates/plain_python/palonexus-agent.yaml"
    )
    (source / "palonexus-agent.yaml").write_text(
        template.read_text(encoding="utf-8").replace(
            "release-risk-reviewer", "source-agent"
        ),
        encoding="utf-8",
    )
    (source / "palonexus-registration.yaml").write_text(
        """schema_version: palonexus.agent-registration-profile/v1
descriptor_version: 0.2.0
runtime_profile: {kind: plain-python}
composition_digest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
harness_adapter_contracts: [palonexus.actions/v1]
not_before: '2026-08-21T00:00:00Z'
expires_at: '2027-08-21T00:00:00Z'
""",
        encoding="utf-8",
    )
    source_before = {
        path.name: path.read_bytes() for path in source.iterdir() if path.is_file()
    }
    workspace = tmp_path / "registration"
    values: dict[str, dict[str, str]] = {
        "session": {
            "session_token": "pnx_dev_session-secret",
            "tenant_id": "tenant-a",
            "membership_id": "member-1",
            "owner_subject": "okta:tenant-a:robin-singh",
        }
    }
    created: list[str] = []

    class Store:
        state_dir = tmp_path / "state"

        def load(self, name: str) -> dict[str, str] | None:
            value = values.get(name)
            return dict(value) if value is not None else None

        def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
            if name in values:
                return False
            created.append(name)
            values[name] = dict(value)
            return True

        def save(self, name: str, value: dict[str, str]) -> None:
            values[name] = dict(value)

    class Client:
        def __init__(self, origin: str) -> None:
            assert origin == "https://api.palonexus.cloud"

        def require_cli_compatibility(self, *args: object) -> dict[str, str]:
            return _compatibility_response()

        def register_agent(
            self,
            session: dict[str, str],
            agent: dict[str, str],
            descriptor: dict[str, object],
            **kwargs: object,
        ) -> dict[str, object]:
            assert session == values["session"]
            assert descriptor["name"] == "second-agent"
            assert descriptor["authority_profile"] == _registration_profile()
            public_jwk = json.loads(agent["public_key_jwk"])
            thumbprint = hashlib.sha256(canonical_json(public_jwk)).hexdigest()
            return {
                **_registration_response(
                    str(descriptor["descriptor_digest"]), thumbprint
                ),
                "agent_id": "second-agent",
                "name": "second-agent",
            }

        def reconcile_agent_registration(self, *args: object) -> dict[str, object]:
            raise AssertionError("successful registration attempted recovery")

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr("palonexus.cli.commands.DeveloperClient", Client)
    monkeypatch.setattr(
        "palonexus.cli.commands._require_standalone_registration_cli", lambda: None
    )
    monkeypatch.setattr("palonexus.cli.commands.installed_sdk_version", lambda: "0.2.2")

    argv = [
        "agents",
        "add",
        "--from",
        str(source),
        "--name",
        "second-agent",
        "--tenant",
        "tenant-a",
        "--workspace",
        str(workspace),
        "--yes",
    ]
    assert main(argv) == 0
    assert main(argv) == 0
    assert {
        path.name: path.read_bytes() for path in source.iterdir() if path.is_file()
    } == source_before

    credential_name = "agent:tenant-a:second-agent"
    assert created == [credential_name]
    assert values[credential_name]["agent_id"] == "second-agent"
    assert values[credential_name]["agent_generation"] == "1"
    derived = yaml.safe_load(
        (workspace / "palonexus-agent.yaml").read_text(encoding="utf-8")
    )
    assert derived["name"] == "second-agent"
    assert (
        yaml.safe_load(
            (workspace / "palonexus-registration.yaml").read_text(encoding="utf-8")
        )["composition_digest"]
        == "b" * 64
    )
    receipt = json.loads((workspace / "registration.json").read_text())
    assert receipt["registration"]["agent_id"] == "second-agent"
    all_local_files = "".join(
        path.read_text(encoding="utf-8")
        for path in workspace.iterdir()
        if path.is_file()
    )
    assert values[credential_name]["private_key"] not in all_local_files
    captured = capsys.readouterr()
    assert "Owner:  okta:tenant-a:robin-singh" in captured.err
    assert "Tenant: tenant-a" in captured.err
    assert "Workspace:" in captured.err
    assert values[credential_name]["private_key"] not in captured.out + captured.err


def test_agents_add_incompatible_cli_makes_no_local_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "registration"

    class Store:
        state_dir = tmp_path / "state"

        def load(self, name: str) -> dict[str, str] | None:
            assert name == "session"
            return {
                "session_token": "pnx_dev_session-secret",
                "tenant_id": "tenant-a",
                "owner_subject": "okta:tenant-a:robin-singh",
            }

        def create_if_absent(self, *args: object) -> bool:
            raise AssertionError("incompatible CLI created a credential")

    class Client:
        def __init__(self, _origin: str) -> None:
            pass

        def require_cli_compatibility(self, *args: object) -> dict[str, str]:
            raise CLIIncompatible(
                "No changes were made. Upgrade with `uv tool upgrade palonexus`."
            )

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr("palonexus.cli.commands.DeveloperClient", Client)
    monkeypatch.setattr(
        "palonexus.cli.commands._require_standalone_registration_cli", lambda: None
    )
    monkeypatch.setattr(
        "palonexus.cli.commands._derived_registration_material",
        lambda *_: (b"descriptor", b"profile"),
    )
    monkeypatch.setattr("palonexus.cli.commands.installed_sdk_version", lambda: "0.2.1")
    args = build_parser().parse_args(
        [
            "agents",
            "add",
            "--from",
            str(tmp_path / "source"),
            "--name",
            "second-agent",
            "--tenant",
            "tenant-a",
            "--workspace",
            str(workspace),
            "--yes",
        ]
    )

    with pytest.raises(CommandError, match="uv tool upgrade palonexus"):
        from palonexus.cli.commands import agents_add

        agents_add(args)
    assert not workspace.exists()


def test_registration_rejects_a_project_virtualenv_cli_before_mutation(
    tmp_path: Path,
) -> None:
    from palonexus.cli.commands import _standalone_cli_preflight

    active = tmp_path / "project/.venv"
    invocation = active / "bin/pnxs"
    standalone = tmp_path / "bin/pnxs"
    invocation.parent.mkdir(parents=True)
    standalone.parent.mkdir(parents=True)
    for executable in (invocation, standalone):
        executable.touch()
        executable.chmod(0o700)
    with pytest.raises(CommandError, match=str(standalone)):
        _standalone_cli_preflight(
            invocation=invocation,
            virtual_env=active,
            search_path=os.pathsep.join((str(active / "bin"), str(standalone.parent))),
        )
    _standalone_cli_preflight(
        invocation=standalone,
        virtual_env=active,
        search_path=os.pathsep.join((str(active / "bin"), str(standalone.parent))),
    )


def test_project_client_prefers_tenant_scoped_agent_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from palonexus.cli.commands import _project_client

    _write_revocation_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    values = {
        "session": {"session_token": "session", "tenant_id": "tenant-a"},
        "agent:tenant-a:release-risk-reviewer": {"source": "scoped"},
        "agent:release-risk-reviewer": {"source": "legacy"},
    }
    loaded: list[str] = []

    class Store:
        def load(self, name: str) -> dict[str, str] | None:
            loaded.append(name)
            return values.get(name)

    class Client:
        def __init__(self, origin: str) -> None:
            assert origin == "https://api.palonexus.cloud"

    monkeypatch.setattr("palonexus.cli.commands.credential_store", lambda **_: Store())
    monkeypatch.setattr("palonexus.cli.commands.DeveloperClient", Client)
    args = build_parser().parse_args(["agents", "status"])

    *_, agent, _descriptor, credential_name = _project_client(args)
    assert agent == {"source": "scoped"}
    assert credential_name == "agent:tenant-a:release-risk-reviewer"
    assert loaded == ["session", "agent:tenant-a:release-risk-reviewer"]

    del values["agent:tenant-a:release-risk-reviewer"]
    loaded.clear()
    *_, agent, _descriptor, credential_name = _project_client(args)
    assert agent == {"source": "legacy"}
    assert credential_name == "agent:release-risk-reviewer"
    assert loaded == [
        "session",
        "agent:tenant-a:release-risk-reviewer",
        "agent:release-risk-reviewer",
    ]


def test_registered_agent_resolves_owner_bound_identity() -> None:
    response = _registration_response("a" * 64, "b" * 64)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=response)

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    resolved = client.registered_agent(
        {
            "session_token": "pnx_dev_session",
            "tenant_id": "tenant-a",
            "owner_subject": "okta:tenant-a:robin-singh",
        },
        "release-risk-reviewer",
    )

    assert resolved == response
    assert len(seen) == 1
    assert seen[0].method == "GET"
    assert seen[0].url == (
        "https://api.palonexus.cloud/v1/developer/agents/release-risk-reviewer"
    )
    assert seen[0].headers["authorization"] == "Bearer pnx_dev_session"


def test_registered_agent_reconciliation_requires_the_exact_local_binding() -> None:
    descriptor_digest = "a" * 64
    credential = generate_agent_credential()
    public_jwk = json.loads(credential["public_key_jwk"])
    thumbprint = hashlib.sha256(
        json.dumps(public_jwk, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    response = _registration_response(descriptor_digest, thumbprint)
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    session = {
        "session_token": "pnx_dev_session",
        "tenant_id": "tenant-a",
        "membership_id": "member-1",
        "owner_subject": "okta:tenant-a:robin-singh",
    }
    descriptor = {
        "name": "release-risk-reviewer",
        "descriptor_digest": descriptor_digest,
        "authority_profile": _registration_profile(),
    }

    assert (
        client.reconcile_agent_registration(session, credential, descriptor) == response
    )
    with pytest.raises(ProtocolError):
        client.reconcile_agent_registration(
            session,
            {
                **credential,
                "public_key_jwk": generate_agent_credential()["public_key_jwk"],
            },
            descriptor,
        )


def test_agent_registration_binds_canonical_owner_subject_not_membership_id() -> None:
    descriptor_digest = "a" * 64
    credential = generate_agent_credential()
    public_jwk = json.loads(credential["public_key_jwk"])
    thumbprint = hashlib.sha256(
        json.dumps(public_jwk, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    response = _registration_response(descriptor_digest, thumbprint)
    response["accountable_owner"] = "okta:tenant-a:employee-1"
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=response)),
    )

    result = client.register_agent(
        {
            "session_token": "pnx_dev_session",
            "tenant_id": "tenant-a",
            "membership_id": "member-1",
            "owner_subject": "okta:tenant-a:employee-1",
        },
        credential,
        {
            "name": "release-risk-reviewer",
            "descriptor_digest": descriptor_digest,
            "authority_profile": _registration_profile(),
        },
    )

    assert result["accountable_owner"] == "okta:tenant-a:employee-1"


def test_ceiling_request_and_status_use_exact_router_contract() -> None:
    descriptor_digest = "a" * 64
    response = _ceiling_response(descriptor_digest)
    seen: list[httpx.Request] = []
    approval_url = (
        "https://demo1.palonexus.cloud/developer-agents/"
        "release-risk-reviewer?request=request-1"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        value = (
            {**response, "approvalUrl": approval_url}
            if request.method == "POST"
            else response
        )
        return httpx.Response(201 if request.method == "POST" else 200, json=value)

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    session = {
        "session_token": "pnx_dev_session",
        "tenant_id": "tenant-a",
        "membership_id": "member-1",
    }
    request_body = {
        "schemaVersion": "palonexus.ceiling-request/v1",
        "agentGeneration": 1,
        "descriptorDigest": descriptor_digest,
        "expiresAt": "2026-08-13T19:00:00Z",
        "rules": response["requestedRules"],
    }

    created = client.request_authority(
        session, "release-risk-reviewer", "request-1", request_body
    )
    status = client.agent_status(session, "release-risk-reviewer", "request-1")

    assert created == {**response, "approvalUrl": approval_url}
    assert status == response
    assert seen[0].headers["idempotency-key"] == "request-1"
    assert json.loads(seen[0].content) == request_body
    assert seen[1].method == "GET"
    assert seen[1].url.path == (
        "/v1/developer/agents/release-risk-reviewer/ceiling-requests/request-1"
    )


@pytest.mark.parametrize(
    "approval_url",
    [
        "http://demo1.palonexus.cloud/developer-agents/release-risk-reviewer?request=request-1",
        "https://demo1.palonexus.cloud/other?request=request-1",
        "https://demo1.palonexus.cloud/developer-agents/other?request=request-1",
        "https://demo1.palonexus.cloud/developer-agents/release-risk-reviewer?request=other",
        "https://user@demo1.palonexus.cloud/developer-agents/release-risk-reviewer?request=request-1",
        "https://demo1.palonexus.cloud/developer-agents/release-risk-reviewer?request=request-1#fragment",
    ],
)
def test_ceiling_request_rejects_unsafe_or_unbound_approval_url(
    approval_url: str,
) -> None:
    descriptor_digest = "a" * 64
    response = {
        **_ceiling_response(descriptor_digest),
        "approvalUrl": approval_url,
    }
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=response)),
    )
    with pytest.raises(ProtocolError, match="approval"):
        client.request_authority(
            {
                "session_token": "pnx_dev_session",
                "tenant_id": "tenant-a",
                "membership_id": "member-1",
            },
            "release-risk-reviewer",
            "request-1",
            {
                "schemaVersion": "palonexus.ceiling-request/v1",
                "agentGeneration": 1,
                "descriptorDigest": descriptor_digest,
                "expiresAt": "2026-08-13T19:00:00Z",
                "rules": response["requestedRules"],
            },
        )


def test_ceiling_creation_rejects_server_mutation_of_immutable_request() -> None:
    descriptor_digest = "a" * 64
    response = _ceiling_response(descriptor_digest)
    response["agentGeneration"] = 2
    response["requestedRules"] = [
        {
            **response["requestedRules"][0],  # type: ignore[index]
            "resource": "release/other",
        }
    ]
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=response)),
    )
    request_body = {
        "schemaVersion": "palonexus.ceiling-request/v1",
        "agentGeneration": 1,
        "descriptorDigest": descriptor_digest,
        "expiresAt": "2026-08-13T19:00:00Z",
        "rules": _ceiling_response(descriptor_digest)["requestedRules"],
    }
    with pytest.raises(ProtocolError, match="bound"):
        client.request_authority(
            {
                "session_token": "pnx_dev_session",
                "tenant_id": "tenant-a",
                "membership_id": "member-1",
            },
            "release-risk-reviewer",
            "request-1",
            request_body,
        )


def test_ceiling_status_rejects_malformed_resolved_rule_or_decision() -> None:
    descriptor_digest = "a" * 64
    responses = []
    malformed_resolved = _ceiling_response(descriptor_digest)
    malformed_resolved["resolvedRules"] = [{"approvalMode": "automatic"}]
    responses.append(malformed_resolved)
    malformed_decision = _ceiling_response(descriptor_digest)
    malformed_decision["status"] = "approved"
    malformed_decision["decision"] = {"actor": "owner-2"}
    responses.append(malformed_decision)
    session = {
        "session_token": "pnx_dev_session",
        "tenant_id": "tenant-a",
        "membership_id": "member-1",
    }
    for response in responses:
        client = DeveloperClient(
            "https://api.palonexus.cloud",
            transport=httpx.MockTransport(
                lambda _, response=response: httpx.Response(200, json=response)
            ),
        )
        with pytest.raises(ProtocolError):
            client.agent_status(session, "release-risk-reviewer", "request-1")


def test_developer_action_payload_and_strict_lifecycle_records() -> None:
    seen: list[dict[str, object]] = []
    payload = {"assessment": {"risk": "low", "score": 0.12}}
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    base = {
        "schemaVersion": "palonexus.developer-action/v1",
        "tenantId": "tenant-a",
        "runId": "run-a",
        "rootId": "root-a",
        "actionId": "action-a",
        "version": 1,
        "agentName": "release-agent",
        "requestedBy": "member-a",
        "agentGeneration": 1,
        "runtimeLeaseId": "runtime-a",
        "runtimeGuardObserved": True,
        "runtimeGuardEvidenceId": "e" * 64,
        "runtimeGuardLeaseId": "runtime-a",
        "runtimeGuardGeneration": 1,
        "canonicalAction": "release.assessment.publish",
        "resource": "release/demo",
        "constraints": {"max_risk_score": 0.5},
        "payload": payload,
        "payloadDigest": digest,
        "idempotencyKey": "action-key",
        "effectIdempotencyKey": "effect-key",
        "requestHash": "f" * 64,
        "ceilingRequestId": "ceiling-a",
        "ceilingVersion": 1,
        "target": {
            "registrationId": "release-assessments",
            "version": 2,
        },
        "approval": {"status": "pending"},
        "delivery": {"state": "not_ready"},
        "createdAt": "2026-08-12T12:00:00Z",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            seen.append(json.loads(request.content))
            return httpx.Response(201, json=base)
        return httpx.Response(
            200,
            json={
                **base,
                "proxyId": "proxy-a",
                "proxyGeneration": 1,
                "proxyProofKeyThumbprint": "p" * 43,
                "approval": {"status": "approved"},
                "delivery": {
                    "state": "delivered",
                    "capabilityId": "capability-a",
                },
                "receipt": {
                    "schemaVersion": "palonexus.developer-receipt-reference/v1",
                    "receiptId": "receipt-a",
                    "opaqueDigest": "a" * 64,
                    "recordedAt": "2026-08-12T12:02:00Z",
                    "verified": True,
                    "capabilityId": "capability-a",
                    "tenantId": "tenant-a",
                    "runId": "run-a",
                    "rootId": "root-a",
                    "actionId": "action-a",
                    "payloadDigest": digest,
                    "targetRegistrationId": "release-assessments",
                    "targetRegistrationVersion": 2,
                    "effectIdempotencyKey": "effect-key",
                    "effectId": "effect-a",
                    "effectCreatedAt": "2026-08-12T12:01:59Z",
                },
                "terminalAt": "2026-08-12T12:02:00Z",
            },
        )

    client = DeveloperClient(
        "https://api.palonexus.cloud", transport=httpx.MockTransport(handler)
    )
    guard = generate_agent_credential()
    session = {"tenant_id": "tenant-a", "session_token": "session-a"}
    agent = {"agent_id": "release-agent", "agent_generation": "1"}
    created = client.create_developer_action(
        session,
        agent,
        guard,
        {"runtime_id": "runtime-a"},
        {"runId": "run-a"},
        action="release.assessment.publish",
        resource="release/demo",
        constraints={"max_risk_score": 0.5},
        payload=payload,
        idempotency_key="action-key",
        effect_idempotency_key="effect-key",
    )
    terminal = client.get_developer_action(session, "run-a", "action-a")

    assert seen[0]["payload"] == payload
    assert seen[0]["payloadDigest"] == digest
    assert created["runtimeGuardObserved"] is True
    assert terminal["proxyId"] == "proxy-a" and terminal["terminalAt"]
    assert terminal["receipt"]["capabilityId"] == "capability-a"


def test_developer_action_preserves_exact_terminal_capability_denial() -> None:
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                403,
                headers={"Content-Type": "application/json"},
                json={
                    "schemaVersion": "palonexus.agent-command-outcome/v1",
                    "disposition": "terminal",
                    "code": "capability_denied",
                    "reasonCode": "OUTSIDE_RUN_GRANT",
                },
            )
        ),
    )
    with pytest.raises(CapabilityDenied, match="outside effective run grant"):
        client.create_developer_action(
            {"tenant_id": "tenant-a"},
            {"agent_id": "release-agent", "agent_generation": "1"},
            generate_agent_credential(),
            {"runtime_id": "runtime-a"},
            {"runId": "run-a"},
            action="release.delete",
            resource="release/demo",
            constraints={},
            payload={},
            idempotency_key="action-key",
            effect_idempotency_key="effect-key",
        )


def test_developer_run_accepts_server_cancellation_timestamp_field() -> None:
    response = {
        "schemaVersion": "palonexus.developer-run/v1",
        "tenantId": "tenant-a",
        "runId": "run-a",
        "rootId": "root-a",
        "agentName": "release-agent",
        "agentGeneration": 1,
        "runtimeLeaseId": "runtime-a",
        "descriptorDigest": "a" * 64,
        "inputDigest": "b" * 64,
        "artifactIdentity": "sha256:" + "a" * 64,
        "requestedBy": "member-a",
        "idempotencyKey": "run-key",
        "requestHash": "c" * 64,
        "ceilingRequestId": "ceiling-a",
        "ceilingVersion": 1,
        "effectiveGrantRef": "developer-grant:grant-a",
        "status": "active",
        "canceledAt": "0001-01-01T00:00:00Z",
        "createdAt": "2026-08-12T12:00:00Z",
    }
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=response)),
    )
    guard = generate_agent_credential()

    created = client.create_developer_run(
        {"tenant_id": "tenant-a"},
        {"agent_id": "release-agent", "agent_generation": "1"},
        guard,
        {"runtime_id": "runtime-a"},
        input_digest="b" * 64,
        idempotency_key="run-key",
    )

    assert created["canceledAt"] == "0001-01-01T00:00:00Z"


@pytest.mark.parametrize(
    ("receipt_mutation", "accepted"),
    [
        (lambda value: {**value, "gatewayDecisionId": "gateway-a"}, False),
        (lambda value: {**value, "unknown": True}, False),
        (
            lambda value: {
                key: item for key, item in value.items() if key != "capabilityId"
            },
            False,
        ),
        (
            lambda value: {
                **{key: item for key, item in value.items() if key != "capabilityId"},
                "gatewayDecisionId": "gateway-a",
                "gatewayOutcome": "allow",
            },
            True,
        ),
    ],
)
def test_developer_action_receipt_generations_fail_closed(
    receipt_mutation: object,
    accepted: bool,
) -> None:
    payload = {"assessment": {"risk": "low", "score": 0.12}}
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    receipt = {
        "schemaVersion": "palonexus.developer-receipt-reference/v1",
        "receiptId": "receipt-a",
        "opaqueDigest": "a" * 64,
        "recordedAt": "2026-08-12T12:02:00Z",
        "verified": True,
        "capabilityId": "capability-a",
        "tenantId": "tenant-a",
        "runId": "run-a",
        "rootId": "root-a",
        "actionId": "action-a",
        "payloadDigest": digest,
        "targetRegistrationId": "release-assessments",
        "targetRegistrationVersion": 2,
        "effectIdempotencyKey": "effect-key",
        "effectId": "effect-a",
        "effectCreatedAt": "2026-08-12T12:01:59Z",
    }
    mutated_receipt = receipt_mutation(receipt)  # type: ignore[operator]
    response = {
        "schemaVersion": "palonexus.developer-action/v1",
        "tenantId": "tenant-a",
        "runId": "run-a",
        "rootId": "root-a",
        "actionId": "action-a",
        "version": 1,
        "agentName": "release-agent",
        "requestedBy": "member-a",
        "agentGeneration": 1,
        "runtimeLeaseId": "runtime-a",
        "canonicalAction": "release.assessment.publish",
        "resource": "release/demo",
        "constraints": {"max_risk_score": 0.5},
        "payload": payload,
        "payloadDigest": digest,
        "idempotencyKey": "action-key",
        "effectIdempotencyKey": "effect-key",
        "requestHash": "f" * 64,
        "ceilingRequestId": "ceiling-a",
        "ceilingVersion": 1,
        "target": {
            "registrationId": "release-assessments",
            "version": 2,
        },
        "approval": {"status": "approved"},
        "delivery": {
            "state": "delivered",
            **(
                {"capabilityId": "capability-a"}
                if "capabilityId" in mutated_receipt
                else {}
            ),
        },
        "receipt": mutated_receipt,
        "createdAt": "2026-08-12T12:00:00Z",
        "terminalAt": "2026-08-12T12:02:00Z",
    }
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )

    def call() -> dict[str, object]:
        return client.get_developer_action(
            {"tenant_id": "tenant-a", "session_token": "session-a"},
            "run-a",
            "action-a",
        )

    if accepted:
        assert call()["receipt"]["gatewayOutcome"] == "allow"
    else:
        with pytest.raises(ProtocolError):
            call()


@pytest.mark.parametrize(
    "delivery",
    [
        {"state": "delivered", "capabilityId": "capability-b"},
        {"state": "ready", "capabilityId": "capability-a"},
        {"state": "delivered", "capabilityId": "capability-a", "unknown": True},
    ],
)
def test_developer_action_delivery_capability_fails_closed(
    delivery: dict[str, object],
) -> None:
    payload = {"assessment": {"risk": "low", "score": 0.12}}
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    response = {
        "schemaVersion": "palonexus.developer-action/v1",
        "tenantId": "tenant-a",
        "runId": "run-a",
        "rootId": "root-a",
        "actionId": "action-a",
        "version": 1,
        "agentName": "release-agent",
        "requestedBy": "member-a",
        "agentGeneration": 1,
        "runtimeLeaseId": "runtime-a",
        "canonicalAction": "release.assessment.publish",
        "resource": "release/demo",
        "constraints": {},
        "payloadDigest": digest,
        "idempotencyKey": "action-key",
        "effectIdempotencyKey": "effect-key",
        "requestHash": "f" * 64,
        "ceilingRequestId": "ceiling-a",
        "ceilingVersion": 1,
        "target": {"registrationId": "release-assessments", "version": 2},
        "approval": {"status": "approved"},
        "delivery": delivery,
        "receipt": {
            "schemaVersion": "palonexus.developer-receipt-reference/v1",
            "receiptId": "receipt-a",
            "opaqueDigest": "a" * 64,
            "recordedAt": "2026-08-12T12:02:00Z",
            "verified": True,
            "capabilityId": "capability-a",
            "tenantId": "tenant-a",
            "runId": "run-a",
            "rootId": "root-a",
            "actionId": "action-a",
            "payloadDigest": digest,
            "targetRegistrationId": "release-assessments",
            "targetRegistrationVersion": 2,
            "effectIdempotencyKey": "effect-key",
            "effectId": "effect-a",
            "effectCreatedAt": "2026-08-12T12:01:59Z",
        },
        "createdAt": "2026-08-12T12:00:00Z",
        "terminalAt": "2026-08-12T12:02:00Z",
    }
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )

    with pytest.raises(ProtocolError):
        client.get_developer_action(
            {"tenant_id": "tenant-a", "session_token": "session-a"},
            "run-a",
            "action-a",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "private_key": "leaked"},
        lambda value: {**value, "tenant_id": "tenant-b"},
        lambda value: {**value, "generation": True},
        lambda value: {**value, "capabilities": ["release.assessment.publish"]},
        lambda value: {**value, "descriptor_version": "other-contract"},
    ],
)
def test_agent_registration_response_fails_closed_on_unsafe_or_malformed_data(
    mutation: object,
) -> None:
    credential = generate_agent_credential()
    public_jwk = json.loads(credential["public_key_jwk"])
    thumbprint = hashlib.sha256(
        json.dumps(public_jwk, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    value = mutation(_registration_response("a" * 64, thumbprint))  # type: ignore[operator]
    client = DeveloperClient(
        "https://api.palonexus.cloud",
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=value)),
    )
    with pytest.raises(ProtocolError):
        client.register_agent(
            {
                "session_token": "pnx_dev_session",
                "tenant_id": "tenant-a",
                "membership_id": "member-1",
                "owner_subject": "okta:tenant-a:robin-singh",
            },
            credential,
            {
                "name": "release-risk-reviewer",
                "descriptor_digest": "a" * 64,
                "authority_profile": _registration_profile(),
            },
        )


def test_generated_descriptor_is_strict_and_requests_frozen_exact_resource(
    tmp_path: Path,
) -> None:
    from palonexus.cli.commands import _project_descriptor

    descriptor_path = tmp_path / "palonexus-agent.yaml"
    descriptor_path.write_text(
        """schemaVersion: palonexus.agent/v1
name: release-risk-reviewer
version: 0.1.0
entrypoint:
  module: agent
  symbol: review_release
inputSchema:
  type: object
  additionalProperties: false
  required: [change_id, risk, summary]
  properties:
    change_id: {type: string}
    risk: {type: string, enum: [low, medium, high]}
    summary: {type: string}
outputSchema: &assessmentPayload
  type: object
  additionalProperties: false
  required: [assessment]
  properties:
    assessment:
      type: object
      additionalProperties: false
      required: [risk, score]
      properties:
        risk: {type: string, enum: [low, medium, high]}
        score: {type: number, minimum: 0, maximum: 1}
actions:
  - action: release.assessment.publish
    resource: release/demo
    target: release-assessments
    approval: exact-action
    constraints: {max_risk_score: 1}
    argumentSchema: *assessmentPayload
""",
        encoding="utf-8",
    )
    descriptor = _project_descriptor(descriptor_path)
    assert descriptor["rules"] == [
        {
            "schema_version": "palonexus.requested-capability/v1",
            "canonical_action": "release.assessment.publish",
            "resource": "release/demo",
            "constraints": {"max_risk_score": 1},
            "logical_target_id": "release-assessments",
        }
    ]
    assert (
        descriptor["descriptor_digest"]
        == hashlib.sha256(descriptor_path.read_bytes()).hexdigest()
    )
    assert descriptor["input_schema"]["required"] == [
        "change_id",
        "risk",
        "summary",
    ]
    assert descriptor["output_schema"] == descriptor["action_schema"]
    assert descriptor["action_schema"]["properties"]["assessment"]["required"] == [
        "risk",
        "score",
    ]

    descriptor_path.write_text(
        descriptor_path.read_text(encoding="utf-8") + "tenantId: tenant-a\n",
        encoding="utf-8",
    )
    with pytest.raises(CommandError, match="descriptor"):
        _project_descriptor(descriptor_path)


def test_descriptor_supports_multiple_unique_exact_actions(tmp_path: Path) -> None:
    from palonexus.cli.commands import _descriptor_action, _project_descriptor

    descriptor_path = tmp_path / "palonexus-agent.yaml"
    descriptor_path.write_text(
        """schemaVersion: palonexus.agent/v1
name: release-risk-reviewer
version: 0.2.0
entrypoint: {module: agent, symbol: review_release}
inputSchema: {type: object}
outputSchema: {type: object}
actions:
  - action: mcp:change-control-mcp/assess-release/schema-a
    resource: release/demo
    target: change-control-mcp-assess
    approval: exact-action
    constraints: {max_risk_score: 1}
    argumentSchema: {type: object, required: [release_id]}
  - action: mcp:change-control-mcp/delete-release/schema-b
    resource: release/demo
    target: change-control-mcp-delete
    approval: exact-action
    requestAuthority: false
    constraints: {}
    argumentSchema: {type: object, required: [release_id]}
""",
        encoding="utf-8",
    )

    descriptor = _project_descriptor(descriptor_path)

    assert [rule["canonical_action"] for rule in descriptor["rules"]] == [
        "mcp:change-control-mcp/assess-release/schema-a"
    ]
    assert [action["target"] for action in descriptor["actions"]] == [
        "change-control-mcp-assess",
        "change-control-mcp-delete",
    ]
    assert descriptor["actions"][0]["argument_schema"]["required"] == ["release_id"]
    assert (
        _descriptor_action(
            descriptor,
            "mcp:change-control-mcp/delete-release/schema-b",
            "release/demo",
        )["constraints"]
        == {}
    )
    with pytest.raises(CommandError, match="not declared"):
        _descriptor_action(descriptor, "mcp:change-control-mcp/unknown/schema-c", "r")

    descriptor_path.write_text(
        descriptor_path.read_text(encoding="utf-8").replace(
            "mcp:change-control-mcp/delete-release/schema-b",
            "mcp:change-control-mcp/assess-release/schema-a",
        ),
        encoding="utf-8",
    )
    with pytest.raises(CommandError, match="unique"):
        _project_descriptor(descriptor_path)


def test_descriptor_binds_governed_subagent_without_action_authority(
    tmp_path: Path,
) -> None:
    from palonexus.cli.commands import _project_descriptor

    source = (
        Path(__file__).parents[2] / "examples/r3-governed-agent/palonexus-agent.yaml"
    )
    descriptor_path = tmp_path / "palonexus-agent.yaml"
    descriptor_path.write_bytes(source.read_bytes())

    descriptor = _project_descriptor(descriptor_path)

    assert descriptor["subagents"] == [
        {
            "name": "evidence-checker",
            "version": "1",
            "digest": (
                "a8c921382a7456782eabbba736c5973be5b7385c717992cd5acfd3ea7abb6964"
            ),
            "runtime_profile": "python-sandbox",
            "sandbox_profile": "network-restricted",
            "attestation_requirement_digest": (
                "ee8f1bbab0243c9aacf3549a5b4c8787c0f65a0f55e5a4b6baa6a88a84c928da"
            ),
            "requested_ttl_seconds": 300,
            "requested_authority": {
                "capability_ids": ["controlled_publisher"],
                "action_classes": ["controlled_publish"],
                "action_ids": [
                    "mcp:change-control-mcp/assess_release/93c5c52c6762a21b1b35dea92835f8385a29c7c9da3ecb4f1b4c0faa3937132b"
                ],
                "effects": ["external_record.create"],
                "resources": ["release:2026.08.30"],
                "target_registration_ids": ["change-control-mcp"],
                "constraints_digest": (
                    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                ),
                "maximum_token_ttl_seconds": 120,
                "requires_human_approval": False,
            },
            "budget_reservation": {
                "cost_microunits": 0,
                "model_tokens": 0,
                "steps": 1,
                "tool_calls": 1,
                "external_effects": 1,
                "jobs": 0,
            },
        }
    ]
    assert [rule["canonical_action"] for rule in descriptor["rules"]] == [
        "mcp:change-control-mcp/assess_release/93c5c52c6762a21b1b35dea92835f8385a29c7c9da3ecb4f1b4c0faa3937132b"
    ]


def test_registration_profile_is_explicit_strict_and_required(
    tmp_path: Path,
) -> None:
    from palonexus.cli.commands import _project_registration_profile

    profile_path = tmp_path / "palonexus-registration.yaml"
    profile_path.write_text(
        """schema_version: palonexus.agent-registration-profile/v1
descriptor_version: 0.2.0
runtime_profile: {kind: plain-python}
composition_digest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
harness_adapter_contracts: [palonexus.actions/v1]
not_before: '2026-08-21T00:00:00Z'
expires_at: '2027-08-21T00:00:00Z'
""",
        encoding="utf-8",
    )
    assert _project_registration_profile(profile_path) == _registration_profile()

    profile_path.unlink()
    with pytest.raises(CommandError, match="palonexus-registration.yaml is required"):
        _project_registration_profile(profile_path)
