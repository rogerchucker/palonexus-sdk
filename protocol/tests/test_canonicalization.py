from __future__ import annotations

import importlib
import importlib.util
import json
import subprocess
import sys
import unicodedata
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
REFERENCE_MODULE = "protocol.reference.canonicalize"
REFERENCE = ROOT / "reference" / "canonicalize.py"
VECTORS = ROOT / "test-vectors" / "canonicalization"


@pytest.fixture(scope="module")
def canonicalize() -> ModuleType:
    assert importlib.util.find_spec(REFERENCE_MODULE) is not None, (
        "Task 6 reference canonicalizer is missing"
    )
    return importlib.import_module(REFERENCE_MODULE)


def _error_code(exc_info: pytest.ExceptionInfo[BaseException]) -> str:
    return str(getattr(exc_info.value, "code", ""))


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    (
        (
            {"e\u0301": "Cafe\u0301", "z": 1},
            {"é": "Café", "z": Decimal("1.0")},
            b'{"z":1,"\xc3\xa9":"Caf\xc3\xa9"}',
        ),
        (
            {"nested": {"b": 2, "a": 1}, "array": ["e\u0301", None]},
            {"array": ["é", None], "nested": {"a": 1, "b": 2}},
            b'{"array":["\xc3\xa9",null],"nested":{"a":1,"b":2}}',
        ),
    ),
)
def test_canonical_json_is_nfc_sorted_compact_and_utf8(
    canonicalize: ModuleType,
    left: dict[str, Any],
    right: dict[str, Any],
    expected: bytes,
) -> None:
    assert canonicalize.canonical_json(left) == expected
    assert canonicalize.canonical_json(right) == expected


def test_unicode_contract_is_pinned_and_sorts_by_scalar_value(
    canonicalize: ModuleType,
) -> None:
    assert canonicalize.UNICODE_VERSION == "15.1.0"
    assert canonicalize.unicode_data.__name__ == "unicodedata2"
    assert canonicalize.IDNA_VERSION == "3.18"
    assert canonicalize.idna_core.unicodedata is unicodedata
    assert canonicalize.canonical_json({"\U00010000": 2, "\ue000": 1}) == (
        '{"\ue000":1,"\U00010000":2}'.encode()
    )


def test_unicode_15_1_unassigned_code_points_fail_closed(
    canonicalize: ModuleType,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonical_json({"future": "\U0001cc00"})

    assert _error_code(captured) == "unassigned_unicode"


def test_json_parser_rejects_duplicate_keys_after_nfc(
    canonicalize: ModuleType,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as direct:
        canonicalize.parse_json('{"scope":1,"scope":2}')
    with pytest.raises(canonicalize.CanonicalizationError) as equivalent:
        canonicalize.parse_json('{"e\\u0301":1,"\\u00e9":2}')

    assert _error_code(direct) == "duplicate_key"
    assert _error_code(equivalent) == "duplicate_key"


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("1.2300", b"1.23"),
        ("1e3", b"1000"),
        ("-0.000", b"0"),
        ("1e-3", b"0.001"),
        ("9007199254740991", b"9007199254740991"),
    ),
)
def test_exact_json_numbers_have_a_portable_decimal_form(
    canonicalize: ModuleType,
    source: str,
    expected: bytes,
) -> None:
    assert canonicalize.canonical_json(canonicalize.parse_json(source)) == expected


@pytest.mark.parametrize(
    ("value", "code"),
    (
        (0.1, "binary_float"),
        (Decimal("NaN"), "non_finite_number"),
        (Decimal("1e309"), "number_out_of_range"),
        (Decimal("1e-309"), "number_out_of_range"),
    ),
)
def test_ambiguous_or_nonportable_numbers_fail_closed(
    canonicalize: ModuleType,
    value: object,
    code: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonical_json(value)
    assert _error_code(captured) == code


@pytest.mark.parametrize(
    ("source", "code"),
    (
        ('"' + ("x" * 8193) + '"', "string_too_large"),
        ("[" * 33 + "0" + "]" * 33, "nesting_too_deep"),
        ("[" + ",".join("0" for _ in range(1025)) + "]", "too_many_array_items"),
        (
            "{" + ",".join(f'"k{i}":0' for i in range(257)) + "}",
            "too_many_object_keys",
        ),
        ("1." + ("2" * 128), "number_too_precise"),
        ("1e999999999999999999999999999999999999", "number_out_of_range"),
    ),
)
def test_portable_canonical_input_limits_fail_with_stable_errors(
    canonicalize: ModuleType,
    source: str,
    code: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.parse_json(source)
    assert _error_code(captured) == code


def test_total_input_limit_is_checked_before_json_recursion(
    canonicalize: ModuleType,
) -> None:
    source = b'{"value":"' + (b"x" * 65536) + b'"}'
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.parse_json(source)
    assert _error_code(captured) == "input_too_large"

    deeply_nested = "[" * 2000 + "0" + "]" * 2000
    with pytest.raises(canonicalize.CanonicalizationError) as deep:
        canonicalize.parse_json(deeply_nested)
    assert _error_code(deep) == "nesting_too_deep"


def test_native_cycles_fail_with_a_stable_error(
    canonicalize: ModuleType,
) -> None:
    value: list[Any] = []
    value.append(value)
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonical_json(value)
    assert _error_code(captured) == "cyclic_value"


def test_shared_dag_expansion_fails_at_existing_output_limit(
    canonicalize: ModuleType,
) -> None:
    shared: Any = {"leaf": "value"}
    for _ in range(13):
        shared = [shared, shared]

    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonical_json(shared)

    assert _error_code(captured) == "input_too_large"


def test_caller_mapping_is_traversed_once(
    canonicalize: ModuleType,
) -> None:
    class Changing(dict[str, Any]):
        calls = 0

        def items(self) -> Any:
            self.calls += 1
            if self.calls > 1:
                raise AssertionError("caller mapping was re-read")
            return super().items()

    value = Changing({"key": ["stable"]})
    assert canonicalize.canonical_json(value) == b'{"key":["stable"]}'
    assert value.calls == 1


def test_unbounded_mapping_stops_at_per_object_limit(
    canonicalize: ModuleType,
) -> None:
    class Unbounded(Mapping[str, Any]):
        yielded = 0

        def __getitem__(self, key: str) -> Any:
            raise AssertionError("snapshot must consume items directly")

        def __iter__(self) -> Any:
            raise AssertionError("snapshot must consume items directly")

        def __len__(self) -> int:
            raise AssertionError("snapshot must not trust caller length")

        def items(self) -> Any:
            index = 0
            while True:
                self.yielded += 1
                yield f"k{index}", index
                index += 1

    value = Unbounded()
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonical_json(value)
    assert _error_code(captured) == "too_many_object_keys"
    assert value.yielded == canonicalize.MAX_OBJECT_KEYS + 1


def test_absent_object_values_are_omitted_but_null_is_preserved(
    canonicalize: ModuleType,
) -> None:
    absent = canonicalize.canonical_json(
        {"required": "value", "optional": canonicalize.ABSENT}
    )
    explicit_null = canonicalize.canonical_json({"required": "value", "optional": None})

    assert absent == b'{"required":"value"}'
    assert explicit_null == b'{"optional":null,"required":"value"}'
    assert canonicalize.canonical_hash(absent) != canonicalize.canonical_hash(
        explicit_null
    )
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonical_json([canonicalize.ABSENT])
    assert _error_code(captured) == "absent_array_value"


@pytest.mark.parametrize(
    ("path", "cwd", "expected"),
    (
        (
            "src/../deploy/./production.yaml",
            "/workspace/project",
            "/workspace/project/deploy/production.yaml",
        ),
        ("../../shared/policy.rego", "/workspace/project", "/shared/policy.rego"),
        ("/workspace/link/../secret.txt", "/ignored", "/workspace/secret.txt"),
        ("Cafe\u0301.txt", "/workspace", "/workspace/Café.txt"),
    ),
)
def test_paths_are_absolute_nfc_and_lexically_cleaned_without_io(
    canonicalize: ModuleType,
    path: str,
    cwd: str,
    expected: str,
) -> None:
    assert canonicalize.canonicalize_path(path, cwd=cwd) == expected


def test_prepared_resources_bind_execution_to_the_canonical_value(
    canonicalize: ModuleType,
) -> None:
    path = canonicalize.prepare_path_resource(
        "Cafe\u0301/../re\u0301sume\u0301.txt",
        cwd="/workspace",
    )
    url = canonicalize.prepare_url_resource(
        "HTTPS://EXAMPLE.COM/Cafe%CC%81?q=re%CC%81sume%CC%81"
    )
    shell = canonicalize.prepare_shell_resource("printf 'Cafe\u0301'")
    mcp = canonicalize.prepare_mcp_resource(
        "github",
        "issues.create",
        {"title": "Cafe\u0301"},
    )

    assert path.execution == "/workspace/résumé.txt"
    assert path.resource == "path:/workspace/résumé.txt"
    assert url.execution == "https://example.com/Caf%C3%A9?q=r%C3%A9sum%C3%A9"
    assert canonicalize.parse_json(url.resource)["url"] == url.execution
    assert shell.execution == "printf 'Café'"
    assert "Cafe\u0301" not in shell.resource
    assert mcp.execution == {
        "server": "github",
        "tool": "issues.create",
        "input": {"title": "Café"},
    }
    assert mcp.resource.startswith("mcp:github/issues.create#sha256:")


def test_prepared_url_executes_normalized_secrets_while_resource_redacts_them(
    canonicalize: ModuleType,
) -> None:
    prepared = canonicalize.prepare_url_resource(
        "HTTPS://EXAMPLE.COM:443/a/../b?token=synthetic-secret&q=Cafe%CC%81"
    )

    assert prepared.execution == (
        "https://example.com/b?q=Caf%C3%A9&token=synthetic-secret"
    )
    assert canonicalize.parse_json(prepared.resource)["url"] == (
        "https://example.com/b?q=Caf%C3%A9&token=%5BREDACTED%5D"
    )


@pytest.mark.parametrize(
    ("path", "cwd", "code"),
    (
        ("file.txt", "relative/cwd", "cwd_not_absolute"),
        ("bad\x00name", "/workspace", "invalid_path"),
        ("C:\\workspace\\file.txt", "/workspace", "unsupported_path_syntax"),
    ),
)
def test_ambiguous_path_inputs_fail_closed(
    canonicalize: ModuleType,
    path: str,
    cwd: str,
    code: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_path(path, cwd=cwd)
    assert _error_code(captured) == code


def test_path_canonicalization_never_reads_or_resolves_the_filesystem(
    canonicalize: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("canonicalization must not inspect the filesystem")

    for attribute in ("exists", "is_symlink", "resolve", "stat"):
        monkeypatch.setattr(Path, attribute, forbidden)

    assert (
        canonicalize.canonicalize_path(
            "../symlink/../target",
            cwd="/workspace/project",
        )
        == "/workspace/target"
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "HTTPS://Example.COM:443/a/../b?z=last&token=secret&a=2&a=1#fragment",
            "https://example.com/b?a=2&a=1&token=%5BREDACTED%5D&z=last",
        ),
        (
            "http://EXAMPLE.com:80/%7euser/%2e%2e/api?q=Cafe%CC%81",
            "http://example.com/api?q=Caf%C3%A9",
        ),
        (
            "https://example.com?empty=&B=2&a=1",
            "https://example.com/?B=2&a=1&empty=",
        ),
    ),
)
def test_urls_apply_the_normative_authorization_normalization_policy(
    canonicalize: ModuleType,
    source: str,
    expected: str,
) -> None:
    assert canonicalize.canonicalize_url(source) == expected


@pytest.mark.parametrize(
    ("source", "code"),
    (
        ("https://user:secret@example.com/", "url_userinfo"),
        ("https://example.com./", "noncanonical_url_host"),
        ("https://bad_host.example/", "invalid_url_host"),
        ("https://bad..example/", "invalid_url_host"),
        ("https://%65xample.com/", "invalid_url_host"),
        ("https://127.1/", "ambiguous_numeric_host"),
        ("https://2130706433/", "ambiguous_numeric_host"),
        ("https://0177.0.0.1/", "ambiguous_numeric_host"),
        ("https://[2001:db8::1]/", "unsupported_ipv6"),
        ("https:\\\\example.com\\path", "invalid_url"),
        ("https://example.com:0443/", "noncanonical_url_port"),
        ("https://example.com/\x01", "invalid_url"),
    ),
)
def test_url_authority_and_ambiguous_syntax_fail_closed(
    canonicalize: ModuleType,
    source: str,
    code: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_url(source)
    assert _error_code(captured) == code


def test_url_paths_preserve_empty_and_encoded_reserved_segments(
    canonicalize: ModuleType,
) -> None:
    empty_segment = canonicalize.canonicalize_url("https://example.com/a//b")
    collapsed = canonicalize.canonicalize_url("https://example.com/a/b")
    encoded_slash = canonicalize.canonicalize_url("https://example.com/a%2fb")
    path_slash = canonicalize.canonicalize_url("https://example.com/a/b")
    dotted = canonicalize.canonicalize_url("https://example.com/a//./c/../b")

    assert empty_segment == "https://example.com/a//b"
    assert empty_segment != collapsed
    assert encoded_slash == "https://example.com/a%2Fb"
    assert encoded_slash != path_slash
    assert dotted == "https://example.com/a//b"


@pytest.mark.parametrize(
    ("source", "code"),
    (
        ("ftp://example.com/file", "unsupported_url_scheme"),
        ("https:///missing-host", "missing_url_host"),
        ("https://example.com/%zz", "invalid_percent_encoding"),
        ("https://example.com:99999/", "invalid_url_port"),
        ("https://café.example/", "unsupported_url_host"),
    ),
)
def test_unsupported_or_ambiguous_urls_fail_closed(
    canonicalize: ModuleType,
    source: str,
    code: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_url(source)
    assert _error_code(captured) == code


def test_url_host_accepts_valid_a_labels_and_rejects_malformed_punycode(
    canonicalize: ModuleType,
) -> None:
    assert canonicalize.canonicalize_url("https://XN--BCHER-KVA.example/") == (
        "https://xn--bcher-kva.example/"
    )

    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_url("https://xn--.example/")

    assert _error_code(captured) == "invalid_url_host"


def test_idna_validation_uses_pinned_unicode_15_1_bidi_data(
    canonicalize: ModuleType,
) -> None:
    assert canonicalize.canonicalize_url("https://xn--8g0n.example/") == (
        "https://xn--8g0n.example/"
    )


@pytest.mark.parametrize(
    "host",
    (
        "xn--a.example",
        "xn--0.example",
        "xn--a-ecp.example",
        "xn--1ug.example",
    ),
)
def test_idna2008_rejects_invalid_contextual_or_bidi_a_labels(
    canonicalize: ModuleType,
    host: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_url(f"https://{host}/")

    assert _error_code(captured) == "invalid_url_host"


def test_repeated_query_values_keep_their_relative_order(
    canonicalize: ModuleType,
) -> None:
    left = canonicalize.canonicalize_url("https://example.com/?a=2&a=1&b=3")
    reordered_keys = canonicalize.canonicalize_url("https://example.com/?b=3&a=2&a=1")
    reordered_values = canonicalize.canonicalize_url("https://example.com/?a=1&a=2&b=3")

    assert left == reordered_keys
    assert left != reordered_values


def test_url_redaction_additions_cannot_remove_protocol_defaults(
    canonicalize: ModuleType,
) -> None:
    result = canonicalize.canonicalize_url(
        "https://example.com/?token=synthetic-token&private=synthetic-private",
        sensitive_query_keys=frozenset({"private"}),
    )

    assert result == (
        "https://example.com/?private=%5BREDACTED%5D&token=%5BREDACTED%5D"
    )


def test_shell_redaction_preserves_scope_without_exposing_known_secrets(
    canonicalize: ModuleType,
) -> None:
    first = canonicalize.canonicalize_shell(
        "curl --token hunter2 -H 'Authorization: Bearer abc' "
        "TOKEN=xyz https://example.com"
    )
    second = canonicalize.canonicalize_shell(
        "curl --token different -H 'Authorization: Bearer def' "
        "TOKEN=uvw https://example.com"
    )

    serialized = canonicalize.canonical_json(first).decode()
    assert "hunter2" not in serialized
    assert "Bearer abc" not in serialized
    assert "TOKEN=xyz" not in serialized
    assert first["tokens"] == second["tokens"]
    assert first["commandHash"] != second["commandHash"]
    assert canonicalize.canonical_hash(first) != canonicalize.canonical_hash(second)
    assert first["commandHash"].startswith("sha256:")


def test_shell_parse_failure_still_binds_the_unredacted_command(
    canonicalize: ModuleType,
) -> None:
    result = canonicalize.canonicalize_shell("echo 'unterminated secret")

    assert result["tokens"] == ["[UNPARSEABLE]"]
    assert result["commandHash"].startswith("sha256:")
    assert "secret" not in canonicalize.canonical_json(result).decode()


def test_shell_redaction_handles_inline_headers_and_case_insensitive_urls(
    canonicalize: ModuleType,
) -> None:
    result = canonicalize.canonicalize_shell(
        "curl '--header=Authorization: Bearer synthetic-secret' "
        "HTTPS://EXAMPLE.COM/path?token=synthetic-token"
    )
    serialized = canonicalize.canonical_json(result).decode()

    assert "synthetic-secret" not in serialized
    assert "synthetic-token" not in serialized
    assert "--header=[REDACTED]" in result["tokens"]
    assert "https://example.com/path?token=%5BREDACTED%5D" in result["tokens"]


def test_shell_additional_sensitive_names_extend_mandatory_defaults(
    canonicalize: ModuleType,
) -> None:
    first = canonicalize.canonicalize_shell(
        "deploy --tenant-secret alpha TENANT_SECRET=bravo "
        "--tenant-secret=charlie --token mandatory",
        additional_sensitive_names={"tenant_secret", "tenant-secret"},
    )
    second = canonicalize.canonicalize_shell(
        "deploy --tenant-secret delta TENANT_SECRET=echo "
        "--tenant-secret=foxtrot --token changed",
        additional_sensitive_names={"TENANT_SECRET"},
    )

    serialized = canonicalize.canonical_json(first).decode()
    for secret in ("alpha", "bravo", "charlie", "mandatory"):
        assert secret not in serialized
    assert first["tokens"] == second["tokens"]
    assert first["commandHash"] != second["commandHash"]


def test_shell_additional_sensitive_names_redact_url_query_keys(
    canonicalize: ModuleType,
) -> None:
    first = canonicalize.canonicalize_shell(
        "curl 'https://example.com/run?Tenant_Secret=alpha&token=mandatory'",
        additional_sensitive_names={"tenant-secret"},
    )
    second = canonicalize.canonicalize_shell(
        "curl 'https://example.com/run?Tenant_Secret=bravo&token=changed'",
        additional_sensitive_names={"TENANT_SECRET"},
    )

    assert first["tokens"] == second["tokens"]
    assert first["commandHash"] != second["commandHash"]
    serialized = canonicalize.canonical_json(first).decode()
    assert "alpha" not in serialized
    assert "mandatory" not in serialized


def test_prepared_url_resource_binds_redacted_credentials_without_exposing_them(
    canonicalize: ModuleType,
) -> None:
    first = canonicalize.prepare_url_resource(
        "https://example.com/run?token=synthetic-alpha"
    )
    second = canonicalize.prepare_url_resource(
        "https://example.com/run?token=synthetic-bravo"
    )

    first_resource = canonicalize.parse_json(first.resource)
    second_resource = canonicalize.parse_json(second.resource)
    assert first_resource["url"] == ("https://example.com/run?token=%5BREDACTED%5D")
    assert first_resource["executionHash"] != second_resource["executionHash"]
    assert first.resource != second.resource
    assert "synthetic-alpha" not in first.resource
    assert first.execution.endswith("token=synthetic-alpha")

    first_target = canonicalize.build_target(
        kind="url",
        service="example",
        prepared=first,
    )
    second_target = canonicalize.build_target(
        kind="url",
        service="example",
        prepared=second,
    )
    assert first_target["resourceHash"] != second_target["resourceHash"]


@pytest.mark.parametrize(
    "name",
    ("", "bad name", "token=value", "\x00secret", "ＴＯＫＥＮ"),
)
def test_invalid_additional_sensitive_names_fail_closed(
    canonicalize: ModuleType,
    name: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_shell(
            "echo safe",
            additional_sensitive_names={name},
        )
    assert _error_code(captured) == "invalid_sensitive_name"


def test_mcp_resource_uses_server_qualified_tool_and_nested_canonical_json(
    canonicalize: ModuleType,
) -> None:
    left = canonicalize.canonicalize_mcp(
        "github",
        "issues.create",
        {"labels": ["security", "agent"], "issue": {"title": "Cafe\u0301", "n": 1}},
    )
    right = canonicalize.canonicalize_mcp(
        "github",
        "issues.create",
        {
            "issue": {"n": Decimal("1.0"), "title": "Café"},
            "labels": ["security", "agent"],
        },
    )

    assert left == right
    assert left.startswith("mcp:github/issues.create#sha256:")
    assert len(left.rsplit(":", 1)[1]) == 64


@pytest.mark.parametrize(
    ("server", "tool"),
    (("github/other", "issues.create"), ("github", "../issues"), ("", "tool")),
)
def test_mcp_qualified_names_cannot_be_ambiguous(
    canonicalize: ModuleType,
    server: str,
    tool: str,
) -> None:
    with pytest.raises(canonicalize.CanonicalizationError) as captured:
        canonicalize.canonicalize_mcp(server, tool, {})
    assert _error_code(captured) == "invalid_mcp_name"


def _action() -> dict[str, Any]:
    canonicalize = importlib.import_module(REFERENCE_MODULE)
    prepared = canonicalize.prepare_path_resource(
        "deploy/production.yaml",
        cwd="/workspace",
    )
    return {
        "schemaVersion": "1",
        "actionId": "act_not_hashed",
        "requestId": "req_not_hashed",
        "correlationId": "corr_not_hashed",
        "idempotencyKey": "authz_not_hashed",
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
        "target": canonicalize.build_target(
            kind="local-action",
            service="workspace",
            prepared=prepared,
        ),
        "sideEffect": "write",
        "occurredAt": "2026-07-25T20:00:00Z",
        "context": {"toolName": "apply_patch"},
    }


def _trusted() -> dict[str, str]:
    return {
        "tenantId": "tenant_example",
        "actorId": "subject_example",
        "agentId": "agent_example",
        "delegationId": "delegation_example",
        "clientId": "registered-codex",
    }


def test_client_scope_input_is_explicit_and_contains_only_client_visible_scope(
    canonicalize: ModuleType,
) -> None:
    scope = canonicalize.client_scope_input(_action())

    assert scope == {
        "scopeType": "client",
        "scopeVersion": "1",
        "adapter": {"id": "codex", "version": "0.2.0-alpha.1"},
        "task": {
            "taskId": "task_01J5ABCDEFGHJKMNPQRSTVWXY0",
            "sessionId": "session_01J5ABCDEFGHJKMNPQRSTVWXY0",
        },
        "action": "file:write",
        "target": {
            "kind": "local-action",
            "service": "workspace",
            "resourceHash": _action()["target"]["resourceHash"],
        },
        "sideEffect": "write",
    }
    assert "hostVersion" not in canonicalize.canonical_json(scope).decode()
    assert "clientId" not in canonicalize.canonical_json(scope).decode()


def test_resource_hash_uses_a_typed_versioned_preimage(
    canonicalize: ModuleType,
) -> None:
    target = _action()["target"]
    preimage = canonicalize.resource_hash_input(target)

    assert preimage == {
        "preimageType": "palonexus.resource",
        "preimageVersion": "1",
        "kind": "local-action",
        "service": "workspace",
        "resource": "path:/workspace/deploy/production.yaml",
    }
    assert target["resourceHash"] == canonicalize.canonical_hash(preimage)
    assert canonicalize.validated_target(target) == target


def test_valid_action_vectors_bind_their_canonical_resource(
    canonicalize: ModuleType,
) -> None:
    vectors = sorted((ROOT / "test-vectors" / "action" / "valid").glob("*.json"))
    assert vectors

    for path in vectors:
        action = json.loads(path.read_text(encoding="utf-8"))
        assert canonicalize.validated_target(action["target"]) == action["target"], path


def test_scope_hashing_rejects_a_supplied_resource_hash_mismatch(
    canonicalize: ModuleType,
) -> None:
    action = _action()
    action["target"]["resource"] = "path:/workspace/other.yaml"

    with pytest.raises(canonicalize.CanonicalizationError) as client:
        canonicalize.client_scope_hash(action)
    with pytest.raises(canonicalize.CanonicalizationError) as authoritative:
        canonicalize.authoritative_scope_hash(action, _trusted())

    assert _error_code(client) == "resource_hash_mismatch"
    assert _error_code(authoritative) == "resource_hash_mismatch"


def test_adapter_is_diagnostic_but_bound_into_the_client_hash(
    canonicalize: ModuleType,
) -> None:
    action = _action()
    original = canonicalize.client_scope_hash(action)
    action["adapter"]["id"] = "claude-code"

    assert canonicalize.client_scope_hash(action) != original


def test_request_attempt_and_diagnostic_context_do_not_change_scope_hash(
    canonicalize: ModuleType,
) -> None:
    action = _action()
    original = canonicalize.client_scope_hash(action)
    action.update(
        {
            "actionId": "act_changed",
            "requestId": "req_changed",
            "correlationId": "corr_changed",
            "idempotencyKey": "authz_changed",
            "occurredAt": "2026-07-25T21:00:00Z",
            "context": {"safeDisplay": "changed"},
        }
    )
    action["adapter"]["hostVersion"] = "0.146.0"

    assert canonicalize.client_scope_hash(action) == original


def test_authoritative_scope_input_adds_only_trusted_identity(
    canonicalize: ModuleType,
) -> None:
    scope = canonicalize.authoritative_scope_input(_action(), _trusted())

    assert scope == {
        "scopeType": "authoritative",
        "scopeVersion": "1",
        "clientScope": canonicalize.client_scope_input(_action()),
        "trusted": _trusted(),
    }
    assert scope["trusted"]["clientId"] == "registered-codex"
    assert scope["clientScope"]["adapter"]["id"] == "codex"


def test_trusted_client_id_changes_only_the_authoritative_hash(
    canonicalize: ModuleType,
) -> None:
    action = _action()
    trusted = _trusted()
    client_hash = canonicalize.client_scope_hash(action)
    first = canonicalize.authoritative_scope_hash(action, trusted)
    trusted["clientId"] = "registered-claude"

    assert canonicalize.client_scope_hash(action) == client_hash
    assert canonicalize.authoritative_scope_hash(action, trusted) != first


def test_caller_cannot_smuggle_trusted_identity_into_scope(
    canonicalize: ModuleType,
) -> None:
    action = _action()
    original_client = canonicalize.client_scope_hash(action)
    original_authoritative = canonicalize.authoritative_scope_hash(action, _trusted())
    action["clientId"] = "privileged"
    action["adapter"]["clientId"] = "privileged"
    action["context"]["tenantId"] = "other"

    assert canonicalize.client_scope_hash(action) == original_client
    assert (
        canonicalize.authoritative_scope_hash(action, _trusted())
        == original_authoritative
    )


@pytest.mark.parametrize("missing", ("tenantId", "actorId", "clientId"))
def test_required_authoritative_identity_cannot_be_missing_or_null(
    canonicalize: ModuleType,
    missing: str,
) -> None:
    trusted: dict[str, Any] = _trusted()
    trusted.pop(missing)
    with pytest.raises(canonicalize.CanonicalizationError) as absent:
        canonicalize.authoritative_scope_input(_action(), trusted)
    trusted[missing] = None
    with pytest.raises(canonicalize.CanonicalizationError) as explicit_null:
        canonicalize.authoritative_scope_input(_action(), trusted)

    assert _error_code(absent) == "invalid_authoritative_scope"
    assert _error_code(explicit_null) == "invalid_authoritative_scope"


def test_optional_authoritative_values_are_omitted_not_null(
    canonicalize: ModuleType,
) -> None:
    trusted = _trusted()
    trusted.pop("agentId")
    trusted.pop("delegationId")

    scope = canonicalize.authoritative_scope_input(_action(), trusted)

    assert scope["trusted"] == {
        "tenantId": "tenant_example",
        "actorId": "subject_example",
        "clientId": "registered-codex",
    }


def test_committed_vectors_cover_every_adversarial_contract(
    canonicalize: ModuleType,
) -> None:
    expected_names = {
        "adapter-client-trust-boundary",
        "duplicate-keys",
        "idna2008-a-label",
        "mcp-nested-json",
        "missing-vs-null",
        "numeric-portability",
        "path-traversal-symlink-policy",
        "resource-preimage-binding",
        "shell-redaction-collision-resistance",
        "unicode-equivalence",
        "url-credential-binding",
        "url-normalization-policy",
    }
    vector_paths = sorted(VECTORS.glob("*.json"))

    assert {path.stem for path in vector_paths} == expected_names
    assert canonicalize.render_vectors() == {
        path.name: path.read_bytes() for path in vector_paths
    }
    for path in vector_paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        assert value["status"] == "draft-pending-gate-0"
        assert value["canonicalizationVersion"] == "1"
        assert canonicalize.verify_vector(value) == []


def test_vector_verifier_recomputes_and_rejects_tampering(
    canonicalize: ModuleType,
) -> None:
    vector = json.loads(
        (VECTORS / "adapter-client-trust-boundary.json").read_text(encoding="utf-8")
    )
    vector["inputs"]["adapterMutation"]["adapter"]["id"] = "tampered"

    errors = canonicalize.verify_vector(vector)

    assert errors
    assert any("changedAdapterClientScopeHash" in error for error in errors)


def test_vector_check_mode_detects_no_regeneration_drift() -> None:
    result = subprocess.run(
        [sys.executable, str(REFERENCE), "--check-vectors"],
        cwd=ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "canonicalization vectors are current" in result.stdout


def test_reference_cli_is_vector_only_and_has_no_transport_surface() -> None:
    text = REFERENCE.read_text(encoding="utf-8")

    assert "--write-vectors" in text
    assert "--check-vectors" in text
    for forbidden in ("httpx", "requests", "urllib.request", "socket", "/v1/decide"):
        assert forbidden not in text


def test_reference_and_package_are_distinct_synced_implementations() -> None:
    reference = importlib.import_module(REFERENCE_MODULE)
    package = importlib.import_module("palonexus._canonicalize")

    assert reference.main is not package.main
    assert reference.canonical_json is not package.canonical_json
    assert reference.__file__ != package.__file__
    assert reference.VECTORS == VECTORS
    for vector in VECTORS.glob("*.json"):
        payload = json.loads(vector.read_text())
        assert payload
