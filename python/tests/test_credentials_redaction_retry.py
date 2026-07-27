# SPDX-License-Identifier: MIT
"""Credential, diagnostic-redaction, and authorization-retry contracts."""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import inspect
import logging
import pickle
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from io import StringIO
from typing import Any

import pytest
from palonexus import (
    AsyncCredentialProvider,
    CompletionState,
    Credential,
    CredentialAcquisitionCancelled,
    CredentialUnavailable,
    InvalidCredentialDeadline,
    Redactor,
    RetryFailure,
    RetryPolicy,
    RetryPolicyError,
    RetryReason,
    SyncCredentialProvider,
)
from palonexus.credentials import acquire_credential, acquire_credential_async

TOKEN = "synthetic_TEST_9fG2kP7mQ4vX8zL1"
OTHER_TOKEN = "synthetic_OTHER_3mN8rT6wY2pK5jH9"
IDEMPOTENCY_KEY = "authz_01J5ABCDEFGHJKMNPQRSTVWXY0"


class _SyncProvider:
    def __init__(
        self,
        result: Credential | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[float | None, Callable[[], bool] | None]] = []

    def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Credential | None:
        self.calls.append((deadline, cancelled))
        if self.error is not None:
            raise self.error
        return self.result


class _AsyncProvider:
    def __init__(
        self,
        result: Credential | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls = 0

    async def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Credential | None:
        del deadline, cancelled
        self.calls += 1
        await asyncio.sleep(0)
        if self.error is not None:
            raise self.error
        return self.result


def _credential(
    *,
    token: str = TOKEN,
    expires_at: datetime | None = None,
) -> Credential:
    return Credential(
        token,
        expires_at=expires_at or datetime.now(UTC) + timedelta(minutes=5),
    )


def _testing_policy(
    random_value: float,
    **overrides: Any,
) -> RetryPolicy:
    values: dict[str, Any] = {
        "max_attempts": 4,
        "max_elapsed": 30.0,
        "initial_delay": 1.0,
        "max_delay": 8.0,
        "multiplier": 2.0,
        "jitter_fraction": 0.25,
        "max_retry_after": 10.0,
    }
    values.update(overrides)
    return RetryPolicy._for_testing(  # noqa: SLF001 - test-only injection contract
        random_source=lambda: random_value,
        **values,
    )


def test_credential_provider_contracts_cover_sync_and_async_acquisition() -> None:
    sync = _SyncProvider(_credential())
    asynchronous = _AsyncProvider(_credential())

    with pytest.raises(TypeError):
        isinstance(sync, SyncCredentialProvider)
    with pytest.raises(TypeError):
        isinstance(asynchronous, AsyncCredentialProvider)
    assert "fallback" not in inspect.signature(acquire_credential).parameters
    assert "fallback" not in inspect.signature(acquire_credential_async).parameters
    assert "now" not in inspect.signature(acquire_credential).parameters
    assert "now" not in inspect.signature(acquire_credential_async).parameters
    assert "now" not in inspect.signature(Credential.authorization_header).parameters
    assert "monotonic_now" not in inspect.signature(acquire_credential).parameters


def test_sync_credential_acquisition_returns_only_a_current_bearer_header() -> None:
    credential = _credential()
    provider = _SyncProvider(credential)

    acquired = acquire_credential(
        provider,
        deadline=None,
        cancelled=lambda: False,
    )

    assert acquired is credential
    assert acquired.authorization_header() == f"Bearer {TOKEN}"
    assert provider.calls == [(None, provider.calls[0][1])]


@pytest.mark.parametrize(
    "provider",
    (
        _SyncProvider(None),
        _SyncProvider(error=RuntimeError(f"provider failed with {TOKEN}")),
    ),
)
def test_sync_credential_acquisition_fails_closed_without_secret_retention(
    provider: _SyncProvider,
) -> None:
    with pytest.raises(CredentialUnavailable) as caught:
        acquire_credential(provider)

    assert TOKEN not in str(caught.value)
    assert TOKEN not in repr(caught.value)
    assert caught.value.__cause__ is None


def test_expired_credential_and_acquisition_deadline_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired = _credential(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    with pytest.raises(CredentialUnavailable):
        acquire_credential(_SyncProvider(expired))
    assert expired.closed
    with pytest.raises(Exception, match="authentication_failed"):
        expired.authorization_header()
    monkeypatch.setattr("palonexus.credentials._monotonic_now", lambda: 5.0)
    with pytest.raises(CredentialAcquisitionCancelled) as caught:
        acquire_credential(
            _SyncProvider(_credential()),
            deadline=5.0,
        )
    assert caught.value.code == "credential_acquisition_cancelled"


@pytest.mark.parametrize(
    "deadline",
    (
        True,
        float("nan"),
        float("inf"),
        Decimal("1e999999"),
        "tomorrow",
    ),
)
def test_invalid_deadlines_fail_before_provider_invocation(deadline: object) -> None:
    provider = _SyncProvider(_credential())

    with pytest.raises(InvalidCredentialDeadline) as caught:
        acquire_credential(provider, deadline=deadline)  # type: ignore[arg-type]

    assert caught.value.code == "invalid_deadline"
    assert provider.calls == []


def test_deadline_is_converted_once_and_secret_conversion_failures_are_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StatefulDeadline:
        calls = 0

        def __float__(self) -> float:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(TOKEN)
            return 2.0

        def __repr__(self) -> str:
            return TOKEN

    class HostileDeadline:
        def __float__(self) -> float:
            raise RuntimeError(TOKEN)

        def __repr__(self) -> str:
            return TOKEN

    monkeypatch.setattr("palonexus.credentials._monotonic_now", lambda: 1.0)
    stateful = StatefulDeadline()
    provider = _SyncProvider(_credential())
    assert (
        acquire_credential(
            provider,
            deadline=stateful,  # type: ignore[arg-type]
        )
        is provider.result
    )
    assert stateful.calls == 1

    failed_provider = _SyncProvider(_credential())
    with pytest.raises(InvalidCredentialDeadline) as caught:
        acquire_credential(
            failed_provider,
            deadline=HostileDeadline(),  # type: ignore[arg-type]
        )
    assert TOKEN not in _captured_traceback(caught.value)
    assert failed_provider.calls == []


def test_credential_acquisition_honors_cancellation_before_and_after_provider() -> None:
    pre_cancelled = _SyncProvider(_credential())
    with pytest.raises(CredentialAcquisitionCancelled):
        acquire_credential(pre_cancelled, cancelled=lambda: True)
    assert pre_cancelled.calls == []

    checks = iter((False, True))
    post_cancelled = _SyncProvider(_credential())
    with pytest.raises(CredentialAcquisitionCancelled):
        acquire_credential(post_cancelled, cancelled=lambda: next(checks))
    assert len(post_cancelled.calls) == 1
    assert post_cancelled.result is not None
    assert post_cancelled.result.closed


def test_credential_does_not_render_pickle_copy_or_retain_after_close() -> None:
    credential = _credential()
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("palonexus-credential-test")
    logger.handlers = [handler]
    logger.propagate = False
    logger.warning("credential=%s", credential)

    rendered = " ".join((str(credential), repr(credential), stream.getvalue()))
    assert TOKEN not in rendered
    assert "redacted" in rendered.lower()
    assert not hasattr(credential, "token")
    with pytest.raises(TypeError):
        pickle.dumps(credential)
    with pytest.raises(TypeError):
        copy.copy(credential)
    with pytest.raises(TypeError):
        copy.deepcopy(credential)
    credential.close()
    with pytest.raises(Exception, match="authentication_failed"):
        credential.authorization_header()


@pytest.mark.parametrize(
    "token",
    (
        "",
        "contains space",
        "line\nbreak",
        "snowman-\N{SNOWMAN}",
        "x" * 8193,
    ),
)
def test_invalid_bearer_tokens_fail_with_a_stable_secret_free_error(token: str) -> None:
    with pytest.raises(Exception) as caught:
        Credential(token, expires_at=datetime.now(UTC) + timedelta(minutes=1))

    assert type(caught.value).__name__ == "AuthenticationFailed"
    if token:
        assert token not in str(caught.value)
    assert caught.value.__cause__ is None


def _captured_traceback(error: BaseException) -> str:
    captured = traceback.TracebackException.from_exception(
        error,
        capture_locals=True,
    )
    official = [
        frame
        for frame in captured.stack
        if frame.filename.endswith("/palonexus/credentials.py")
    ]
    return repr([(frame.name, frame.locals) for frame in official])


def test_credential_failures_never_retain_secrets_in_captured_traceback() -> None:
    class LeakyProvider:
        def __repr__(self) -> str:
            return f"LeakyProvider({TOKEN})"

        def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            local_secret = TOKEN
            raise RuntimeError(local_secret)

    class LeakyResult:
        def __repr__(self) -> str:
            return f"LeakyResult({OTHER_TOKEN})"

    for provider in (LeakyProvider(), _SyncProvider(LeakyResult())):  # type: ignore[arg-type]
        with pytest.raises(CredentialUnavailable) as caught:
            acquire_credential(provider)  # type: ignore[arg-type]
        rendered = _captured_traceback(caught.value)
        assert TOKEN not in rendered
        assert OTHER_TOKEN not in rendered
        assert caught.value.__cause__ is None

    with pytest.raises(Exception) as caught:
        Credential(
            f"{TOKEN}\n",
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )
    assert TOKEN not in _captured_traceback(caught.value)


def test_expiry_and_cancellation_tracebacks_keep_official_frames_secret_free() -> None:
    expired = _credential(
        token=OTHER_TOKEN,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    with pytest.raises(CredentialUnavailable) as expired_error:
        acquire_credential(_SyncProvider(expired))
    assert OTHER_TOKEN not in _captured_traceback(expired_error.value)
    assert expired.closed

    class SecretCancellation:
        def __repr__(self) -> str:
            return TOKEN

        def __call__(self) -> bool:
            return True

    with pytest.raises(CredentialAcquisitionCancelled) as cancelled_error:
        acquire_credential(
            _SyncProvider(_credential()),
            cancelled=SecretCancellation(),
        )
    assert TOKEN not in _captured_traceback(cancelled_error.value)


def test_hostile_credential_value_subclasses_cannot_escape_safe_errors() -> None:
    class HostileToken(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            del args, kwargs
            raise RuntimeError(TOKEN)

    class HostileDateTime(datetime):
        def astimezone(self, tz: object | None = None) -> datetime:
            del tz
            raise RuntimeError(OTHER_TOKEN)

    values = (
        (HostileToken("apparently-valid-token"), datetime.now(UTC)),
        (TOKEN, HostileDateTime.now(UTC)),
    )
    for token, expires_at in values:
        with pytest.raises(Exception) as caught:
            Credential(token, expires_at=expires_at)
        assert type(caught.value).__name__ == "AuthenticationFailed"
        assert TOKEN not in str(caught.value)
        assert OTHER_TOKEN not in str(caught.value)
        assert caught.value.__cause__ is None


def test_async_acquisition_has_parity_and_sanitizes_provider_errors() -> None:
    async def scenario() -> None:
        credential = _credential()
        assert await acquire_credential_async(_AsyncProvider(credential)) is credential

        provider = _AsyncProvider(
            error=RuntimeError(f"provider failed with {OTHER_TOKEN}")
        )
        with pytest.raises(CredentialUnavailable) as caught:
            await acquire_credential_async(provider)
        assert OTHER_TOKEN not in str(caught.value)
        assert OTHER_TOKEN not in _captured_traceback(caught.value)
        assert caught.value.__cause__ is None

    asyncio.run(scenario())


def test_async_task_cancellation_is_not_converted_or_suppressed() -> None:
    class BlockingProvider:
        async def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            await asyncio.Future()
            return None

    async def scenario() -> None:
        running = asyncio.create_task(acquire_credential_async(BlockingProvider()))
        await asyncio.sleep(0)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(scenario())


def test_async_provider_cannot_suppress_outer_cancellation_and_return_secret() -> None:
    returned = _credential()
    entered: asyncio.Event
    release: asyncio.Event

    class SuppressingProvider:
        async def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await release.wait()
                return returned

    async def scenario() -> None:
        nonlocal entered
        nonlocal release
        entered = asyncio.Event()
        release = asyncio.Event()
        running = asyncio.create_task(acquire_credential_async(SuppressingProvider()))
        await entered.wait()
        running.cancel()
        with pytest.raises(asyncio.CancelledError) as cancelled_error:
            await asyncio.wait_for(running, timeout=0.1)
        assert TOKEN not in _captured_traceback(cancelled_error.value)
        assert OTHER_TOKEN not in _captured_traceback(cancelled_error.value)
        assert not returned.closed
        release.set()
        for _ in range(10):
            if returned.closed:
                break
            await asyncio.sleep(0)
        assert returned.closed

    asyncio.run(scenario())


def test_sync_and_async_provider_shapes_fail_closed_without_coroutine_warning(
    recwarn: pytest.WarningsRecorder,
) -> None:
    class AsyncInSync:
        async def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            return _credential()

    class SyncInAsync:
        def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            return _credential()

    with pytest.raises(CredentialUnavailable):
        acquire_credential(AsyncInSync())  # type: ignore[arg-type]

    async def scenario() -> None:
        with pytest.raises(CredentialUnavailable):
            await acquire_credential_async(SyncInAsync())  # type: ignore[arg-type]

    asyncio.run(scenario())
    assert not recwarn


def test_provider_cancellation_exceptions_are_never_mapped_to_unavailable() -> None:
    class SyncCancelled:
        def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            raise concurrent.futures.CancelledError

    class AsyncCancelled:
        async def get_credential(
            self,
            *,
            deadline: float | None = None,
            cancelled: Callable[[], bool] | None = None,
        ) -> Credential | None:
            del deadline, cancelled
            raise asyncio.CancelledError

    with pytest.raises(concurrent.futures.CancelledError):
        acquire_credential(SyncCancelled())

    async def scenario() -> None:
        with pytest.raises(asyncio.CancelledError):
            await acquire_credential_async(AsyncCancelled())

    asyncio.run(scenario())


def test_redactor_applies_mandatory_and_deployment_sensitive_names() -> None:
    redactor = Redactor(additional_sensitive_names={"tenant_secret"})
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Cookie": f"session={OTHER_TOKEN}",
        "Tenant-Secret": OTHER_TOKEN,
        "X-Request-ID": "safe-request-id",
        "Status-Code": "200",
        "Postal-Code": "90210",
    }
    query = {
        "token": TOKEN,
        "tenant_secret": OTHER_TOKEN,
        "page": "2",
    }

    assert redactor.redact_headers(headers) == {
        "Authorization": "[REDACTED]",
        "Cookie": "[REDACTED]",
        "Tenant-Secret": "[REDACTED]",
        "X-Request-ID": "safe-request-id",
        "Status-Code": "200",
        "Postal-Code": "90210",
    }
    assert redactor.redact_query(query) == {
        "token": "[REDACTED]",
        "tenant_secret": "[REDACTED]",
        "page": "2",
    }
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert query["token"] == TOKEN


def test_nested_redaction_is_non_mutating_bounded_and_cycle_safe() -> None:
    secret_list: list[object] = [TOKEN]
    source: dict[str, object] = {
        "safe": {"value": "hello"},
        "password": "short-secret",
        "items": secret_list,
    }
    secret_list.append(source)
    redactor = Redactor(max_depth=3, max_items=4, max_string_length=32)

    result = redactor.redact(source)

    assert result == {
        "safe": {"value": "hello"},
        "password": "[REDACTED]",
        "items": ["[REDACTED]", "[CYCLE]"],
    }
    assert source["password"] == "short-secret"
    assert secret_list[1] is source

    too_deep = redactor.redact({"a": {"b": {"c": {"d": "value"}}}})
    assert too_deep == {"a": {"b": {"c": "[MAX_DEPTH]"}}}
    assert redactor.redact(list(range(20))) == [0, 1, 2, 3, "[TRUNCATED]"]


def test_url_redaction_removes_userinfo_fragment_and_sensitive_query_values() -> None:
    value = (
        f"https://user:{TOKEN}@Example.COM:443/run?"
        f"page=2&token={OTHER_TOKEN}&note=Bearer%20{TOKEN}#private"
    )

    rendered = Redactor().redact_url(value)

    assert rendered == (
        "https://example.com/run?"
        "note=Bearer%20%5BREDACTED%5D&page=2&token=%5BREDACTED%5D"
    )
    assert TOKEN not in rendered
    assert OTHER_TOKEN not in rendered
    assert "user" not in rendered
    assert "private" not in rendered


def test_sensitive_names_decode_bounded_obfuscation_and_match_exactly() -> None:
    redactor = Redactor(additional_sensitive_names={"tenant_secret"})
    query = {
        "to%256ben": TOKEN,
        "tenant%E2%80%8B_secret": OTHER_TOKEN,
        "status-code": "200",
        "postal-code": "90210",
        "x-token": "safe",
    }

    assert redactor.redact_query(query) == {
        "to%256ben": "[REDACTED]",
        "tenant%E2%80%8B_secret": "[REDACTED]",
        "status-code": "200",
        "postal-code": "90210",
        "x-token": "safe",
    }
    rendered = redactor.redact_url(
        f"https://example.test/?%2574oken={TOKEN}&status-code=200"
    )
    assert TOKEN not in rendered
    assert "%5BREDACTED%5D" in rendered
    assert redactor.redact_text("status-code=200 postal-code=90210") == (
        "status-code=200 postal-code=90210"
    )


@pytest.mark.parametrize(
    "value",
    (
        f"to%256ben='{TOKEN} with spaces'",
        f'to\u200bken="{TOKEN} with spaces"',
        f"x-api-key: {TOKEN}",
        f"x-access-token={TOKEN}",
        f"proxy-authorization: Basic {TOKEN}",
        f"set-cookie: session={TOKEN}",
    ),
)
def test_text_redaction_uses_structured_sensitive_name_rules(value: str) -> None:
    rendered = Redactor().redact_text(value)

    assert TOKEN not in rendered
    assert "[REDACTED]" in rendered


@pytest.mark.parametrize(
    "value",
    (
        "token\u200b=shortsecret",
        "token%253Dshortsecret",
        "to%E2%2580%258Bken%253Dshortsecret",
    ),
)
def test_text_redaction_detects_assignments_on_bounded_comparison_view(
    value: str,
) -> None:
    rendered = Redactor().redact_text(value)

    assert "shortsecret" not in rendered
    assert "[REDACTED]" in rendered


def test_shell_redaction_reuses_protocol_rules_and_covers_embedded_secrets() -> None:
    command = (
        f"deploy --tenant-secret {TOKEN} TENANT_SECRET={OTHER_TOKEN} "
        f"--token={TOKEN} -H 'Authorization: Bearer {OTHER_TOKEN}' "
        f"https://example.test/run?api_key={TOKEN}"
    )
    redactor = Redactor(additional_sensitive_names={"tenant_secret"})

    tokens = redactor.redact_shell(command)

    assert tokens == [
        "deploy",
        "--tenant-secret",
        "[REDACTED]",
        "TENANT_SECRET=[REDACTED]",
        "--token=[REDACTED]",
        "-H",
        "[REDACTED]",
        "https://example.test/run?api_key=%5BREDACTED%5D",
    ]
    assert TOKEN not in repr(tokens)
    assert OTHER_TOKEN not in repr(tokens)
    assert redactor.redact_shell("unterminated '") == ["[UNPARSEABLE]"]


def test_shell_redaction_applies_full_mandatory_set_to_low_entropy_values() -> None:
    tokens = Redactor().redact_shell(
        "deploy --access-token short ACCESS_TOKEN=tiny --client-secret brief"
    )

    assert tokens == [
        "deploy",
        "--access-token",
        "[REDACTED]",
        "ACCESS_TOKEN=[REDACTED]",
        "--client-secret",
        "[REDACTED]",
    ]


def test_shell_redaction_handles_encoded_names_and_quoted_multiword_values() -> None:
    tokens = Redactor().redact_shell(
        "deploy --to%256ben 'two word secret' "
        "TO%E2%80%8BKEN='another secret' --status-code 200"
    )

    assert tokens == [
        "deploy",
        "--to%256ben",
        "[REDACTED]",
        "TO%E2%80%8BKEN=[REDACTED]",
        "--status-code",
        "200",
    ]


@pytest.mark.parametrize(
    "value",
    (
        f"Authorization: Bearer {TOKEN}",
        f"token={TOKEN}",
        f"api-key: {TOKEN}",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.signature_123456789",
        TOKEN,
        "7f4a9c2e8b1d6a3f0c5e7b9d2a4f8c1e",
    ),
)
def test_text_redaction_covers_bearer_api_jwt_and_high_entropy_values(
    value: str,
) -> None:
    rendered = Redactor().redact_text(value)

    assert TOKEN not in rendered
    assert "eyJzdWIiOiJhZ2VudCJ9" not in rendered
    assert "[REDACTED]" in rendered


def test_redaction_neutralizes_controls_unknown_values_and_hostile_mappings() -> None:
    class Unknown:
        def __repr__(self) -> str:
            return TOKEN

    class HostileMapping(dict[str, object]):
        def items(self) -> Any:
            raise RuntimeError(TOKEN)

    redactor = Redactor()

    assert redactor.redact_text("safe\nforged") == "safe[CONTROL]forged"
    assert redactor.redact_text("safe\u200bforged") == "safe[CONTROL]forged"
    assert redactor.redact(Unknown()) == "[REDACTED]"
    assert redactor.redact(HostileMapping(value=TOKEN)) == "[REDACTED]"


def test_hostile_text_subclasses_cannot_escape_redaction_or_retry_boundaries() -> None:
    class HostileText(str):
        def __iter__(self) -> Any:
            raise RuntimeError(TOKEN)

        def strip(self, *args: object, **kwargs: object) -> str:
            del args, kwargs
            raise RuntimeError(OTHER_TOKEN)

    value = HostileText(TOKEN)

    assert Redactor().redact_text(value) == "[REDACTED]"
    decision = _testing_policy(0.5).authorization_retry(
        attempt=1,
        elapsed=0,
        side_effect="read_only",
        failure=RetryFailure.RATE_LIMITED,
        retry_after=value,
    )
    assert decision.should_retry
    assert decision.delay == 1.0


def test_redaction_rejects_hostile_and_nonfinite_numeric_diagnostics() -> None:
    class HostileInteger(int):
        def __repr__(self) -> str:
            return TOKEN

    redactor = Redactor()

    assert redactor.redact(HostileInteger(7)) == "[REDACTED]"
    assert redactor.redact(float("nan")) == "[REDACTED]"
    assert redactor.redact(float("inf")) == "[REDACTED]"


def test_redaction_enforces_global_occurrence_and_input_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared: object = {"token": TOKEN}
    for _ in range(8):
        shared = [shared, shared]

    redactor = Redactor(
        max_depth=16,
        max_items=8,
        max_nodes=24,
        max_total_bytes=128,
        max_string_length=64,
        max_query_pairs=4,
    )
    rendered = repr(redactor.redact(shared))
    assert TOKEN not in rendered
    assert "[LIMIT]" in rendered
    assert len(rendered) < 2048

    def must_not_transform(_value: str) -> str:
        raise AssertionError("oversized text reached transformation")

    monkeypatch.setattr("palonexus.redaction._replace_controls", must_not_transform)
    assert redactor.redact_text("a" * 65) == "[TRUNCATED]"

    called = False

    def must_not_parse(*args: object, **kwargs: object) -> list[object]:
        nonlocal called
        del args, kwargs
        called = True
        raise AssertionError("oversized query reached parser")

    monkeypatch.setattr("palonexus.redaction.parse_qsl", must_not_parse)
    assert (
        redactor.redact_url(
            "https://example.test/?" + "&".join(f"k{i}=v" for i in range(5))
        )
        == "[URL]"
    )
    assert redactor.redact_url("https://example.test/?token=" + ("x" * 65)) == "[URL]"
    assert not called


def test_all_entrypoints_reject_oversize_raw_fields_before_decoding() -> None:
    redactor = Redactor(max_string_length=32)
    oversized = "%41" * 12

    assert redactor.redact_text(oversized) == "[TRUNCATED]"
    assert redactor.redact_headers({"Safe": oversized}) == {"Safe": "[TRUNCATED]"}
    assert redactor.redact_query({"safe": oversized}) == {"safe": "[REDACTED]"}
    assert redactor.redact({"safe": oversized}) == {"safe": "[LIMIT]"}


def test_nested_mapping_is_snapshotted_once_and_never_reread() -> None:
    class OnceMapping(dict[str, object]):
        calls = 0

        def items(self) -> Any:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(TOKEN)
            return super().items()

    source = OnceMapping(token=TOKEN, safe="value")
    rendered = Redactor().redact(source)

    assert rendered == {"token": "[REDACTED]", "safe": "value"}
    assert source.calls == 1


def test_retry_policy_uses_bounded_exponential_jitter() -> None:
    low = _testing_policy(0.0)
    middle = _testing_policy(0.5)
    high = _testing_policy(1.0)

    assert (
        low.authorization_retry(
            attempt=1,
            elapsed=0,
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
        ).delay
        == 0.75
    )
    assert (
        middle.authorization_retry(
            attempt=2,
            elapsed=0,
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
        ).delay
        == 2.0
    )
    assert (
        high.authorization_retry(
            attempt=4,
            elapsed=0,
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
        ).reason
        is RetryReason.ATTEMPTS_EXHAUSTED
    )
    assert (
        high.authorization_retry(
            attempt=3,
            elapsed=0,
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
        ).delay
        == 5.0
    )


@pytest.mark.parametrize(
    "arguments",
    (
        {"max_attempts": 0},
        {"max_elapsed": 0},
        {"initial_delay": -1},
        {"max_delay": 0},
        {"multiplier": 0.5},
        {"jitter_fraction": -0.1},
        {"jitter_fraction": 1.1},
        {"max_retry_after": -1},
    ),
)
def test_retry_policy_rejects_invalid_configuration_without_echoing_values(
    arguments: dict[str, object],
) -> None:
    with pytest.raises(ValueError) as caught:
        RetryPolicy(**arguments)  # type: ignore[arg-type]

    assert "invalid retry policy" in str(caught.value).lower()
    assert repr(arguments) not in str(caught.value)


def test_retry_numeric_configuration_is_converted_once_and_failures_are_safe() -> None:
    class StatefulFloat:
        calls = 0

        def __float__(self) -> float:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(TOKEN)
            return 3.0

    class HostileFloat:
        def __float__(self) -> float:
            raise RuntimeError(TOKEN)

        def __repr__(self) -> str:
            return TOKEN

    stateful = StatefulFloat()
    policy = RetryPolicy(max_elapsed=stateful)  # type: ignore[arg-type]
    assert stateful.calls == 1
    assert "max_elapsed=3.0" in repr(policy)

    with pytest.raises(RetryPolicyError) as caught:
        RetryPolicy(max_elapsed=HostileFloat())  # type: ignore[arg-type]
    assert TOKEN not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "parameter",
    (
        "max_attempts",
        "max_elapsed",
        "initial_delay",
        "max_delay",
        "multiplier",
        "jitter_fraction",
        "max_retry_after",
    ),
)
def test_retry_constructor_failure_traceback_never_retains_hostile_numeric(
    parameter: str,
) -> None:
    class HostileNumeric:
        def __float__(self) -> float:
            raise RuntimeError("TOPSECRET")

        def __index__(self) -> int:
            raise RuntimeError("TOPSECRET")

        def __repr__(self) -> str:
            return "TOPSECRET"

    with pytest.raises(RetryPolicyError) as caught:
        RetryPolicy(**{parameter: HostileNumeric()})  # type: ignore[arg-type]

    captured = traceback.TracebackException.from_exception(
        caught.value,
        capture_locals=True,
    )
    assert "TOPSECRET" not in "".join(captured.format())
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_retry_deadline_failure_traceback_never_retains_hostile_numeric() -> None:
    class HostileDeadline:
        def __float__(self) -> float:
            raise RuntimeError("TOPSECRET")

        def __repr__(self) -> str:
            return "TOPSECRET"

    with pytest.raises(RetryPolicyError) as caught:
        _testing_policy(0.5).authorization_retry(
            attempt=1,
            elapsed=0,
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
            deadline_remaining=HostileDeadline(),  # type: ignore[arg-type]
        )

    captured = traceback.TracebackException.from_exception(
        caught.value,
        capture_locals=True,
    )
    assert "TOPSECRET" not in "".join(captured.format())
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_retry_state_numeric_values_are_converted_exactly_once() -> None:
    class StatefulElapsed:
        calls = 0

        def __float__(self) -> float:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(TOKEN)
            return 0.0

    elapsed = StatefulElapsed()
    decision = _testing_policy(0.5).authorization_retry(
        attempt=1,
        elapsed=elapsed,  # type: ignore[arg-type]
        side_effect="read_only",
        failure=RetryFailure.CONNECTION,
    )
    assert decision.should_retry
    assert elapsed.calls == 1

    class HostileElapsed:
        def __float__(self) -> float:
            raise RuntimeError(TOKEN)

    with pytest.raises(RetryPolicyError) as caught:
        _testing_policy(0.5).authorization_retry(
            attempt=1,
            elapsed=HostileElapsed(),  # type: ignore[arg-type]
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
        )
    assert TOKEN not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_retry_budget_cancellation_and_deadline_stop_with_stable_reasons() -> None:
    policy = _testing_policy(0.5, max_elapsed=3.0)
    common = {
        "attempt": 1,
        "elapsed": 0.0,
        "side_effect": "read_only",
        "failure": RetryFailure.TIMEOUT,
    }

    assert policy.authorization_retry(**common, cancelled=True).reason is (
        RetryReason.CANCELLED
    )
    assert policy.authorization_retry(**common, deadline_remaining=0).reason is (
        RetryReason.DEADLINE_EXCEEDED
    )
    assert policy.authorization_retry(**common, deadline_remaining=0.5).reason is (
        RetryReason.DEADLINE_EXCEEDED
    )
    elapsed_common = {**common, "elapsed": 2.5}
    assert policy.authorization_retry(**elapsed_common).reason is (
        RetryReason.ELAPSED_EXHAUSTED
    )


def test_retry_never_consumes_the_entire_remaining_budget() -> None:
    policy = _testing_policy(
        0.5,
        max_elapsed=1.0,
        initial_delay=1.0,
        max_delay=1.0,
        jitter_fraction=0,
    )
    common = {
        "attempt": 1,
        "elapsed": 0.0,
        "side_effect": "read_only",
        "failure": RetryFailure.TIMEOUT,
    }

    assert policy.authorization_retry(**common).reason is (
        RetryReason.ELAPSED_EXHAUSTED
    )
    deadline_policy = _testing_policy(
        0.5,
        max_elapsed=2.0,
        initial_delay=1.0,
        max_delay=1.0,
        jitter_fraction=0,
    )
    assert (
        deadline_policy.authorization_retry(
            **common,
            deadline_remaining=1.0,
        ).reason
        is RetryReason.DEADLINE_EXCEEDED
    )


def test_retry_after_delta_and_http_date_are_safely_parsed_and_capped() -> None:
    now = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
    policy = _testing_policy(0.5)
    arguments = {
        "attempt": 1,
        "elapsed": 0.0,
        "side_effect": "read_only",
        "failure": RetryFailure.RATE_LIMITED,
        "now": now,
    }

    assert policy.authorization_retry(**arguments, retry_after="7").delay == 7.0
    assert (
        policy.authorization_retry(
            **arguments,
            retry_after="Sun, 26 Jul 2026 12:00:04 GMT",
        ).delay
        == 4.0
    )
    assert policy.authorization_retry(**arguments, retry_after="999999").delay == 10.0
    assert policy.authorization_retry(**arguments, retry_after=TOKEN).delay == 1.0
    assert policy.authorization_retry(**arguments, retry_after="7\nforged").delay == 1.0


@pytest.mark.parametrize(
    "failure",
    (
        RetryFailure.VALIDATION,
        RetryFailure.AUTHENTICATION,
        RetryFailure.DENIED,
        RetryFailure.IDEMPOTENCY_CONFLICT,
        RetryFailure.PERMANENT,
    ),
)
def test_non_transient_failures_are_never_retried(failure: RetryFailure) -> None:
    decision = _testing_policy(0.5).authorization_retry(
        attempt=1,
        elapsed=0,
        side_effect="read_only",
        failure=failure,
    )

    assert not decision.should_retry
    assert decision.delay is None
    assert decision.reason is RetryReason.NON_RETRYABLE


@pytest.mark.parametrize("side_effect", ("write", "destructive", "external"))
def test_side_effecting_authorization_retries_require_valid_idempotency(
    side_effect: str,
) -> None:
    policy = _testing_policy(0.5)
    common = {
        "attempt": 1,
        "elapsed": 0,
        "side_effect": side_effect,
        "failure": RetryFailure.CONNECTION,
        "completion": CompletionState.NOT_EXECUTED,
    }

    assert policy.authorization_retry(**common).reason is (
        RetryReason.IDEMPOTENCY_REQUIRED
    )
    assert (
        policy.authorization_retry(
            **common,
            authorization_idempotency_key="not-valid",
        ).reason
        is RetryReason.IDEMPOTENCY_REQUIRED
    )
    assert policy.authorization_retry(
        **common,
        authorization_idempotency_key=IDEMPOTENCY_KEY,
    ).should_retry


def test_authorization_ambiguity_retries_but_application_ambiguity_stops() -> None:
    policy = _testing_policy(0.5)
    common = {
        "attempt": 1,
        "elapsed": 0,
        "side_effect": "write",
        "failure": RetryFailure.TIMEOUT,
        "authorization_idempotency_key": IDEMPOTENCY_KEY,
    }

    authorization = policy.authorization_retry(
        **common,
        completion=CompletionState.AUTHORIZATION_AMBIGUOUS,
    )
    application = policy.authorization_retry(
        **common,
        completion=CompletionState.APPLICATION_AMBIGUOUS,
    )

    assert authorization.should_retry
    assert authorization.reason is RetryReason.RETRY_SCHEDULED
    assert not application.should_retry
    assert application.reason is RetryReason.APPLICATION_AMBIGUOUS


def test_side_effect_retry_requires_explicit_completion_confirmation() -> None:
    decision = _testing_policy(0.5).authorization_retry(
        attempt=1,
        elapsed=0,
        side_effect="write",
        failure=RetryFailure.CONNECTION,
        authorization_idempotency_key=IDEMPOTENCY_KEY,
    )

    assert not decision.should_retry
    assert decision.reason is RetryReason.APPLICATION_AMBIGUOUS


def test_read_retry_does_not_require_idempotency_and_decisions_are_immutable() -> None:
    decision = _testing_policy(0.5).authorization_retry(
        attempt=1,
        elapsed=0,
        side_effect="read_only",
        failure=RetryFailure.UNAVAILABLE,
    )

    assert decision.should_retry
    assert decision.reason is RetryReason.RETRY_SCHEDULED
    with pytest.raises((AttributeError, TypeError)):
        decision.delay = 99


def test_retry_randomness_injection_is_private_and_random_values_fail_closed() -> None:
    assert "random_source" not in inspect.signature(RetryPolicy).parameters
    policy = RetryPolicy._for_testing(  # noqa: SLF001 - test-only injection contract
        random_source=lambda: 2.0,
    )

    decision = policy.authorization_retry(
        attempt=1,
        elapsed=0,
        side_effect="read_only",
        failure=RetryFailure.CONNECTION,
    )

    assert not decision.should_retry
    assert decision.reason is RetryReason.INVALID_RANDOMNESS


def test_retry_random_source_exceptions_and_nonfinite_values_fail_closed() -> None:
    def explode() -> float:
        raise RuntimeError(TOKEN)

    class HostileRandom:
        def __float__(self) -> float:
            raise RuntimeError("TOPSECRET")

        def __repr__(self) -> str:
            return "TOPSECRET"

    policies = (
        RetryPolicy._for_testing(random_source=explode),  # noqa: SLF001
        RetryPolicy._for_testing(  # noqa: SLF001
            random_source=lambda: HostileRandom(),  # type: ignore[arg-type]
        ),
        RetryPolicy._for_testing(random_source=lambda: float("nan")),  # noqa: SLF001
        RetryPolicy._for_testing(random_source=lambda: float("inf")),  # noqa: SLF001
    )

    for policy in policies:
        decision = policy.authorization_retry(
            attempt=1,
            elapsed=0,
            side_effect="read_only",
            failure=RetryFailure.CONNECTION,
        )
        assert decision.reason is RetryReason.INVALID_RANDOMNESS
        assert TOKEN not in repr(decision)
