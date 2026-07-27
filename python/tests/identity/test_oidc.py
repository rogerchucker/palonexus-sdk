# SPDX-License-Identifier: MIT
"""Security-boundary tests for explicit OIDC verification."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import pickle
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
    utils,
)
from palonexus.identity import (
    OIDCVerificationFailed,
    OIDCVerifier,
    OIDCVerifierConfig,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
ISSUER = "https://issuer.example"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
JWKS = f"{ISSUER}/keys"
AUDIENCE = "palonexus-sdk"
_SDK_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "palonexus"


def _is_sdk_source_path(filename: str) -> bool:
    return Path(filename).resolve().is_relative_to(_SDK_SOURCE_ROOT)


def test_secret_graph_frame_filter_excludes_repository_test_paths() -> None:
    assert not _is_sdk_source_path(__file__)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _integer(value: int) -> str:
    return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(
    key: rsa.RSAPrivateKey,
    *,
    kid: str = "key-1",
    **extra: object,
) -> dict[str, object]:
    numbers = key.public_key().public_numbers()
    value: dict[str, object] = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "key_ops": ["verify"],
        "alg": "RS256",
        "n": _integer(numbers.n),
        "e": _integer(numbers.e),
    }
    value.update(extra)
    return value


def _token(
    key: rsa.RSAPrivateKey,
    *,
    kid: str = "key-1",
    header: dict[str, object] | None = None,
    claims: dict[str, object] | None = None,
) -> str:
    protected: dict[str, object] = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    protected.update(header or {})
    for name in tuple(protected):
        if protected[name] is None:
            del protected[name]
    payload: dict[str, object] = {
        "iss": ISSUER,
        "sub": "agent-7",
        "aud": ["palonexus-client", AUDIENCE],
        "azp": "palonexus-client",
        "iat": int(NOW.timestamp()),
        "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "jti": "token-7",
    }
    payload.update(claims or {})
    for name in tuple(payload):
        if payload[name] is None:
            del payload[name]
    first = _b64(json.dumps(protected, separators=(",", ":"), sort_keys=True).encode())
    second = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = key.sign(
        f"{first}.{second}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{first}.{second}.{_b64(signature)}"


def _algorithm_case(
    algorithm: str,
) -> tuple[object, dict[str, object], str]:
    if algorithm in {"RS256", "PS256"}:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = _jwk(key, alg=algorithm)
        return key, jwk, algorithm
    if algorithm == "ES256":
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        return (
            key,
            {
                "kty": "EC",
                "kid": "key-1",
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "ES256",
                "crv": "P-256",
                "x": _b64(numbers.x.to_bytes(32, "big")),
                "y": _b64(numbers.y.to_bytes(32, "big")),
            },
            algorithm,
        )
    key = ed25519.Ed25519PrivateKey.generate()
    return (
        key,
        {
            "kty": "OKP",
            "kid": "key-1",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": _b64(key.public_key().public_bytes_raw()),
        },
        algorithm,
    )


def _algorithm_token(key: object, algorithm: str) -> str:
    header = {"alg": algorithm, "kid": "key-1", "typ": "JWT"}
    claims = {
        "iss": ISSUER,
        "sub": "agent-7",
        "aud": ["palonexus-client", AUDIENCE],
        "azp": "palonexus-client",
        "iat": int(NOW.timestamp()),
        "nbf": int((NOW - timedelta(seconds=1)).timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    first = _b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    second = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    message = f"{first}.{second}".encode()
    if algorithm == "RS256":
        signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
    elif algorithm == "PS256":
        signature = key.sign(  # type: ignore[union-attr]
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    elif algorithm == "ES256":
        der = key.sign(message, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
        r, s = utils.decode_dss_signature(der)
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        s = min(s, order - s)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        signature = key.sign(message)  # type: ignore[union-attr]
    return f"{first}.{second}.{_b64(signature)}"


class ScriptedOIDC:
    def __init__(self, keys: list[dict[str, object]]) -> None:
        self.keys = keys
        self.discovery_calls = 0
        self.jwks_calls = 0
        self.requests: list[httpx.Request] = []
        self.lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.requests.append(request)
            if str(request.url) == DISCOVERY:
                self.discovery_calls += 1
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "application/json",
                        "set-cookie": "session=LEAK-cookie-secret; Secure",
                    },
                    json={"issuer": ISSUER, "jwks_uri": JWKS},
                )
            if str(request.url) == JWKS:
                self.jwks_calls += 1
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json={"keys": self.keys},
                )
        return httpx.Response(
            404,
            headers={"content-type": "application/json"},
            json={},
        )


def _config(**changes: object) -> OIDCVerifierConfig:
    values: dict[str, object] = {
        "issuer": ISSUER,
        "audiences": (AUDIENCE,),
        "client_id": "palonexus-client",
        "algorithms": ("RS256",),
        "discovery_url": DISCOVERY,
        "cache_ttl_seconds": 60,
        "max_unknown_rotation_delay_seconds": 30,
        "leeway_seconds": 2,
    }
    values.update(changes)
    return OIDCVerifierConfig(**values)  # type: ignore[arg-type]


def _verifier(
    service: ScriptedOIDC,
    **config: object,
) -> OIDCVerifier:
    return OIDCVerifier(
        _config(**config),
        transport=httpx.MockTransport(service),
        testing_only=True,
        clock=lambda: NOW,
    )


def test_discovery_and_verified_identity_are_explicit_and_immutable(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    service = ScriptedOIDC([_jwk(signing_key)])
    verifier = _verifier(service)
    identity = verifier.verify(_token(signing_key))

    assert identity.issuer == ISSUER
    assert identity.subject == "agent-7"
    assert identity.audiences == ("palonexus-client", AUDIENCE)
    assert identity.authorized_party == "palonexus-client"
    assert identity.token_id == "token-7"
    assert identity.claims["sub"] == "agent-7"
    assert copy.deepcopy(identity) is identity
    assert repr(identity) == "VerifiedOIDCIdentity([VERIFIED])"
    with pytest.raises((AttributeError, TypeError)):
        identity.subject = "attacker"  # type: ignore[misc]
    with pytest.raises(TypeError):
        pickle.dumps(identity)
    verifier.close()


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"issuer": "https://issuer.example?secret=x"},
        {"issuer": "https://user:pass@issuer.example"},
        {"issuer": "http://issuer.example"},
        {"audiences": ()},
        {"algorithms": ()},
        {"algorithms": ("none",)},
        {"algorithms": ("HS256",)},
        {"algorithms": ("RS256", "HS256")},
        {"discovery_url": "https://other.example/discovery"},
        {"jwks_url": "http://issuer.example/keys"},
    ],
)
def test_config_requires_explicit_secure_values(change: dict[str, object]) -> None:
    values: dict[str, object] = {
        "issuer": ISSUER,
        "audiences": (AUDIENCE,),
        "client_id": "palonexus-client",
        "algorithms": ("RS256",),
        "discovery_url": DISCOVERY,
    }
    values.update(change)
    if not change:
        values.pop("issuer")
    expected_error = TypeError if not change else OIDCVerificationFailed
    with pytest.raises(expected_error):
        OIDCVerifierConfig(**values)  # type: ignore[arg-type]
    assert OIDCVerifierConfig.__init__.__defaults__ is None
    assert "localhost" not in repr(OIDCVerifierConfig)


def test_issuer_audience_azp_nonce_and_typ_are_bound(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    candidates = (
        _token(signing_key, claims={"iss": "https://evil.example"}),
        _token(signing_key, claims={"aud": "other"}),
        _token(signing_key, claims={"aud": [AUDIENCE, "other"]}),
        _token(signing_key, claims={"aud": [AUDIENCE, "other"], "azp": "other"}),
        _token(signing_key, header={"typ": "JOSE"}),
    )
    for candidate in candidates:
        with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(candidate)

    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(signing_key), expected_nonce="nonce-7")
        identity = verifier.verify(
            _token(signing_key, claims={"nonce": "nonce-7"}),
            expected_nonce="nonce-7",
        )
        assert identity.nonce == "nonce-7"


def test_algorithm_confusion_tamper_and_critical_headers_fail_closed(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    good = _token(signing_key)
    first, second, third = good.split(".")
    variants = (
        _token(signing_key, header={"alg": "HS256"}),
        _token(signing_key, header={"alg": "none"}),
        _token(signing_key, header={"crit": ["exp"]}),
        _token(signing_key, header={"b64": False}),
        f"{first}.{_b64(b'{}')}.{third}",
        good + "=",
    )
    for value in variants:
        with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(value)


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256", "EdDSA"])
def test_each_supported_asymmetric_algorithm_is_interoperable(
    algorithm: str,
) -> None:
    key, jwk, selected = _algorithm_case(algorithm)
    with _verifier(
        ScriptedOIDC([jwk]),
        algorithms=(selected,),
    ) as verifier:
        assert verifier.verify(_algorithm_token(key, selected)).subject == "agent-7"


def test_duplicate_kid_and_dangerous_jwk_metadata_are_rejected(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    sets = (
        [_jwk(signing_key), _jwk(signing_key)],
        [_jwk(signing_key, jku="https://evil.example/key")],
        [_jwk(signing_key, x5u="https://evil.example/cert")],
        [_jwk(signing_key, x5c=["forbidden"])],
        [_jwk(signing_key, use="enc")],
        [_jwk(signing_key, key_ops=["sign"])],
        [_jwk(signing_key, alg="PS256")],
    )
    for keys in sets:
        with _verifier(ScriptedOIDC(keys)) as verifier:
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(signing_key))


def test_rotation_unknown_kid_refreshes_once_and_cache_prevents_stampede(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service = ScriptedOIDC([_jwk(signing_key)])
    with _verifier(service) as verifier:
        assert verifier.verify(_token(signing_key)).subject == "agent-7"
        service.keys = [_jwk(rotated, kid="key-2")]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    verifier.verify,
                    [_token(rotated, kid="key-2")] * 16,
                )
            )
        assert {item.subject for item in results} == {"agent-7"}
    assert service.discovery_calls == 2
    assert service.jwks_calls == 2


def test_same_kid_signature_rotation_forces_one_refresh(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service = ScriptedOIDC([_jwk(signing_key)])
    with _verifier(service) as verifier:
        verifier.verify(_token(signing_key))
        service.keys = [_jwk(rotated)]
        assert verifier.verify(_token(rotated)).subject == "agent-7"
    assert service.jwks_calls == 2


def test_cache_ttl_uses_the_injected_utc_clock(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    current = [NOW]
    service = ScriptedOIDC([_jwk(signing_key)])
    verifier = OIDCVerifier(
        _config(cache_ttl_seconds=1),
        transport=httpx.MockTransport(service),
        testing_only=True,
        clock=lambda: current[0],
    )
    with verifier:
        verifier.verify(_token(signing_key))
        current[0] += timedelta(seconds=2)
        verifier.verify(_token(signing_key))
    assert service.jwks_calls == 2


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": int((NOW - timedelta(seconds=3)).timestamp())},
        {"nbf": int((NOW + timedelta(seconds=3)).timestamp())},
        {"iat": int((NOW + timedelta(seconds=3)).timestamp())},
        {"sub": ""},
        {"exp": "secret"},
    ],
)
def test_time_and_subject_claims_are_strict(
    signing_key: rsa.RSAPrivateKey,
    claims: dict[str, object],
) -> None:
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(signing_key, claims=claims))


def test_expiry_at_exact_leeway_boundary_is_rejected(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(
                _token(
                    signing_key,
                    claims={"exp": int((NOW - timedelta(seconds=2)).timestamp())},
                )
            )


@pytest.mark.parametrize("mode", ["unavailable", "malformed", "oversize", "redirect"])
def test_unavailable_malformed_oversize_or_redirected_metadata_fails_closed(
    signing_key: rsa.RSAPrivateKey,
    mode: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "unavailable":
            raise httpx.ConnectError("callback_secret=do-not-retain")
        if mode == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.example"})
        if mode == "oversize":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b"{" + (b"x" * 1_048_577),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'{"issuer":"x","issuer":"y"}',
        )

    verifier = OIDCVerifier(
        _config(),
        transport=httpx.MockTransport(handler),
        testing_only=True,
        clock=lambda: NOW,
    )
    with verifier, pytest.raises(OIDCVerificationFailed) as captured:
        verifier.verify(_token(signing_key))
    rendered = repr(captured.value)
    assert "secret" not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_transport_has_no_ambient_auth_cookies_proxy_or_redirects(
    signing_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@proxy.invalid")
    service = ScriptedOIDC([_jwk(signing_key)])
    with _verifier(service) as verifier:
        verifier.verify(_token(signing_key))
    assert all("authorization" not in request.headers for request in service.requests)
    assert all("cookie" not in request.headers for request in service.requests)
    assert all(request.url.scheme == "https" for request in service.requests)


@pytest.mark.parametrize(
    "exception_type",
    [asyncio.CancelledError, GeneratorExit, KeyboardInterrupt, SystemExit],
)
def test_control_flow_propagates_without_secret_graph(
    signing_key: rsa.RSAPrivateKey,
    exception_type: type[BaseException],
) -> None:
    def cancel(_: httpx.Request) -> httpx.Response:
        callback_secret = "do-not-retain"
        del callback_secret
        raise exception_type

    verifier = OIDCVerifier(
        _config(),
        transport=httpx.MockTransport(cancel),
        testing_only=True,
        clock=lambda: NOW,
    )
    with verifier, pytest.raises(exception_type) as captured:
        verifier.verify(_token(signing_key))
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert captured.value.__traceback__ is not None


def test_raw_token_url_and_callback_secrets_are_unreachable_from_error_graph(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    raw_token = _token(signing_key, claims={"private": "LEAK-claim-secret"})

    def broken(_: httpx.Request) -> httpx.Response:
        raise RuntimeError("LEAK-callback-secret")

    verifier = OIDCVerifier(
        _config(),
        transport=httpx.MockTransport(broken),
        testing_only=True,
        clock=lambda: NOW,
    )
    with verifier, pytest.raises(OIDCVerificationFailed) as captured:
        verifier.verify(raw_token)
    values: list[object] = []
    pending: list[BaseException] = [captured.value]
    while pending:
        current = pending.pop()
        values.extend((current, current.args))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        for frame, _ in traceback.walk_tb(current.__traceback__):
            if _is_sdk_source_path(frame.f_code.co_filename):
                values.extend(frame.f_locals.values())
    rendered = " ".join(repr(value) for value in values)
    assert raw_token not in rendered
    assert "LEAK-claim-secret" not in rendered
    assert "LEAK-callback-secret" not in rendered


def test_unknown_kid_and_bad_signature_have_bounded_refresh_amplification(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    service = ScriptedOIDC([_jwk(signing_key)])
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with _verifier(service) as verifier:
        verifier.verify(_token(signing_key))
        for _ in range(20):
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(attacker, kid="unknown"))
        after_unknown = service.jwks_calls
        for _ in range(20):
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(attacker))
        after_signature = service.jwks_calls
    assert after_unknown == 2
    assert after_signature == 3


def test_concurrent_unknown_kid_is_singleflight(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    service = ScriptedOIDC([_jwk(signing_key)])
    with _verifier(service) as verifier:
        verifier.verify(_token(signing_key))

        def rejected(_: int) -> bool:
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(signing_key, kid="unknown"))
            return True

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert all(pool.map(rejected, range(32)))
    assert service.jwks_calls == 2


def test_failed_refresh_backoff_and_rotation_after_cooldown(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    current = [NOW]
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service = ScriptedOIDC([_jwk(signing_key)])
    verifier = OIDCVerifier(
        _config(refresh_cooldown_seconds=2, failure_backoff_seconds=1),
        transport=httpx.MockTransport(service),
        testing_only=True,
        clock=lambda: current[0],
    )
    with verifier:
        verifier.verify(_token(signing_key))
        service.keys = [_jwk(signing_key)]
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(rotated))
        service.keys = [_jwk(rotated)]
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(rotated))
        assert service.jwks_calls == 2
        current[0] += timedelta(seconds=2)
        assert verifier.verify(_token(rotated)).subject == "agent-7"
    assert service.jwks_calls == 3


def test_failed_refresh_backoff_suppresses_distinct_attacker_kids(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    service = ScriptedOIDC([_jwk(signing_key)])
    failing = [False]

    def handler(request: httpx.Request) -> httpx.Response:
        if failing[0]:
            with service.lock:
                service.requests.append(request)
                if str(request.url) == DISCOVERY:
                    service.discovery_calls += 1
            raise httpx.ConnectError("metadata unavailable")
        return service(request)

    verifier = OIDCVerifier(
        _config(),
        transport=httpx.MockTransport(handler),
        testing_only=True,
        clock=lambda: NOW,
    )
    with verifier:
        verifier.verify(_token(signing_key))
        failing[0] = True
        for kid in ("unknown-1", "unknown-2", "unknown-3"):
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(signing_key, kid=kid))
    assert service.discovery_calls == 2


def test_provider_style_optional_jwk_metadata_and_missing_kid(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    eligible = _jwk(signing_key)
    for name in ("kid", "alg", "use", "key_ops"):
        eligible.pop(name)
    irrelevant = _jwk(signing_key, kid="encryption", use="enc")
    with _verifier(
        ScriptedOIDC([irrelevant, eligible]),
        allow_missing_kid=True,
        require_typ=False,
    ) as verifier:
        identity = verifier.verify(
            _token(signing_key, header={"kid": None, "typ": None})
        )
    assert identity.subject == "agent-7"


def test_optional_jwk_alg_is_selected_by_token_algorithm() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eligible = _jwk(key)
    eligible.pop("alg")
    with _verifier(
        ScriptedOIDC([eligible]),
        algorithms=("RS256", "PS256"),
    ) as verifier:
        assert verifier.verify(_token(key)).subject == "agent-7"


def test_es256_requires_exact_coordinate_width() -> None:
    key, jwk, algorithm = _algorithm_case("ES256")
    encoded_x = jwk["x"]
    assert isinstance(encoded_x, str)
    x = base64.urlsafe_b64decode(encoded_x + "==")
    jwk["x"] = _b64(x[1:])
    with _verifier(
        ScriptedOIDC([jwk]),
        algorithms=("ES256",),
    ) as verifier:
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_algorithm_token(key, algorithm))


def test_missing_kid_rejects_ambiguous_eligible_keys(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first = _jwk(signing_key)
    second = _jwk(other, kid="key-2")
    with _verifier(
        ScriptedOIDC([first, second]),
        allow_missing_kid=True,
        require_typ=False,
    ) as verifier:
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(signing_key, header={"kid": None, "typ": None}))


def test_multi_audience_azp_binds_distinct_client_id(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        accepted = verifier.verify(
            _token(
                signing_key,
                claims={
                    "aud": [
                        "palonexus-client",
                        AUDIENCE,
                        "another-resource",
                    ],
                    "azp": "palonexus-client",
                },
            )
        )
        assert accepted.authorized_party == "palonexus-client"
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(
                _token(
                    signing_key,
                    claims={
                        "aud": ["palonexus-client", AUDIENCE, "other"],
                        "azp": AUDIENCE,
                    },
                )
            )


def test_verified_claims_are_deeply_immutable_and_copy_on_read(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        identity = verifier.verify(
            _token(
                signing_key,
                claims={"nested": {"values": [1, {"enabled": True}]}},
            )
        )
    first = identity.claims
    nested = first["nested"]
    assert isinstance(nested, dict)
    values = nested["values"]
    assert isinstance(values, list)
    values.append("mutated")
    assert identity.claims["nested"] == {"values": [1, {"enabled": True}]}
    assert type(identity._claims).__name__ == "_FrozenObject"


def test_es256_high_s_malleated_twin_is_rejected() -> None:
    key, jwk, algorithm = _algorithm_case("ES256")
    token = _algorithm_token(key, algorithm)
    first, second, encoded = token.split(".")
    signature = base64.urlsafe_b64decode(encoded + "==")
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    s = int.from_bytes(signature[32:], "big")
    twin = signature[:32] + (order - s).to_bytes(32, "big")
    malleated = f"{first}.{second}.{_b64(twin)}"
    with _verifier(
        ScriptedOIDC([jwk]),
        algorithms=("ES256",),
    ) as verifier:
        assert verifier.verify(token).subject == "agent-7"
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(malleated)


@pytest.mark.parametrize(
    "name",
    ["jku", "x5u", "x5c", "x5t", "x5t#S256", "jwk", "crit", "b64"],
)
def test_closed_token_metadata_policy(
    signing_key: rsa.RSAPrivateKey,
    name: str,
) -> None:
    value: object = ["unknown"] if name == "crit" else "forbidden"
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(signing_key, header={name: value}))


def test_numeric_date_boundaries(signing_key: rsa.RSAPrivateKey) -> None:
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        accepted = _token(
            signing_key,
            claims={
                "exp": int((NOW - timedelta(seconds=1)).timestamp()),
                "nbf": int((NOW + timedelta(seconds=2)).timestamp()),
                "iat": int((NOW + timedelta(seconds=2)).timestamp()),
            },
        )
        assert verifier.verify(accepted).subject == "agent-7"
        for claim in ("nbf", "iat"):
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(
                    _token(
                        signing_key,
                        claims={claim: int((NOW + timedelta(seconds=3)).timestamp())},
                    )
                )


def test_client_id_is_always_an_id_token_audience(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    with _verifier(ScriptedOIDC([_jwk(signing_key)])) as verifier:
        for claims in (
            {"aud": AUDIENCE, "azp": None},
            {"aud": [AUDIENCE, "other"], "azp": "palonexus-client"},
            {
                "aud": ["palonexus-client", AUDIENCE],
                "azp": None,
            },
        ):
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(signing_key, claims=claims))

    with _verifier(
        ScriptedOIDC([_jwk(signing_key)]),
        audiences=("palonexus-client",),
    ) as verifier:
        identity = verifier.verify(
            _token(
                signing_key,
                claims={"aud": "palonexus-client", "azp": None},
            )
        )
    assert identity.audiences == ("palonexus-client",)


def test_unknown_kid_recovers_within_configured_proactive_horizon(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    current = [NOW]
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service = ScriptedOIDC([_jwk(signing_key)])
    verifier = OIDCVerifier(
        _config(
            cache_ttl_seconds=60,
            max_unknown_rotation_delay_seconds=2,
            refresh_cooldown_seconds=30,
        ),
        transport=httpx.MockTransport(service),
        testing_only=True,
        clock=lambda: current[0],
    )
    with verifier:
        verifier.verify(_token(signing_key))
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(signing_key, kid="attacker-kid"))
        service.keys = [_jwk(rotated, kid="rotated")]
        with pytest.raises(OIDCVerificationFailed):
            verifier.verify(_token(rotated, kid="rotated"))
        current[0] += timedelta(seconds=2)
        assert verifier.verify(_token(rotated, kid="rotated")).subject == "agent-7"
    assert service.jwks_calls == 3


def test_valid_discovery_then_unavailable_jwks_is_opaque(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if str(request.url) == DISCOVERY:
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"issuer": ISSUER, "jwks_uri": JWKS},
            )
        raise httpx.ConnectError("LEAK-jwks-secret")

    verifier = OIDCVerifier(
        _config(),
        transport=httpx.MockTransport(handler),
        testing_only=True,
        clock=lambda: NOW,
    )
    with verifier, pytest.raises(OIDCVerificationFailed) as captured:
        verifier.verify(_token(signing_key))
    assert calls == [DISCOVERY, JWKS]
    assert "LEAK" not in repr(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_key_ops_is_exactly_verify_when_present(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    for operations in (
        ["verify", "encrypt"],
        ["verify", "sign"],
        ["encrypt"],
        [],
    ):
        with _verifier(
            ScriptedOIDC([_jwk(signing_key, key_ops=operations)])
        ) as verifier:
            with pytest.raises(OIDCVerificationFailed):
                verifier.verify(_token(signing_key))
