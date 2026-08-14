# SPDX-License-Identifier: MIT
"""macOS/Linux credential custody with process-shared mutation locking."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

import keyring

_MUTATION_LOCK = threading.RLock()


class CredentialStoreUnavailable(RuntimeError):
    """No approved credential store is available."""


class KeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, value: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


def _default_state_dir() -> Path:
    if state_home := os.environ.get("XDG_STATE_HOME"):
        return Path(state_home) / "palonexus"
    return Path.home() / ".local" / "state" / "palonexus"


class CredentialStore:
    service = "cloud.palonexus.pnxs"

    def __init__(
        self,
        *,
        keyring_backend: KeyringBackend | None = None,
        state_dir: Path | None = None,
        allow_file_fallback: bool = False,
    ) -> None:
        self.keyring = keyring_backend or keyring
        self.state_dir = state_dir or _default_state_dir()
        self.allow_file_fallback = allow_file_fallback

    @property
    def fallback_path(self) -> Path:
        return self.state_dir / "credentials.json"

    @contextmanager
    def _mutation_lock(self) -> Iterator[None]:
        with _MUTATION_LOCK:
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.state_dir, 0o700)
            descriptor = os.open(
                self.state_dir / ".credentials.lock",
                os.O_CREAT | os.O_RDWR,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _file_values(self) -> dict[str, dict[str, str]]:
        path = self.fallback_path
        if not path.exists():
            return {}
        if path.stat().st_mode & 0o077:
            raise CredentialStoreUnavailable("credential file permissions are not 0600")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CredentialStoreUnavailable("credential file is unreadable") from error
        if not isinstance(value, dict):
            raise CredentialStoreUnavailable("credential file is invalid")
        return value

    def _write_file_values(self, values: dict[str, dict[str, str]]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".credentials-", suffix=".tmp", dir=self.state_dir
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(values, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            temporary.replace(self.fallback_path)
        finally:
            temporary.unlink(missing_ok=True)
        os.chmod(self.fallback_path, 0o600)

    @staticmethod
    def _decode_keyring_value(serialized: str) -> dict[str, str]:
        try:
            value = json.loads(serialized)
        except json.JSONDecodeError as error:
            raise CredentialStoreUnavailable("OS keyring value is invalid") from error
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in value.items()
        ):
            raise CredentialStoreUnavailable("OS keyring value is invalid")
        return value

    def save(self, name: str, value: dict[str, str]) -> None:
        with self._mutation_lock():
            serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
            try:
                self.keyring.set_password(self.service, name, serialized)
                return
            except Exception as error:
                if not self.allow_file_fallback:
                    raise CredentialStoreUnavailable(
                        "OS keyring unavailable; pass --allow-file-credential-store "
                        "to consent to a 0600 fallback"
                    ) from error
            values = self._file_values()
            values[name] = value
            self._write_file_values(values)

    def create_if_absent(self, name: str, value: dict[str, str]) -> bool:
        with self._mutation_lock():
            keyring_available = True
            try:
                serialized = self.keyring.get_password(self.service, name)
            except Exception as error:
                if not self.allow_file_fallback:
                    raise CredentialStoreUnavailable(
                        "OS keyring unavailable"
                    ) from error
                keyring_available = False
                serialized = None

            keyring_value = (
                self._decode_keyring_value(serialized)
                if serialized is not None
                else None
            )
            file_values = self._file_values() if self.allow_file_fallback else {}
            file_value = file_values.get(name)
            if (
                keyring_value is not None
                and file_value is not None
                and keyring_value != file_value
            ):
                raise CredentialStoreUnavailable("credential stores disagree")
            if keyring_value is not None or file_value is not None:
                return False

            if keyring_available:
                try:
                    serialized = json.dumps(
                        value, sort_keys=True, separators=(",", ":")
                    )
                    self.keyring.set_password(self.service, name, serialized)
                    return True
                except Exception as error:
                    if not self.allow_file_fallback:
                        raise CredentialStoreUnavailable(
                            "OS keyring unavailable; pass "
                            "--allow-file-credential-store to consent "
                            "to a 0600 fallback"
                        ) from error
            file_values[name] = value
            self._write_file_values(file_values)
            return True

    def load(self, name: str) -> dict[str, str] | None:
        if self.allow_file_fallback:
            with self._mutation_lock():
                try:
                    serialized = self.keyring.get_password(self.service, name)
                except Exception:
                    serialized = None
                keyring_value = (
                    self._decode_keyring_value(serialized)
                    if serialized is not None
                    else None
                )
                file_value = self._file_values().get(name)
                if (
                    keyring_value is not None
                    and file_value is not None
                    and keyring_value != file_value
                ):
                    raise CredentialStoreUnavailable("credential stores disagree")
                return keyring_value if keyring_value is not None else file_value

        try:
            serialized = self.keyring.get_password(self.service, name)
        except Exception as error:
            raise CredentialStoreUnavailable("OS keyring unavailable") from error
        if serialized is None:
            return None
        return self._decode_keyring_value(serialized)

    def delete(self, name: str) -> None:
        with self._mutation_lock():
            try:
                self.keyring.delete_password(self.service, name)
            except Exception as error:
                if not self.allow_file_fallback:
                    raise CredentialStoreUnavailable(
                        "OS keyring unavailable"
                    ) from error
            if self.allow_file_fallback:
                values = self._file_values()
                if name in values:
                    del values[name]
                    self._write_file_values(values)
