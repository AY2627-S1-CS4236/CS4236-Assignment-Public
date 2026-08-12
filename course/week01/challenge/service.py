"""Backup storage and encryption logic for SeedSafe."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib
import secrets
import threading


SEED_BYTES = 16
COMPANY_NAME = "SeedSafe"


@dataclass(frozen=True, slots=True)
class StoredBackup:
    record_id: str
    created_at: str
    ciphertext: bytes


class BackupRepository:
    """Thread-safe in-memory storage for encrypted backup records."""

    def __init__(self) -> None:
        self._records: list[StoredBackup] = []
        self._lock = threading.Lock()

    def add(self, record: StoredBackup) -> None:
        with self._lock:
            self._records.append(record)

    def all(self) -> tuple[StoredBackup, ...]:
        with self._lock:
            # The public archive displays the newest backup first.
            return tuple(reversed(self._records))

    def find(self, record_id: str) -> StoredBackup | None:
        with self._lock:
            return next(
                (record for record in self._records if record.record_id == record_id),
                None,
            )


class BackupService:
    """Create encrypted records and restore them with customer-held seeds."""

    def __init__(self, initial_text: str) -> None:
        if not initial_text:
            raise ValueError("the initial backup must not be empty")

        otp = importlib.import_module("educrypto.otp")
        self._encrypt = otp.encrypt
        self._decrypt = otp.decrypt
        self._repository = BackupRepository()
        # Publish the startup secret through the same path as customer backups.
        self.store(initial_text)

    @staticmethod
    def _stamp(created_at: str) -> bytes:
        return f"\n\n{COMPANY_NAME} {created_at}".encode("utf-8")

    def store(self, text: str) -> tuple[StoredBackup, bytes]:
        if not isinstance(text, str) or not text:
            raise ValueError("backup text must not be empty")

        created_at = datetime.now(timezone.utc).isoformat()
        plaintext = text.encode("utf-8") + self._stamp(created_at)
        seed = secrets.token_bytes(SEED_BYTES)
        record = StoredBackup(
            record_id=f"backup_{secrets.token_hex(8)}",
            created_at=created_at,
            ciphertext=self._encrypt(seed, plaintext),
        )
        self._repository.add(record)
        return record, seed

    def list_backups(self) -> tuple[StoredBackup, ...]:
        return self._repository.all()

    def restore(self, record_id: str, seed: bytes) -> str:
        if len(seed) != SEED_BYTES:
            raise ValueError("recovery seed has the wrong length")

        record = self._repository.find(record_id)
        if record is None:
            raise ValueError("backup record was not found")

        plaintext = self._decrypt(seed, record.ciphertext)
        stamp = self._stamp(record.created_at)
        # The stamp also verifies that the supplied seed produced valid plaintext.
        if not plaintext.endswith(stamp):
            raise ValueError("recovery seed could not restore this backup")

        try:
            return plaintext[: -len(stamp)].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("restored backup is not valid text") from error
