"""Backup storage and encryption logic for SeedSafe."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib
import secrets
import threading


SEED_BYTES = 16
BLOCK_BYTES = 16
# SeedSafe fixes the configurable course cipher to ten rounds.
ROUNDS = 10
# For input nibbles H || L, substitute (H XOR L) || L.
SBOX = bytes(
    ((((value >> 4) ^ (value & 0x0F)) << 4) | (value & 0x0F))
    for value in range(256)
)
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


class BackupCipher:
    """The application's 128-bit substitution-permutation cipher."""

    def __init__(self) -> None:
        # Use the student's public implementation for each single-block operation
        spn = importlib.import_module("educrypto.spn")
        self._encrypt_block = spn.encrypt_block
        self._decrypt_block = spn.decrypt_block

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if len(key) != SEED_BYTES:
            raise ValueError("key must contain exactly 16 bytes")

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        self._validate_key(key)
        # Zero-fill only to the next block boundary. An already aligned message
        # receives no additional block, and the empty message stays empty.
        padding_length = (-len(plaintext)) % BLOCK_BYTES
        padded = plaintext + (b"\x00" * padding_length)

        # Process blocks independently with the same key and configuration.
        return b"".join(
            self._encrypt_block(
                key,
                padded[offset : offset + BLOCK_BYTES], # Split into different blocks
                sbox=SBOX,
                rounds=ROUNDS,
            )
            for offset in range(0, len(padded), BLOCK_BYTES)
        )

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        self._validate_key(key)
        # Every ciphertext chunk must be a complete 16-byte SPN block.
        if len(ciphertext) % BLOCK_BYTES:
            raise ValueError("ciphertext must contain complete SPN blocks")

        # Reverse each independent block in its original archive order.
        padded = b"".join(
            self._decrypt_block(
                key,
                ciphertext[offset : offset + BLOCK_BYTES], # Split into different blocks
                sbox=SBOX,
                rounds=ROUNDS,
            )
            for offset in range(0, len(ciphertext), BLOCK_BYTES)
        )

        # Zero filling carries no length field, so restoration removes all
        # trailing zero bytes. SeedSafe appends a nonzero timestamp stamp before
        # encryption, making that convention sufficient for stored text.
        return padded.rstrip(b"\x00")


class BackupService:
    """Create encrypted records and restore them with customer-held seeds."""

    def __init__(self, initial_text: str) -> None:
        if not initial_text:
            raise ValueError("the initial backup must not be empty")

        self._cipher = BackupCipher()
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
            ciphertext=self._cipher.encrypt(seed, plaintext),
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

        plaintext = self._cipher.decrypt(seed, record.ciphertext)
        stamp = self._stamp(record.created_at)
        # The stamp also verifies that the supplied seed produced valid plaintext.
        if not plaintext.endswith(stamp):
            raise ValueError("recovery seed could not restore this backup")

        try:
            return plaintext[: -len(stamp)].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("restored backup is not valid text") from error
