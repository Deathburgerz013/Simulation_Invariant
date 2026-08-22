#!/usr/bin/env python3
"""Durable, hash-chained receipt ledger.

This API only appends to its ledger file. It detects malformed, truncated, and
hash-inconsistent history before appending. It does not claim that an external
actor with filesystem authority cannot replace or delete the whole ledger;
callers must retain an expected ledger id/head hash outside the file when that
threat matters.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Optional


LEDGER_RECORD_TYPE = "bounded_receipt_ledger_record"
LEDGER_RECORD_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_RECORD_BYTES = 1024 * 1024


class ReceiptLedgerError(ValueError):
    """The ledger or proposed append violates the declared contract."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReceiptLedgerError("payload_not_canonical_json") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_hash(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _normalize_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ReceiptLedgerError("payload_must_be_mapping")
    encoded = _canonical_json(dict(payload))
    decoded = json.loads(encoded.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ReceiptLedgerError("payload_must_be_mapping")
    return decoded


@dataclass(frozen=True)
class LedgerRecord:
    type: str
    version: int
    ledger_id: str
    sequence: int
    prev_record_hash: str
    payload_hash: str
    payload: dict[str, Any]
    record_hash: str

    def hash_payload(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("record_hash")
        return value

    def compute_hash(self) -> str:
        return _sha256(_canonical_json(self.hash_payload()))

    def verify_hash(self) -> bool:
        return _is_hash(self.record_hash) and secrets.compare_digest(
            self.compute_hash(), self.record_hash
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    ledger_id: str
    record_count: int
    head_hash: str
    error: str


def _record_from_dict(value: object) -> LedgerRecord:
    if not isinstance(value, dict):
        raise ReceiptLedgerError("record_not_object")
    required = {
        "type",
        "version",
        "ledger_id",
        "sequence",
        "prev_record_hash",
        "payload_hash",
        "payload",
        "record_hash",
    }
    if set(value) != required:
        raise ReceiptLedgerError("record_fields_mismatch")
    if not isinstance(value["payload"], dict):
        raise ReceiptLedgerError("record_payload_not_object")
    try:
        return LedgerRecord(**value)
    except TypeError as exc:
        raise ReceiptLedgerError("record_fields_invalid") from exc


def verify_ledger_bytes(data: bytes) -> tuple[LedgerVerification, list[LedgerRecord]]:
    if not data:
        return LedgerVerification(True, "", 0, GENESIS_HASH, ""), []
    if not data.endswith(b"\n"):
        return LedgerVerification(False, "", 0, GENESIS_HASH, "truncated_tail"), []

    records: list[LedgerRecord] = []
    ledger_id = ""
    previous = GENESIS_HASH
    for expected_sequence, raw_line in enumerate(data.splitlines()):
        if not raw_line:
            return LedgerVerification(
                False, ledger_id, len(records), previous, "blank_record"
            ), records
        if len(raw_line) > MAX_RECORD_BYTES:
            return LedgerVerification(
                False, ledger_id, len(records), previous, "record_too_large"
            ), records
        try:
            value = json.loads(raw_line.decode("utf-8"))
            record = _record_from_dict(value)
        except (UnicodeDecodeError, json.JSONDecodeError, ReceiptLedgerError) as exc:
            error = str(exc) or "record_decode_failed"
            return LedgerVerification(False, ledger_id, len(records), previous, error), records
        if _canonical_json(record.to_dict()) != raw_line:
            return LedgerVerification(
                False, ledger_id, len(records), previous, "record_not_canonical"
            ), records
        if (
            record.type != LEDGER_RECORD_TYPE
            or type(record.version) is not int
            or record.version != LEDGER_RECORD_VERSION
        ):
            return LedgerVerification(
                False, ledger_id, len(records), previous, "record_schema_mismatch"
            ), records
        if not isinstance(record.ledger_id, str) or not record.ledger_id:
            return LedgerVerification(
                False, ledger_id, len(records), previous, "ledger_id_missing"
            ), records
        if expected_sequence == 0:
            ledger_id = record.ledger_id
        elif record.ledger_id != ledger_id:
            return LedgerVerification(
                False, ledger_id, len(records), previous, "ledger_id_mismatch"
            ), records
        if type(record.sequence) is not int or record.sequence != expected_sequence:
            return LedgerVerification(
                False, ledger_id, len(records), previous, "sequence_mismatch"
            ), records
        if not _is_hash(record.prev_record_hash) or not secrets.compare_digest(
            record.prev_record_hash, previous
        ):
            return LedgerVerification(
                False, ledger_id, len(records), previous, "previous_hash_mismatch"
            ), records
        expected_payload_hash = _sha256(_canonical_json(record.payload))
        if not _is_hash(record.payload_hash) or not secrets.compare_digest(
            expected_payload_hash, record.payload_hash
        ):
            return LedgerVerification(
                False, ledger_id, len(records), previous, "payload_hash_mismatch"
            ), records
        if not record.verify_hash():
            return LedgerVerification(
                False, ledger_id, len(records), previous, "record_hash_mismatch"
            ), records
        records.append(record)
        previous = record.record_hash

    return LedgerVerification(True, ledger_id, len(records), previous, ""), records


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_parent_directory(path: Path) -> int:
    """Open every existing parent component without following symlinks."""
    absolute = path.absolute()
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parent.parts[1:]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        return current
    except OSError as exc:
        os.close(current)
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReceiptLedgerError("ledger_parent_is_symlink_or_not_directory") from exc
        raise


def _open_ledger(path: Path, *, writable: bool) -> tuple[int, int]:
    if path.name in {"", ".", ".."}:
        raise ReceiptLedgerError("ledger_filename_invalid")
    parent_fd = _open_parent_directory(path)
    flags = os.O_NOFOLLOW
    flags |= os.O_RDWR | os.O_APPEND | os.O_CREAT if writable else os.O_RDONLY
    try:
        fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        if exc.errno == errno.ELOOP:
            raise ReceiptLedgerError("ledger_is_symlink") from exc
        raise
    opened_stat = os.fstat(fd)
    if not stat.S_ISREG(opened_stat.st_mode):
        os.close(fd)
        os.close(parent_fd)
        raise ReceiptLedgerError("ledger_not_regular_file")
    if opened_stat.st_nlink != 1:
        os.close(fd)
        os.close(parent_fd)
        raise ReceiptLedgerError("ledger_has_multiple_hard_links")
    return fd, parent_fd


def verify_ledger(path: str | os.PathLike[str]) -> LedgerVerification:
    ledger_path = Path(path)
    try:
        fd, parent_fd = _open_ledger(ledger_path, writable=False)
    except FileNotFoundError:
        return LedgerVerification(False, "", 0, GENESIS_HASH, "ledger_missing")
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        result, _ = verify_ledger_bytes(_read_fd(fd))
        return result
    finally:
        os.close(fd)
        os.close(parent_fd)


def append_receipt(
    path: str | os.PathLike[str],
    *,
    ledger_id: str,
    payload: Mapping[str, Any],
    expected_head_hash: Optional[str] = None,
) -> LedgerRecord:
    """Append one canonical record after verifying all existing bytes."""
    if not isinstance(ledger_id, str) or not ledger_id.strip():
        raise ReceiptLedgerError("ledger_id_required")
    if expected_head_hash is not None and not _is_hash(expected_head_hash):
        raise ReceiptLedgerError("expected_head_hash_invalid")
    normalized_payload = _normalize_payload(payload)
    if len(_canonical_json(normalized_payload)) > MAX_RECORD_BYTES // 2:
        raise ReceiptLedgerError("record_too_large")
    ledger_path = Path(path)
    fd, parent_fd = _open_ledger(ledger_path, writable=True)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        verification, records = verify_ledger_bytes(_read_fd(fd))
        if not verification.valid:
            raise ReceiptLedgerError(verification.error)
        if records and verification.ledger_id != ledger_id:
            raise ReceiptLedgerError("ledger_id_mismatch")
        if expected_head_hash is not None and not secrets.compare_digest(
            expected_head_hash, verification.head_hash
        ):
            raise ReceiptLedgerError("expected_head_mismatch")
        fields = {
            "type": LEDGER_RECORD_TYPE,
            "version": LEDGER_RECORD_VERSION,
            "ledger_id": ledger_id,
            "sequence": len(records),
            "prev_record_hash": verification.head_hash,
            "payload_hash": _sha256(_canonical_json(normalized_payload)),
            "payload": normalized_payload,
        }
        record_hash = _sha256(_canonical_json(fields))
        record = LedgerRecord(**fields, record_hash=record_hash)
        encoded = _canonical_json(record.to_dict()) + b"\n"
        if len(encoded) > MAX_RECORD_BYTES:
            raise ReceiptLedgerError("record_too_large")
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("ledger_append_short_write")
            view = view[written:]
        os.fsync(fd)
        os.fsync(parent_fd)
        opened_stat = os.fstat(fd)
        current_stat = os.stat(
            ledger_path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise ReceiptLedgerError("ledger_path_identity_changed")
        return record
    finally:
        os.close(fd)
        os.close(parent_fd)


def append_validation_packet(
    path: str | os.PathLike[str],
    *,
    ledger_id: str,
    packet: Any,
    expected_head_hash: Optional[str] = None,
) -> LedgerRecord:
    """Explicitly persist one already-bound validation packet."""
    if not hasattr(packet, "verify_hash") or not packet.verify_hash():
        raise ReceiptLedgerError("validation_packet_hash_invalid")
    if not hasattr(packet, "to_dict"):
        raise ReceiptLedgerError("validation_packet_not_serializable")
    packet_payload = packet.to_dict()
    if packet_payload.get("type") != "bounded_candidate_validation":
        raise ReceiptLedgerError("validation_packet_type_invalid")
    if packet_payload.get("write_authority") != "NONE":
        raise ReceiptLedgerError("validation_packet_write_authority_invalid")
    if packet_payload.get("promotion_authority") != "NONE":
        raise ReceiptLedgerError("validation_packet_promotion_authority_invalid")
    payload = {
        "receipt_kind": "bounded_candidate_validation",
        "validation_packet": packet_payload,
        "source_write_authority": "NONE",
        "promotion_authority": "NONE",
    }
    return append_receipt(
        path,
        ledger_id=ledger_id,
        payload=payload,
        expected_head_hash=expected_head_hash,
    )
