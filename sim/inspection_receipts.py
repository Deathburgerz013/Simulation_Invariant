"""Hash-bound evidence of byte ranges presented for inspection."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any


RECEIPT_TYPE = "simulation_file_inspection_receipt"
FORMAT_VERSION = 1
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class InspectionReceiptError(ValueError):
    """Raised when inspection evidence is malformed, tampered, or stale."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _identity(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _normalize_path(value: str | os.PathLike[str]) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw:
        raise InspectionReceiptError("source path must be a non-empty relative path")
    candidate = raw.replace("\\", "/")
    path = PurePosixPath(candidate)
    if (
        path.is_absolute()
        or _WINDOWS_DRIVE.match(candidate)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise InspectionReceiptError(
            f"source path must be a normalized relative path: {raw}"
        )
    return path.as_posix()


def _root_path(root: str | os.PathLike[str]) -> Path:
    candidate = Path(root)
    if not candidate.exists() or not candidate.is_dir() or candidate.is_symlink():
        raise InspectionReceiptError("root must be an existing non-symlink directory")
    return candidate


def _source_path(root: Path, relative: str) -> Path:
    source = root.joinpath(*PurePosixPath(relative).parts)
    if not source.exists() or not source.is_file() or source.is_symlink():
        raise InspectionReceiptError("source must be an existing regular file")
    return source


def _file_identity(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                digest.update(block)
    except OSError as exc:
        raise InspectionReceiptError(
            f"unable to read source: {exc.__class__.__name__}"
        ) from exc
    return size, digest.hexdigest()


def _range_identity(path: Path, start: int, end: int) -> str:
    digest = hashlib.sha256()
    remaining = end - start
    try:
        with path.open("rb") as stream:
            stream.seek(start)
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    raise InspectionReceiptError("source ended inside covered range")
                remaining -= len(block)
                digest.update(block)
    except OSError as exc:
        raise InspectionReceiptError(
            f"unable to read covered range: {exc.__class__.__name__}"
        ) from exc
    return digest.hexdigest()


def _validated_ranges(
    ranges: Sequence[Sequence[int]],
    source_size: int,
) -> list[tuple[int, int]]:
    if isinstance(ranges, (str, bytes)) or not isinstance(ranges, Sequence):
        raise InspectionReceiptError("covered_ranges must be a sequence")
    result: list[tuple[int, int]] = []
    previous_end = 0
    for index, value in enumerate(ranges):
        if (
            isinstance(value, (str, bytes))
            or not isinstance(value, Sequence)
            or len(value) != 2
        ):
            raise InspectionReceiptError("each covered range must contain start and end")
        start, end = value
        if type(start) is not int or type(end) is not int:
            raise InspectionReceiptError("covered range bounds must be integers")
        if start < 0 or end <= start or end > source_size:
            raise InspectionReceiptError("covered range is outside the source")
        if index and start < previous_end:
            raise InspectionReceiptError(
                "covered ranges must be sorted and non-overlapping"
            )
        if index and start < result[-1][0]:
            raise InspectionReceiptError("covered ranges must be sorted")
        result.append((start, end))
        previous_end = end
    return result


def _uncovered_ranges(
    ranges: Sequence[tuple[int, int]],
    source_size: int,
) -> list[dict[str, int]]:
    uncovered: list[dict[str, int]] = []
    cursor = 0
    for start, end in ranges:
        if cursor < start:
            uncovered.append({"start": cursor, "end": start})
        cursor = end
    if cursor < source_size:
        uncovered.append({"start": cursor, "end": source_size})
    return uncovered


def create_inspection_receipt(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    method: str,
    covered_ranges: Sequence[Sequence[int]],
) -> dict[str, Any]:
    """Create evidence for exact source byte ranges without claiming meaning."""
    root_path = _root_path(root)
    relative = _normalize_path(path)
    source = _source_path(root_path, relative)
    if not isinstance(method, str) or not method.strip():
        raise InspectionReceiptError("method must be a non-empty string")
    source_size, source_sha256 = _file_identity(source)
    ranges = _validated_ranges(covered_ranges, source_size)
    covered = [
        {
            "start": start,
            "end": end,
            "sha256": _range_identity(source, start, end),
        }
        for start, end in ranges
    ]
    uncovered = _uncovered_ranges(ranges, source_size)
    body: dict[str, Any] = {
        "type": RECEIPT_TYPE,
        "version": FORMAT_VERSION,
        "path": relative,
        "method": method.strip(),
        "source_size": source_size,
        "source_sha256": source_sha256,
        "covered_ranges": covered,
        "uncovered_ranges": uncovered,
        "covered_byte_count": sum(end - start for start, end in ranges),
        "complete_byte_coverage": not uncovered,
        "semantic_understanding_claimed": False,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "receipt_hash": _identity(body)}


def _validated_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise InspectionReceiptError("inspection receipt must be a mapping")
    candidate = dict(receipt)
    supplied_hash = candidate.pop("receipt_hash", None)
    if not isinstance(supplied_hash, str) or supplied_hash != _identity(candidate):
        raise InspectionReceiptError("receipt hash mismatch")
    if candidate.get("type") != RECEIPT_TYPE:
        raise InspectionReceiptError("unsupported inspection receipt type")
    if candidate.get("version") != FORMAT_VERSION:
        raise InspectionReceiptError("unsupported inspection receipt version")
    path = candidate.get("path")
    if not isinstance(path, str) or _normalize_path(path) != path:
        raise InspectionReceiptError("inspection receipt path is invalid")
    method = candidate.get("method")
    if not isinstance(method, str) or not method.strip() or method != method.strip():
        raise InspectionReceiptError("inspection receipt method is invalid")
    size = candidate.get("source_size")
    if type(size) is not int or size < 0:
        raise InspectionReceiptError("inspection receipt source size is invalid")
    raw_ranges = candidate.get("covered_ranges")
    if not isinstance(raw_ranges, list):
        raise InspectionReceiptError("inspection receipt ranges must be a list")
    pairs: list[tuple[int, int]] = []
    for entry in raw_ranges:
        if not isinstance(entry, Mapping):
            raise InspectionReceiptError("inspection range must be a mapping")
        if set(entry) != {"start", "end", "sha256"}:
            raise InspectionReceiptError("inspection range fields are invalid")
        sha256 = entry["sha256"]
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise InspectionReceiptError("inspection range hash is invalid")
        pairs.append((entry["start"], entry["end"]))
    validated_pairs = _validated_ranges(pairs, size)
    uncovered = _uncovered_ranges(validated_pairs, size)
    if candidate.get("uncovered_ranges") != uncovered:
        raise InspectionReceiptError("uncovered ranges do not match covered ranges")
    covered_count = sum(end - start for start, end in validated_pairs)
    if candidate.get("covered_byte_count") != covered_count:
        raise InspectionReceiptError("covered byte count mismatch")
    if candidate.get("complete_byte_coverage") is not (not uncovered):
        raise InspectionReceiptError("complete byte coverage flag mismatch")
    for field in ("semantic_understanding_claimed", "accepted", "truth_claimed"):
        if candidate.get(field) is not False:
            raise InspectionReceiptError(f"{field} must remain false")
    for field in ("write_authority", "execution_authority"):
        if candidate.get(field) != "NONE":
            raise InspectionReceiptError(f"{field} must remain NONE")
    return {**candidate, "receipt_hash": supplied_hash}


def assess_inspection_receipt(
    root: str | os.PathLike[str],
    receipt: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Return a verified receipt and CURRENT or STALE source state."""
    verified = _validated_receipt(receipt)
    root_path = _root_path(root)
    try:
        source = _source_path(root_path, verified["path"])
    except InspectionReceiptError:
        return verified, "STALE"
    size, sha256 = _file_identity(source)
    if size != verified["source_size"] or sha256 != verified["source_sha256"]:
        return verified, "STALE"
    for entry in verified["covered_ranges"]:
        actual = _range_identity(source, entry["start"], entry["end"])
        if actual != entry["sha256"]:
            return verified, "STALE"
    return verified, "CURRENT"


def verify_inspection_receipt(
    root: str | os.PathLike[str],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify receipt integrity and its binding to the current source."""
    verified, state = assess_inspection_receipt(root, receipt)
    if state != "CURRENT":
        raise InspectionReceiptError("source identity mismatch")
    return verified


__all__ = [
    "FORMAT_VERSION",
    "InspectionReceiptError",
    "RECEIPT_TYPE",
    "assess_inspection_receipt",
    "create_inspection_receipt",
    "verify_inspection_receipt",
]
