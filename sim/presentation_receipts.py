"""Hash-bound evidence of exact byte ranges presented by an environment."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any


RECEIPT_TYPE = "simulation_file_presentation_receipt"
FORMAT_VERSION = 1
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class PresentationReceiptError(ValueError):
    """Raised when presentation evidence is malformed, tampered, or stale."""


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
        raise PresentationReceiptError(
            "source path must be a non-empty relative path"
        )
    candidate = raw.replace("\\", "/")
    path = PurePosixPath(candidate)
    if (
        path.is_absolute()
        or _WINDOWS_DRIVE.match(candidate)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PresentationReceiptError(
            f"source path must be a normalized relative path: {raw}"
        )
    return path.as_posix()


def _root_path(root: str | os.PathLike[str]) -> Path:
    candidate = Path(root)
    if (
        not candidate.exists()
        or not candidate.is_dir()
        or candidate.is_symlink()
    ):
        raise PresentationReceiptError(
            "root must be an existing non-symlink directory"
        )
    return candidate


def _source_path(root: Path, relative: str) -> Path:
    source = root.joinpath(*PurePosixPath(relative).parts)
    if not source.exists() or not source.is_file() or source.is_symlink():
        raise PresentationReceiptError(
            "source must be an existing regular file"
        )
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
        raise PresentationReceiptError(
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
                    raise PresentationReceiptError(
                        "source ended inside presented range"
                    )
                remaining -= len(block)
                digest.update(block)
    except OSError as exc:
        raise PresentationReceiptError(
            f"unable to read presented range: {exc.__class__.__name__}"
        ) from exc
    return digest.hexdigest()


def _validated_ranges(
    ranges: Sequence[Sequence[int]],
    source_size: int,
) -> list[tuple[int, int]]:
    if isinstance(ranges, (str, bytes)) or not isinstance(ranges, Sequence):
        raise PresentationReceiptError(
            "presented_ranges must be a sequence"
        )
    result: list[tuple[int, int]] = []
    previous_end = 0
    for index, value in enumerate(ranges):
        if (
            isinstance(value, (str, bytes))
            or not isinstance(value, Sequence)
            or len(value) != 2
        ):
            raise PresentationReceiptError(
                "each presented range must contain start and end"
            )
        start, end = value
        if type(start) is not int or type(end) is not int:
            raise PresentationReceiptError(
                "presented range bounds must be integers"
            )
        if start < 0 or end <= start or end > source_size:
            raise PresentationReceiptError(
                "presented range is outside the source"
            )
        if index and start < previous_end:
            raise PresentationReceiptError(
                "presented ranges must be sorted and non-overlapping"
            )
        result.append((start, end))
        previous_end = end
    return result


def _unpresented_ranges(
    ranges: Sequence[tuple[int, int]],
    source_size: int,
) -> list[dict[str, int]]:
    unpresented: list[dict[str, int]] = []
    cursor = 0
    for start, end in ranges:
        if cursor < start:
            unpresented.append({"start": cursor, "end": start})
        cursor = end
    if cursor < source_size:
        unpresented.append({"start": cursor, "end": source_size})
    return unpresented


def create_presentation_receipt(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    method: str,
    presented_ranges: Sequence[Sequence[int]],
) -> dict[str, Any]:
    """Bind exact presented byte ranges without claiming inspection."""
    root_path = _root_path(root)
    relative = _normalize_path(path)
    source = _source_path(root_path, relative)
    if not isinstance(method, str) or not method.strip():
        raise PresentationReceiptError("method must be a non-empty string")
    source_size, source_sha256 = _file_identity(source)
    ranges = _validated_ranges(presented_ranges, source_size)
    presented = [
        {
            "start": start,
            "end": end,
            "sha256": _range_identity(source, start, end),
        }
        for start, end in ranges
    ]
    unpresented = _unpresented_ranges(ranges, source_size)
    body: dict[str, Any] = {
        "type": RECEIPT_TYPE,
        "version": FORMAT_VERSION,
        "path": relative,
        "method": method.strip(),
        "source_size": source_size,
        "source_sha256": source_sha256,
        "presented_ranges": presented,
        "unpresented_ranges": unpresented,
        "presented_byte_count": sum(end - start for start, end in ranges),
        "complete_byte_presentation": not unpresented,
        "semantic_inspection_claimed": False,
        "semantic_understanding_claimed": False,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "receipt_hash": _identity(body)}


def _validated_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise PresentationReceiptError(
            "presentation receipt must be a mapping"
        )
    candidate = dict(receipt)
    supplied_hash = candidate.pop("receipt_hash", None)
    if not isinstance(supplied_hash, str) or supplied_hash != _identity(candidate):
        raise PresentationReceiptError("receipt hash mismatch")
    if candidate.get("type") != RECEIPT_TYPE:
        raise PresentationReceiptError(
            "unsupported presentation receipt type"
        )
    if candidate.get("version") != FORMAT_VERSION:
        raise PresentationReceiptError(
            "unsupported presentation receipt version"
        )
    path = candidate.get("path")
    if not isinstance(path, str) or _normalize_path(path) != path:
        raise PresentationReceiptError(
            "presentation receipt path is invalid"
        )
    method = candidate.get("method")
    if (
        not isinstance(method, str)
        or not method.strip()
        or method != method.strip()
    ):
        raise PresentationReceiptError(
            "presentation receipt method is invalid"
        )
    size = candidate.get("source_size")
    if type(size) is not int or size < 0:
        raise PresentationReceiptError(
            "presentation receipt source size is invalid"
        )
    raw_ranges = candidate.get("presented_ranges")
    if not isinstance(raw_ranges, list):
        raise PresentationReceiptError(
            "presentation receipt ranges must be a list"
        )
    pairs: list[tuple[int, int]] = []
    for entry in raw_ranges:
        if not isinstance(entry, Mapping):
            raise PresentationReceiptError(
                "presentation range must be a mapping"
            )
        if set(entry) != {"start", "end", "sha256"}:
            raise PresentationReceiptError(
                "presentation range fields are invalid"
            )
        sha256 = entry["sha256"]
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in sha256
            )
        ):
            raise PresentationReceiptError(
                "presentation range hash is invalid"
            )
        pairs.append((entry["start"], entry["end"]))
    validated_pairs = _validated_ranges(pairs, size)
    unpresented = _unpresented_ranges(validated_pairs, size)
    if candidate.get("unpresented_ranges") != unpresented:
        raise PresentationReceiptError(
            "unpresented ranges do not match presented ranges"
        )
    presented_count = sum(end - start for start, end in validated_pairs)
    if candidate.get("presented_byte_count") != presented_count:
        raise PresentationReceiptError("presented byte count mismatch")
    if candidate.get("complete_byte_presentation") is not (not unpresented):
        raise PresentationReceiptError(
            "complete byte presentation flag mismatch"
        )
    for field in (
        "semantic_inspection_claimed",
        "semantic_understanding_claimed",
        "accepted",
        "truth_claimed",
    ):
        if candidate.get(field) is not False:
            raise PresentationReceiptError(f"{field} must remain false")
    for field in ("write_authority", "execution_authority"):
        if candidate.get(field) != "NONE":
            raise PresentationReceiptError(f"{field} must remain NONE")
    return {**candidate, "receipt_hash": supplied_hash}


def assess_presentation_receipt(
    root: str | os.PathLike[str],
    receipt: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Return a verified receipt and CURRENT or STALE source state."""
    verified = _validated_receipt(receipt)
    root_path = _root_path(root)
    try:
        source = _source_path(root_path, verified["path"])
    except PresentationReceiptError:
        return verified, "STALE"
    size, sha256 = _file_identity(source)
    if size != verified["source_size"] or sha256 != verified["source_sha256"]:
        return verified, "STALE"
    for entry in verified["presented_ranges"]:
        actual = _range_identity(source, entry["start"], entry["end"])
        if actual != entry["sha256"]:
            return verified, "STALE"
    return verified, "CURRENT"


def verify_presentation_receipt(
    root: str | os.PathLike[str],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify receipt integrity and its binding to the current source."""
    verified, state = assess_presentation_receipt(root, receipt)
    if state != "CURRENT":
        raise PresentationReceiptError("source identity mismatch")
    return verified


__all__ = [
    "FORMAT_VERSION",
    "PresentationReceiptError",
    "RECEIPT_TYPE",
    "assess_presentation_receipt",
    "create_presentation_receipt",
    "verify_presentation_receipt",
]
