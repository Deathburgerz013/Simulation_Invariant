"""Lossless bounded presentation packets for files in an environment."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from sim.presentation_receipts import (
    PresentationReceiptError,
    create_presentation_receipt,
    verify_presentation_receipt,
)


OBSERVATION_TYPE = "simulation_bounded_observation_packet"
OBSERVATION_VERSION = 1
DEFAULT_MAX_BYTES = 4096
DEFAULT_METHOD = "bounded-observation-v1"
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class ObservationPacketError(ValueError):
    """Raised when an observation packet or request is invalid."""


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
        raise ObservationPacketError("path must be a non-empty relative path")
    candidate = raw.replace("\\", "/")
    path = PurePosixPath(candidate)
    if (
        path.is_absolute()
        or _WINDOWS_DRIVE.match(candidate)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ObservationPacketError(
            f"path must be a normalized relative path: {raw}"
        )
    return path.as_posix()


def _source(root: str | os.PathLike[str], relative: str) -> tuple[Path, Path]:
    root_path = Path(root)
    if not root_path.exists() or not root_path.is_dir() or root_path.is_symlink():
        raise ObservationPacketError("root must be an existing non-symlink directory")
    source = root_path.joinpath(*PurePosixPath(relative).parts)
    if not source.exists() or not source.is_file() or source.is_symlink():
        raise ObservationPacketError("source must be an existing regular file")
    return root_path, source


def _read_range(path: Path, start: int, end: int) -> bytes:
    remaining = end - start
    chunks: list[bytes] = []
    try:
        with path.open("rb") as stream:
            stream.seek(start)
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    raise ObservationPacketError("source ended inside presented range")
                chunks.append(block)
                remaining -= len(block)
    except OSError as exc:
        raise ObservationPacketError(
            f"unable to read source range: {exc.__class__.__name__}"
        ) from exc
    return b"".join(chunks)


def _utf8_text(content: bytes) -> str | None:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _prior_receipt(
    root: Path,
    relative: str,
    prior_receipt: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if prior_receipt is None:
        return None
    try:
        verified = verify_presentation_receipt(root, prior_receipt)
    except PresentationReceiptError as exc:
        raise ObservationPacketError(str(exc)) from exc
    if verified["path"] != relative:
        raise ObservationPacketError("prior receipt must bind the same source path")
    return verified


def _range_pairs(receipt: Mapping[str, Any] | None) -> list[tuple[int, int]]:
    if receipt is None:
        return []
    return [
        (entry["start"], entry["end"])
        for entry in receipt["presented_ranges"]
    ]


def _overlaps(start: int, end: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(start < prior_end and prior_start < end for prior_start, prior_end in ranges)


def build_observation_packet(
    root: str | os.PathLike[str],
    path: str | os.PathLike[str],
    *,
    start: int | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    prior_receipt: Mapping[str, Any] | None = None,
    method: str = DEFAULT_METHOD,
) -> dict[str, Any]:
    """Present one exact bounded range and accumulate presentation evidence."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ObservationPacketError("max_bytes must be a positive integer")
    if start is not None and type(start) is not int:
        raise ObservationPacketError("start must be an integer")
    if not isinstance(method, str) or not method.strip():
        raise ObservationPacketError("method must be a non-empty string")

    relative = _normalize_path(path)
    root_path, source = _source(root, relative)
    source_size = source.stat().st_size
    prior = _prior_receipt(root_path, relative, prior_receipt)
    prior_ranges = _range_pairs(prior)

    if source_size == 0:
        if start not in {None, 0}:
            raise ObservationPacketError("start must be zero for an empty source")
        if prior_ranges:
            raise ObservationPacketError("empty source cannot have presented ranges")
        selected_start = 0
        selected_end = 0
        presented_range: dict[str, int] | None = None
        content = b""
        combined_ranges: list[tuple[int, int]] = []
    else:
        if start is None:
            if prior is None:
                selected_start = 0
            else:
                uncovered = prior["unpresented_ranges"]
                if not uncovered:
                    raise ObservationPacketError("prior receipt already has complete presentation")
                selected_start = uncovered[0]["start"]
        else:
            selected_start = start
        if selected_start < 0 or selected_start >= source_size:
            raise ObservationPacketError("start must identify a byte inside the source")
        selected_end = min(source_size, selected_start + max_bytes)
        if _overlaps(selected_start, selected_end, prior_ranges):
            raise ObservationPacketError("presented range would overlap prior presentation")
        presented_range = {"start": selected_start, "end": selected_end}
        content = _read_range(source, selected_start, selected_end)
        combined_ranges = sorted(
            [*prior_ranges, (selected_start, selected_end)],
            key=lambda item: item[0],
        )

    receipt_method = prior["method"] if prior is not None else method.strip()
    try:
        receipt = create_presentation_receipt(
            root_path,
            relative,
            method=receipt_method,
            presented_ranges=combined_ranges,
        )
    except PresentationReceiptError as exc:
        raise ObservationPacketError(str(exc)) from exc

    next_offset = (
        receipt["unpresented_ranges"][0]["start"]
        if receipt["unpresented_ranges"]
        else None
    )
    body: dict[str, Any] = {
        "type": OBSERVATION_TYPE,
        "version": OBSERVATION_VERSION,
        "path": relative,
        "source_size": receipt["source_size"],
        "source_sha256": receipt["source_sha256"],
        "presented_range": presented_range,
        "content_encoding": "base64",
        "content_base64": base64.b64encode(content).decode("ascii"),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "utf8_text": _utf8_text(content),
        "next_offset": next_offset,
        "presentation_receipt": receipt,
        "semantic_inspection_claimed": False,
        "semantic_understanding_claimed": False,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "packet_hash": _identity(body)}


def verify_observation_packet(
    root: str | os.PathLike[str],
    packet: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify packet integrity, current source binding, and presented bytes."""
    if not isinstance(packet, Mapping):
        raise ObservationPacketError("observation packet must be a mapping")
    candidate = dict(packet)
    supplied_hash = candidate.pop("packet_hash", None)
    if not isinstance(supplied_hash, str) or supplied_hash != _identity(candidate):
        raise ObservationPacketError("packet hash mismatch")
    if candidate.get("type") != OBSERVATION_TYPE:
        raise ObservationPacketError("unsupported observation packet type")
    if candidate.get("version") != OBSERVATION_VERSION:
        raise ObservationPacketError("unsupported observation packet version")
    relative = _normalize_path(candidate.get("path", ""))
    if relative != candidate["path"]:
        raise ObservationPacketError("observation packet path is invalid")
    root_path, source = _source(root, relative)

    receipt_value = candidate.get("presentation_receipt")
    if not isinstance(receipt_value, Mapping):
        raise ObservationPacketError("presentation receipt is missing")
    try:
        receipt = verify_presentation_receipt(root_path, receipt_value)
    except PresentationReceiptError as exc:
        raise ObservationPacketError(str(exc)) from exc
    if (
        receipt["path"] != relative
        or candidate.get("source_size") != receipt["source_size"]
        or candidate.get("source_sha256") != receipt["source_sha256"]
    ):
        raise ObservationPacketError("source identity mismatch")
    if candidate.get("content_encoding") != "base64":
        raise ObservationPacketError("unsupported content encoding")
    encoded = candidate.get("content_base64")
    if not isinstance(encoded, str):
        raise ObservationPacketError("content_base64 must be a string")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ObservationPacketError("content_base64 is invalid") from exc
    if candidate.get("content_sha256") != hashlib.sha256(content).hexdigest():
        raise ObservationPacketError("presented content hash mismatch")

    presented = candidate.get("presented_range")
    if receipt["source_size"] == 0:
        if presented is not None or content:
            raise ObservationPacketError("empty source presentation is invalid")
        expected = b""
    else:
        if not isinstance(presented, Mapping) or set(presented) != {"start", "end"}:
            raise ObservationPacketError("presented range is invalid")
        start, end = presented["start"], presented["end"]
        if type(start) is not int or type(end) is not int or not 0 <= start < end:
            raise ObservationPacketError("presented range bounds are invalid")
        expected = _read_range(source, start, end)
        matching = [
            entry
            for entry in receipt["presented_ranges"]
            if entry["start"] == start and entry["end"] == end
        ]
        if len(matching) != 1:
            raise ObservationPacketError("presented range is absent from receipt")
    if content != expected:
        raise ObservationPacketError("presented content mismatch")
    if candidate.get("utf8_text") != _utf8_text(content):
        raise ObservationPacketError("UTF-8 preview mismatch")
    expected_next = (
        receipt["unpresented_ranges"][0]["start"]
        if receipt["unpresented_ranges"]
        else None
    )
    if candidate.get("next_offset") != expected_next:
        raise ObservationPacketError("next offset mismatch")
    for field in (
        "semantic_inspection_claimed",
        "semantic_understanding_claimed",
        "accepted",
        "truth_claimed",
    ):
        if candidate.get(field) is not False:
            raise ObservationPacketError(f"{field} must remain false")
    for field in ("write_authority", "execution_authority"):
        if candidate.get(field) != "NONE":
            raise ObservationPacketError(f"{field} must remain NONE")
    return {**candidate, "packet_hash": supplied_hash}


def _load_prior(path: str | os.PathLike[str], root: str, source_path: str) -> dict[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ObservationPacketError(
            f"unable to load prior evidence: {source}: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(value, dict):
        raise ObservationPacketError("prior evidence must contain a JSON object")
    if value.get("type") == OBSERVATION_TYPE:
        return verify_observation_packet(root, value)["presentation_receipt"]
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sim inspect",
        description="Present an exact bounded file range without claiming meaning.",
    )
    parser.add_argument("root", help="Environment directory")
    parser.add_argument("path", help="Relative source path")
    parser.add_argument("--start", type=int, default=None)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--prior", help="Prior observation packet or receipt JSON")
    return parser


def _error_packet(error: Exception) -> dict[str, Any]:
    return {
        "type": "simulation_observation_error",
        "version": OBSERVATION_VERSION,
        "error": str(error),
        "semantic_inspection_claimed": False,
        "semantic_understanding_claimed": False,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        prior = (
            _load_prior(args.prior, args.root, args.path)
            if args.prior
            else None
        )
        packet = build_observation_packet(
            args.root,
            args.path,
            start=args.start,
            max_bytes=args.max_bytes,
            prior_receipt=prior,
        )
    except (ObservationPacketError, PresentationReceiptError, TypeError) as exc:
        print(json.dumps(_error_packet(exc), sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(packet, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


__all__ = [
    "DEFAULT_MAX_BYTES",
    "OBSERVATION_TYPE",
    "OBSERVATION_VERSION",
    "ObservationPacketError",
    "build_observation_packet",
    "main",
    "verify_observation_packet",
]
