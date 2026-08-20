"""Read-only, deterministic coverage receipts for a filesystem environment."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from sim.inspection_receipts import (
    InspectionReceiptError,
    assess_inspection_receipt,
)


RECEIPT_TYPE = "simulation_environment_coverage"
COMPARISON_TYPE = "simulation_environment_coverage_comparison"
FORMAT_VERSION = 1
DEFAULT_EXCLUDED_PATHS = (".git",)

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class EnvironmentCoverageError(ValueError):
    """Raised when an environment or coverage receipt is invalid."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _identity(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


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
        raise EnvironmentCoverageError(
            f"unable to observe file: {path.name}: {exc.__class__.__name__}"
        ) from exc
    return size, digest.hexdigest()


def _normalize_relative_path(value: str | os.PathLike[str], *, label: str) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw:
        raise EnvironmentCoverageError(f"{label} must be a non-empty relative path")

    candidate = raw.replace("\\", "/")
    path = PurePosixPath(candidate)
    if (
        path.is_absolute()
        or _WINDOWS_DRIVE.match(candidate)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise EnvironmentCoverageError(
            f"{label} must be a normalized relative path: {raw}"
        )
    return path.as_posix()


def _normalize_paths(
    values: Iterable[str | os.PathLike[str]],
    *,
    label: str,
) -> list[str]:
    normalized = {
        _normalize_relative_path(value, label=label)
        for value in values
    }
    return sorted(normalized)


def _is_excluded(path: str, exclusions: Sequence[str]) -> bool:
    return any(path == item or path.startswith(item + "/") for item in exclusions)


def _iter_environment_entries(
    root: Path,
    exclusions: Sequence[str],
) -> tuple[list[Path], list[dict[str, str]]]:
    files: list[Path] = []
    unsupported: list[dict[str, str]] = []

    def visit(directory: Path) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            relative = directory.relative_to(root).as_posix() or "."
            unsupported.append(
                {
                    "path": relative,
                    "reason": f"DIRECTORY_UNREADABLE:{exc.__class__.__name__}",
                }
            )
            return

        for child in children:
            relative = child.relative_to(root).as_posix()
            if _is_excluded(relative, exclusions):
                continue
            if child.is_symlink():
                unsupported.append({"path": relative, "reason": "SYMLINK"})
                continue
            try:
                if child.is_dir():
                    visit(child)
                elif child.is_file():
                    files.append(child)
                else:
                    unsupported.append(
                        {"path": relative, "reason": "NON_REGULAR_ENTRY"}
                    )
            except OSError as exc:
                unsupported.append(
                    {
                        "path": relative,
                        "reason": f"ENTRY_UNREADABLE:{exc.__class__.__name__}",
                    }
                )

    visit(root)
    return files, sorted(unsupported, key=lambda item: item["path"])


def observe_environment(
    root: str | os.PathLike[str],
    *,
    inspected_paths: Iterable[str | os.PathLike[str]] = (),
    excluded_paths: Iterable[str | os.PathLike[str]] = DEFAULT_EXCLUDED_PATHS,
    inspection_receipts: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Observe regular files without changing the environment.

    Byte observation does not imply semantic inspection. A caller must name
    every semantically inspected path explicitly.
    """
    root_path = Path(root)
    if not root_path.exists() or not root_path.is_dir():
        raise EnvironmentCoverageError("root must be an existing directory")
    if root_path.is_symlink():
        raise EnvironmentCoverageError("root must not be a symbolic link")

    exclusions = _normalize_paths(excluded_paths, label="excluded path")
    inspected = _normalize_paths(inspected_paths, label="inspected path")
    if inspected:
        raise EnvironmentCoverageError(
            "inspected_paths cannot establish coverage; supply hash-bound "
            "inspection_receipts"
        )

    source_files, unsupported = _iter_environment_entries(root_path, exclusions)
    observed_paths = {
        path.relative_to(root_path).as_posix()
        for path in source_files
    }
    receipts_by_path: dict[str, tuple[dict[str, Any], str]] = {}
    stale_receipts: list[str] = []
    for supplied_receipt in inspection_receipts:
        verified_receipt, state = assess_inspection_receipt(
            root_path,
            supplied_receipt,
        )
        receipt_path = verified_receipt["path"]
        if receipt_path not in observed_paths:
            raise InspectionReceiptError(
                f"receipt path was not observed: {receipt_path}"
            )
        if receipt_path in receipts_by_path:
            raise InspectionReceiptError(
                f"multiple inspection receipts supplied for path: {receipt_path}"
            )
        receipts_by_path[receipt_path] = (verified_receipt, state)
        if state == "STALE":
            stale_receipts.append(verified_receipt["receipt_hash"])

    files: list[dict[str, Any]] = []
    for path in source_files:
        relative = path.relative_to(root_path).as_posix()
        size, sha256 = _file_identity(path)
        entry: dict[str, Any] = {
            "path": relative,
            "size": size,
            "sha256": sha256,
            "inspection_status": "UNINSPECTED",
        }
        receipt_state = receipts_by_path.get(relative)
        if receipt_state is not None:
            inspection_receipt, state = receipt_state
            entry["inspection_receipt_hash"] = inspection_receipt["receipt_hash"]
            if state == "STALE":
                entry["inspection_status"] = "STALE"
            elif inspection_receipt["complete_byte_coverage"]:
                entry["inspection_status"] = "INSPECTED"
            else:
                entry["inspection_status"] = "PARTIAL"
        files.append(entry)
    files.sort(key=lambda item: item["path"])

    inspected_count = sum(
        entry["inspection_status"] == "INSPECTED"
        for entry in files
    )
    uninspected_count = len(files) - inspected_count
    body: dict[str, Any] = {
        "type": RECEIPT_TYPE,
        "version": FORMAT_VERSION,
        "root": ".",
        "files": files,
        "observed_file_count": len(files),
        "inspected_file_count": inspected_count,
        "uninspected_file_count": uninspected_count,
        "excluded_paths": exclusions,
        "unsupported_entries": unsupported,
        "stale_inspection_receipts": sorted(stale_receipts),
        "coverage_complete": (
            uninspected_count == 0
            and not unsupported
            and not stale_receipts
        ),
        "semantic_understanding_claimed": False,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "receipt_hash": _identity(body)}


def _verified_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise EnvironmentCoverageError("coverage receipt must be a mapping")
    candidate = dict(receipt)
    supplied_hash = candidate.pop("receipt_hash", None)
    if not isinstance(supplied_hash, str) or supplied_hash != _identity(candidate):
        raise EnvironmentCoverageError("receipt hash mismatch")
    if candidate.get("type") != RECEIPT_TYPE:
        raise EnvironmentCoverageError("unsupported coverage receipt type")
    if candidate.get("version") != FORMAT_VERSION:
        raise EnvironmentCoverageError("unsupported coverage receipt version")
    files = candidate.get("files")
    if not isinstance(files, list):
        raise EnvironmentCoverageError("coverage receipt files must be a list")

    previous = ""
    for entry in files:
        if not isinstance(entry, Mapping):
            raise EnvironmentCoverageError("coverage file entry must be a mapping")
        path = entry.get("path")
        if not isinstance(path, str):
            raise EnvironmentCoverageError("coverage file path must be a string")
        normalized = _normalize_relative_path(path, label="coverage file path")
        if normalized != path or path <= previous:
            raise EnvironmentCoverageError(
                "coverage file paths must be unique and sorted"
            )
        if type(entry.get("size")) is not int or entry["size"] < 0:
            raise EnvironmentCoverageError("coverage file size must be non-negative")
        sha256 = entry.get("sha256")
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise EnvironmentCoverageError("coverage file hash is invalid")
        previous = path
    return {**candidate, "receipt_hash": supplied_hash}


def compare_environment_receipts(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare two verified observations without granting acceptance."""
    verified_before = _verified_receipt(before)
    verified_after = _verified_receipt(after)
    before_files = {
        entry["path"]: entry
        for entry in verified_before["files"]
    }
    after_files = {
        entry["path"]: entry
        for entry in verified_after["files"]
    }

    before_paths = set(before_files)
    after_paths = set(after_files)
    shared = before_paths & after_paths
    modified = sorted(
        path
        for path in shared
        if (
            before_files[path]["size"],
            before_files[path]["sha256"],
        )
        != (
            after_files[path]["size"],
            after_files[path]["sha256"],
        )
    )
    unchanged = sorted(shared - set(modified))
    added = sorted(after_paths - before_paths)
    removed = sorted(before_paths - after_paths)

    body: dict[str, Any] = {
        "type": COMPARISON_TYPE,
        "version": FORMAT_VERSION,
        "before_receipt_hash": verified_before["receipt_hash"],
        "after_receipt_hash": verified_after["receipt_hash"],
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
        "changed": bool(added or removed or modified),
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "comparison_hash": _identity(body)}


__all__ = [
    "COMPARISON_TYPE",
    "DEFAULT_EXCLUDED_PATHS",
    "EnvironmentCoverageError",
    "FORMAT_VERSION",
    "RECEIPT_TYPE",
    "compare_environment_receipts",
    "observe_environment",
]