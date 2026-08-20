"""Read-only situation packets composed from verified environment primitives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from sim.environment_coverage import (
    DEFAULT_EXCLUDED_PATHS,
    EnvironmentCoverageError,
    compare_environment_receipts,
    observe_environment,
)
from sim.inspection_receipts import InspectionReceiptError


MONITOR_TYPE = "simulation_environment_monitor"
MONITOR_VERSION = 1

_STATUS_PRIORITY = {
    "STALE": 0,
    "PARTIAL": 1,
    "UNINSPECTED": 2,
    "UNSUPPORTED": 3,
}


class MonitorError(ValueError):
    """Raised when a Monitor input cannot produce a bounded packet."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _identity(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _unresolved_boundaries(coverage: Mapping[str, Any]) -> list[dict[str, str]]:
    boundaries: list[dict[str, str]] = []
    for entry in coverage["files"]:
        status = entry["inspection_status"]
        if status != "INSPECTED":
            boundaries.append({"path": entry["path"], "reason": status})
    for entry in coverage["unsupported_entries"]:
        boundaries.append(
            {
                "path": entry["path"],
                "reason": f"UNSUPPORTED:{entry['reason']}",
            }
        )

    def sort_key(boundary: Mapping[str, str]) -> tuple[int, str, str]:
        category = boundary["reason"].split(":", 1)[0]
        return (
            _STATUS_PRIORITY.get(category, len(_STATUS_PRIORITY)),
            boundary["path"],
            boundary["reason"],
        )

    return sorted(boundaries, key=sort_key)


def build_monitor_packet(
    root: str | os.PathLike[str],
    *,
    inspection_receipts: Iterable[Mapping[str, Any]] = (),
    baseline: Mapping[str, Any] | None = None,
    excluded_paths: Iterable[str | os.PathLike[str]] = DEFAULT_EXCLUDED_PATHS,
) -> dict[str, Any]:
    """Build a deterministic read-only packet for the present environment."""
    coverage = observe_environment(
        root,
        excluded_paths=excluded_paths,
        inspection_receipts=inspection_receipts,
    )
    comparison: dict[str, Any] | None = None
    if baseline is not None:
        if not isinstance(baseline, Mapping):
            raise MonitorError("baseline must be a coverage receipt mapping")
        try:
            comparison = compare_environment_receipts(baseline, coverage)
        except EnvironmentCoverageError as exc:
            raise MonitorError(f"baseline coverage receipt is invalid: {exc}") from exc

    unresolved = _unresolved_boundaries(coverage)
    body: dict[str, Any] = {
        "type": MONITOR_TYPE,
        "version": MONITOR_VERSION,
        "coverage": coverage,
        "comparison": comparison,
        "unresolved_boundaries": unresolved,
        "next_boundary": unresolved[0] if unresolved else None,
        "semantic_understanding_claimed": False,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "monitor_hash": _identity(body)}


def _load_json_mapping(path: str | os.PathLike[str], *, label: str) -> dict[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MonitorError(
            f"unable to load {label}: {source}: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(value, dict):
        raise MonitorError(f"{label} must contain a JSON object")
    return value


def _error_packet(error: Exception) -> dict[str, Any]:
    return {
        "type": "simulation_monitor_error",
        "version": MONITOR_VERSION,
        "error": str(error),
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sim monitor",
        description="Emit a deterministic read-only environment situation packet.",
    )
    parser.add_argument("root", help="Environment directory to observe")
    parser.add_argument(
        "--inspection-receipt",
        action="append",
        default=[],
        metavar="PATH",
        help="Hash-bound inspection receipt JSON; may be repeated",
    )
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="Prior environment coverage receipt JSON",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="RELATIVE_PATH",
        help="Excluded relative path; may be repeated",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only Monitor CLI."""
    try:
        args = _parser().parse_args(argv)
        receipts = [
            _load_json_mapping(path, label="inspection receipt")
            for path in args.inspection_receipt
        ]
        baseline = (
            _load_json_mapping(args.baseline, label="baseline")
            if args.baseline
            else None
        )
        exclusions = (
            args.exclude
            if args.exclude is not None
            else DEFAULT_EXCLUDED_PATHS
        )
        packet = build_monitor_packet(
            args.root,
            inspection_receipts=receipts,
            baseline=baseline,
            excluded_paths=exclusions,
        )
    except (
        EnvironmentCoverageError,
        InspectionReceiptError,
        MonitorError,
        TypeError,
    ) as exc:
        print(
            json.dumps(_error_packet(exc), sort_keys=True),
            file=sys.stderr,
        )
        return 2

    print(json.dumps(packet, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


__all__ = [
    "MONITOR_TYPE",
    "MONITOR_VERSION",
    "MonitorError",
    "build_monitor_packet",
    "main",
]