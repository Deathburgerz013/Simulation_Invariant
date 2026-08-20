import hashlib
import json
from pathlib import Path

import pytest

from sim.__main__ import main as package_main
from sim.environment_coverage import observe_environment
from sim.environment_monitor import (
    MONITOR_TYPE,
    MonitorError,
    build_monitor_packet,
    main as monitor_main,
)
from sim.presentation_receipts import create_presentation_receipt


def canonical_hash(value: dict) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_environment(root: Path) -> None:
    (root / "a.txt").write_bytes(b"alpha")
    (root / "b.txt").write_bytes(b"beta")


def present(root: Path, path: str, end: int) -> dict:
    return create_presentation_receipt(
        root,
        path,
        method="bounded-byte-review-v1",
        presented_ranges=[] if end == 0 else [(0, end)],
    )


def snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_monitor_exposes_unseen_state_and_next_boundary(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    packet = build_monitor_packet(root)

    assert packet["type"] == MONITOR_TYPE
    assert packet["version"] == 1
    assert packet["coverage"]["observed_file_count"] == 2
    assert packet["coverage"]["byte_presentation_complete"] is False
    assert packet["unresolved_boundaries"] == [
        {"path": "a.txt", "reason": "UNPRESENTED"},
        {"path": "b.txt", "reason": "UNPRESENTED"},
    ]
    assert packet["next_boundary"] == {
        "path": "a.txt",
        "reason": "UNPRESENTED",
    }
    assert packet["comparison"] is None
    assert packet["semantic_understanding_claimed"] is False
    assert packet["accepted"] is False
    assert packet["truth_claimed"] is False
    assert packet["write_authority"] == "NONE"
    assert packet["execution_authority"] == "NONE"

    body = dict(packet)
    monitor_hash = body.pop("monitor_hash")
    assert monitor_hash == canonical_hash(body)


def test_monitor_is_deterministic_and_read_only(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    before = snapshot(root)

    first = build_monitor_packet(root)
    second = build_monitor_packet(root)

    assert first == second
    assert snapshot(root) == before


def test_monitor_uses_current_complete_presentation_receipts(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    receipts = [present(root, "a.txt", 5), present(root, "b.txt", 4)]

    packet = build_monitor_packet(root, presentation_receipts=receipts)

    assert packet["coverage"]["byte_presentation_complete"] is True
    assert packet["unresolved_boundaries"] == []
    assert packet["next_boundary"] is None
    assert packet["semantic_understanding_claimed"] is False


def test_monitor_prioritizes_stale_then_partial_then_unpresented(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "a-stale.txt").write_bytes(b"stale")
    (root / "b-partial.txt").write_bytes(b"partial")
    (root / "c-unseen.txt").write_bytes(b"unseen")
    stale = present(root, "a-stale.txt", 5)
    partial = create_presentation_receipt(
        root,
        "b-partial.txt",
        method="bounded-byte-review-v1",
        presented_ranges=[(0, 3)],
    )
    (root / "a-stale.txt").write_bytes(b"changed")

    packet = build_monitor_packet(
        root,
        presentation_receipts=[partial, stale],
    )

    assert packet["unresolved_boundaries"] == [
        {"path": "a-stale.txt", "reason": "STALE"},
        {"path": "b-partial.txt", "reason": "PARTIAL"},
        {"path": "c-unseen.txt", "reason": "UNPRESENTED"},
    ]
    assert packet["next_boundary"] == {
        "path": "a-stale.txt",
        "reason": "STALE",
    }


def test_monitor_compares_against_verified_baseline(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    baseline = observe_environment(root)
    (root / "a.txt").write_bytes(b"revised")
    (root / "c.txt").write_bytes(b"new")

    packet = build_monitor_packet(root, baseline=baseline)

    assert packet["comparison"]["added"] == ["c.txt"]
    assert packet["comparison"]["removed"] == []
    assert packet["comparison"]["modified"] == ["a.txt"]
    assert packet["comparison"]["unchanged"] == ["b.txt"]
    assert packet["comparison"]["changed"] is True


def test_monitor_rejects_noncoverage_baseline(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    with pytest.raises(MonitorError, match="baseline"):
        build_monitor_packet(root, baseline={"type": "wrong"})


def test_monitor_cli_prints_one_json_packet_without_mutation(tmp_path, capsys):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    before = snapshot(root)

    result = monitor_main([str(root)])

    captured = capsys.readouterr()
    packet = json.loads(captured.out)
    assert result == 0
    assert captured.err == ""
    assert packet["type"] == MONITOR_TYPE
    assert packet["next_boundary"]["path"] == "a.txt"
    assert snapshot(root) == before


def test_package_entrypoint_dispatches_monitor_command(tmp_path, capsys):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    result = package_main(["monitor", str(root)])

    captured = capsys.readouterr()
    assert result == 0
    assert json.loads(captured.out)["type"] == MONITOR_TYPE


def test_cli_loads_receipts_and_baseline_from_outside_environment(
    tmp_path,
    capsys,
):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    baseline = observe_environment(root)
    receipt = present(root, "a.txt", 5)
    baseline_path = tmp_path / "baseline.json"
    receipt_path = tmp_path / "receipt.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = monitor_main(
        [
            str(root),
            "--baseline",
            str(baseline_path),
            "--presentation-receipt",
            str(receipt_path),
        ]
    )

    packet = json.loads(capsys.readouterr().out)
    assert result == 0
    assert packet["coverage"]["presented_file_count"] == 1
    assert packet["comparison"]["changed"] is False
    assert packet["next_boundary"] == {
        "path": "b.txt",
        "reason": "UNPRESENTED",
    }


def test_cli_reports_bounded_json_error(tmp_path, capsys):
    missing = tmp_path / "missing"

    result = monitor_main([str(missing)])

    captured = capsys.readouterr()
    error = json.loads(captured.err)
    assert result == 2
    assert captured.out == ""
    assert error["type"] == "simulation_monitor_error"
    assert error["accepted"] is False
    assert error["write_authority"] == "NONE"
    assert error["execution_authority"] == "NONE"
