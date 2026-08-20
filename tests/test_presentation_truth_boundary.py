import json

import sim

from sim.environment_coverage import observe_environment
from sim.environment_monitor import build_monitor_packet
from sim.observation_packets import build_observation_packet
from sim.presentation_receipts import (
    create_presentation_receipt,
    verify_presentation_receipt,
)


def all_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from all_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from all_keys(nested)


def test_receipt_proves_presentation_without_claiming_inspection(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")

    receipt = create_presentation_receipt(
        root,
        "source.txt",
        method="bounded-presentation-v1",
        presented_ranges=[(0, 6)],
    )

    assert receipt["type"] == "simulation_file_presentation_receipt"
    assert receipt["presented_byte_count"] == 6
    assert receipt["complete_byte_presentation"] is True
    assert receipt["semantic_inspection_claimed"] is False
    assert receipt["semantic_understanding_claimed"] is False
    assert not any("inspection" in key for key in all_keys(receipt) if key != "semantic_inspection_claimed")
    assert verify_presentation_receipt(root, receipt) == receipt


def test_environment_reports_presentation_not_inherited_inspection(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")
    receipt = create_presentation_receipt(
        root,
        "source.txt",
        method="bounded-presentation-v1",
        presented_ranges=[(0, 6)],
    )

    coverage = observe_environment(root, presentation_receipts=[receipt])

    assert coverage["files"][0]["presentation_status"] == "PRESENTED"
    assert coverage["files"][0]["presentation_receipt_hash"] == receipt[
        "receipt_hash"
    ]
    assert coverage["presented_file_count"] == 1
    assert coverage["unpresented_file_count"] == 0
    assert coverage["byte_presentation_complete"] is True
    assert coverage["semantic_inspection_claimed"] is False
    assert coverage["semantic_understanding_claimed"] is False
    assert "inspection_status" not in coverage["files"][0]
    assert "inspected_file_count" not in coverage


def test_unseen_monitor_boundary_is_unpresented(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")

    packet = build_monitor_packet(root)

    assert packet["next_boundary"] == {
        "path": "source.txt",
        "reason": "UNPRESENTED",
    }
    assert packet["semantic_inspection_claimed"] is False
    assert packet["semantic_understanding_claimed"] is False


def test_observation_packet_accumulates_presentation_evidence(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"abcdefgh")

    first = build_observation_packet(root, "source.txt", max_bytes=4)
    second = build_observation_packet(
        root,
        "source.txt",
        max_bytes=4,
        prior_receipt=first["presentation_receipt"],
    )

    assert "inspection_receipt" not in first
    assert first["presentation_receipt"]["complete_byte_presentation"] is False
    assert second["presentation_receipt"]["complete_byte_presentation"] is True
    assert second["semantic_inspection_claimed"] is False
    assert second["semantic_understanding_claimed"] is False


def test_public_package_does_not_export_legacy_inspection_claims():
    assert hasattr(sim, "create_presentation_receipt")
    assert hasattr(sim, "verify_presentation_receipt")
    assert not hasattr(sim, "create_inspection_receipt")
    assert not hasattr(sim, "verify_inspection_receipt")
    assert "inspection_receipts" not in json.dumps(sorted(sim.__all__))