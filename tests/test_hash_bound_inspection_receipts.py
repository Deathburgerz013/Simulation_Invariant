import hashlib
import json

import pytest

from sim.environment_coverage import observe_environment
from sim.inspection_receipts import (
    InspectionReceiptError,
    create_inspection_receipt,
    verify_inspection_receipt,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: dict) -> str:
    return digest(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )


def test_complete_receipt_binds_every_covered_byte(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    source = root / "design.txt"
    source.write_bytes(b"alpha\nbeta\n")

    receipt = create_inspection_receipt(
        root,
        "design.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 6), (6, 11)],
    )

    assert receipt["type"] == "simulation_file_inspection_receipt"
    assert receipt["version"] == 1
    assert receipt["path"] == "design.txt"
    assert receipt["source_size"] == 11
    assert receipt["source_sha256"] == digest(b"alpha\nbeta\n")
    assert receipt["covered_ranges"] == [
        {"start": 0, "end": 6, "sha256": digest(b"alpha\n")},
        {"start": 6, "end": 11, "sha256": digest(b"beta\n")},
    ]
    assert receipt["covered_byte_count"] == 11
    assert receipt["complete_byte_coverage"] is True
    assert receipt["semantic_understanding_claimed"] is False
    assert receipt["accepted"] is False
    assert receipt["truth_claimed"] is False
    assert receipt["write_authority"] == "NONE"
    assert receipt["execution_authority"] == "NONE"

    body = dict(receipt)
    receipt_hash = body.pop("receipt_hash")
    assert receipt_hash == canonical_hash(body)
    assert verify_inspection_receipt(root, receipt) == receipt


def test_partial_receipt_preserves_uncovered_ranges(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "large.bin").write_bytes(b"0123456789")

    receipt = create_inspection_receipt(
        root,
        "large.bin",
        method="bounded-byte-review-v1",
        covered_ranges=[(2, 5), (7, 10)],
    )

    assert receipt["covered_byte_count"] == 6
    assert receipt["complete_byte_coverage"] is False
    assert receipt["uncovered_ranges"] == [
        {"start": 0, "end": 2},
        {"start": 5, "end": 7},
    ]
    assert verify_inspection_receipt(root, receipt) == receipt


def test_empty_file_can_have_complete_byte_coverage(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "empty.txt").write_bytes(b"")

    receipt = create_inspection_receipt(
        root,
        "empty.txt",
        method="empty-file-observation-v1",
        covered_ranges=[],
    )

    assert receipt["source_size"] == 0
    assert receipt["covered_ranges"] == []
    assert receipt["uncovered_ranges"] == []
    assert receipt["complete_byte_coverage"] is True


@pytest.mark.parametrize(
    "ranges",
    [
        [(-1, 1)],
        [(0, 0)],
        [(0, 11)],
        [(4, 2)],
        [(0, 5), (4, 6)],
        [(5, 6), (0, 1)],
        [(True, 2)],
        [(0, "2")],
    ],
)
def test_invalid_coverage_ranges_are_rejected(tmp_path, ranges):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.bin").write_bytes(b"0123456789")

    with pytest.raises(InspectionReceiptError):
        create_inspection_receipt(
            root,
            "source.bin",
            method="bounded-byte-review-v1",
            covered_ranges=ranges,
        )


@pytest.mark.parametrize(
    "path",
    ["missing.txt", "../outside.txt", "/absolute.txt", "a/../source.txt"],
)
def test_invalid_source_paths_are_rejected(tmp_path, path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_text("source", encoding="utf-8")

    with pytest.raises(InspectionReceiptError):
        create_inspection_receipt(
            root,
            path,
            method="bounded-byte-review-v1",
            covered_ranges=[],
        )


@pytest.mark.parametrize("method", ["", " ", 7, None])
def test_method_must_be_a_nonempty_string(tmp_path, method):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_text("source", encoding="utf-8")

    with pytest.raises(InspectionReceiptError, match="method"):
        create_inspection_receipt(
            root,
            "source.txt",
            method=method,
            covered_ranges=[(0, 6)],
        )


def test_tampered_receipt_is_rejected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")
    receipt = create_inspection_receipt(
        root,
        "source.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 6)],
    )
    tampered = json.loads(json.dumps(receipt))
    tampered["covered_ranges"][0]["sha256"] = "0" * 64

    with pytest.raises(InspectionReceiptError, match="receipt hash mismatch"):
        verify_inspection_receipt(root, tampered)


def test_receipt_becomes_stale_when_source_changes(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"source")
    receipt = create_inspection_receipt(
        root,
        "source.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 6)],
    )
    source.write_bytes(b"change")

    with pytest.raises(InspectionReceiptError, match="source identity mismatch"):
        verify_inspection_receipt(root, receipt)


def test_complete_current_receipt_marks_file_inspected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")
    receipt = create_inspection_receipt(
        root,
        "source.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 6)],
    )

    coverage = observe_environment(
        root,
        inspection_receipts=[receipt],
    )

    assert coverage["files"][0]["inspection_status"] == "INSPECTED"
    assert coverage["files"][0]["inspection_receipt_hash"] == receipt["receipt_hash"]
    assert coverage["inspected_file_count"] == 1
    assert coverage["uninspected_file_count"] == 0
    assert coverage["coverage_complete"] is True
    assert coverage["semantic_understanding_claimed"] is False


def test_partial_receipt_does_not_mark_file_inspected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")
    receipt = create_inspection_receipt(
        root,
        "source.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 3)],
    )

    coverage = observe_environment(
        root,
        inspection_receipts=[receipt],
    )

    assert coverage["files"][0]["inspection_status"] == "PARTIAL"
    assert coverage["inspected_file_count"] == 0
    assert coverage["uninspected_file_count"] == 1
    assert coverage["coverage_complete"] is False


def test_stale_receipt_is_exposed_without_aborting_observation(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"source")
    receipt = create_inspection_receipt(
        root,
        "source.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 6)],
    )
    source.write_bytes(b"changed")

    coverage = observe_environment(
        root,
        inspection_receipts=[receipt],
    )

    assert coverage["files"][0]["inspection_status"] == "STALE"
    assert coverage["inspected_file_count"] == 0
    assert coverage["coverage_complete"] is False
    assert coverage["stale_inspection_receipts"] == [receipt["receipt_hash"]]


def test_receipt_for_unobserved_file_is_rejected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    excluded = root / "excluded"
    excluded.mkdir()
    (excluded / "source.txt").write_bytes(b"source")
    receipt = create_inspection_receipt(
        root,
        "excluded/source.txt",
        method="bounded-byte-review-v1",
        covered_ranges=[(0, 6)],
    )

    with pytest.raises(
        InspectionReceiptError,
        match="receipt path was not observed",
    ):
        observe_environment(
            root,
            excluded_paths=[".git", "excluded"],
            inspection_receipts=[receipt],
        )
