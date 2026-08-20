import hashlib
import json
from pathlib import Path

import pytest

from sim.environment_coverage import (
    EnvironmentCoverageError,
    compare_environment_receipts,
    observe_environment,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_environment(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "src" / "engine.py").write_text(
        "STATE = 'bounded'\n",
        encoding="utf-8",
    )
    (root / "docs" / "design.md").write_text(
        "# Design\n",
        encoding="utf-8",
    )
    (root / "asset.bin").write_bytes(b"\x00\x01\xff")


def test_observation_is_deterministic_and_bounded(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    first = observe_environment(root)
    second = observe_environment(root)

    assert first == second
    assert first["type"] == "simulation_environment_coverage"
    assert first["version"] == 1
    assert first["root"] == "."
    assert first["observed_file_count"] == 3
    assert first["inspected_file_count"] == 0
    assert first["uninspected_file_count"] == 3
    assert first["coverage_complete"] is False
    assert first["accepted"] is False
    assert first["truth_claimed"] is False
    assert first["write_authority"] == "NONE"
    assert first["execution_authority"] == "NONE"


def test_observation_hashes_binary_files_without_decoding(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    receipt = observe_environment(root)
    files = {entry["path"]: entry for entry in receipt["files"]}

    assert list(files) == [
        "asset.bin",
        "docs/design.md",
        "src/engine.py",
    ]
    assert files["asset.bin"] == {
        "path": "asset.bin",
        "size": 3,
        "sha256": digest(b"\x00\x01\xff"),
        "inspection_status": "UNINSPECTED",
    }


def test_inspection_is_explicit_and_does_not_follow_from_observation(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    receipt = observe_environment(
        root,
        inspected_paths=["docs/design.md", "src/engine.py"],
    )
    files = {entry["path"]: entry for entry in receipt["files"]}

    assert files["asset.bin"]["inspection_status"] == "UNINSPECTED"
    assert files["docs/design.md"]["inspection_status"] == "INSPECTED"
    assert files["src/engine.py"]["inspection_status"] == "INSPECTED"
    assert receipt["inspected_file_count"] == 2
    assert receipt["uninspected_file_count"] == 1
    assert receipt["coverage_complete"] is False


def test_complete_coverage_requires_every_observed_file_to_be_declared_inspected(
    tmp_path,
):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    receipt = observe_environment(
        root,
        inspected_paths=[
            "asset.bin",
            "docs/design.md",
            "src/engine.py",
        ],
    )

    assert receipt["coverage_complete"] is True
    assert receipt["inspected_file_count"] == 3
    assert receipt["uninspected_file_count"] == 0
    assert receipt["accepted"] is False
    assert receipt["write_authority"] == "NONE"


def test_exclusions_are_visible_in_the_receipt(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    (root / ".git").mkdir()
    (root / ".git" / "index").write_bytes(b"ignored")
    (root / "cache").mkdir()
    (root / "cache" / "derived.bin").write_bytes(b"derived")

    receipt = observe_environment(
        root,
        excluded_paths=[".git", "cache"],
    )

    assert receipt["excluded_paths"] == [".git", "cache"]
    assert [entry["path"] for entry in receipt["files"]] == [
        "asset.bin",
        "docs/design.md",
        "src/engine.py",
    ]
    assert receipt["coverage_complete"] is False


def test_receipt_identity_covers_the_bounded_body(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    receipt = observe_environment(root)
    body = dict(receipt)
    receipt_hash = body.pop("receipt_hash")
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    assert receipt_hash == digest(encoded)


def test_comparison_reports_added_removed_modified_and_unchanged(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    before = observe_environment(root)

    (root / "asset.bin").unlink()
    (root / "docs" / "design.md").write_text(
        "# Revised design\n",
        encoding="utf-8",
    )
    (root / "new.txt").write_text("new\n", encoding="utf-8")
    after = observe_environment(root)

    comparison = compare_environment_receipts(before, after)

    assert comparison["added"] == ["new.txt"]
    assert comparison["removed"] == ["asset.bin"]
    assert comparison["modified"] == ["docs/design.md"]
    assert comparison["unchanged"] == ["src/engine.py"]
    assert comparison["changed"] is True
    assert comparison["accepted"] is False
    assert comparison["write_authority"] == "NONE"


def test_comparison_of_same_receipt_has_no_change(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    receipt = observe_environment(root)

    comparison = compare_environment_receipts(receipt, receipt)

    assert comparison["added"] == []
    assert comparison["removed"] == []
    assert comparison["modified"] == []
    assert comparison["unchanged"] == [
        "asset.bin",
        "docs/design.md",
        "src/engine.py",
    ]
    assert comparison["changed"] is False


@pytest.mark.parametrize(
    "inspected_path",
    ["missing.txt", "../outside.txt", "/absolute.txt", "src/../asset.bin"],
)
def test_invalid_inspected_paths_are_rejected(tmp_path, inspected_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)

    with pytest.raises(EnvironmentCoverageError):
        observe_environment(root, inspected_paths=[inspected_path])


def test_missing_or_non_directory_roots_are_rejected(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("not a directory", encoding="utf-8")

    with pytest.raises(EnvironmentCoverageError, match="existing directory"):
        observe_environment(tmp_path / "missing")
    with pytest.raises(EnvironmentCoverageError, match="existing directory"):
        observe_environment(file_path)


def test_comparison_rejects_tampered_receipts(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    build_environment(root)
    receipt = observe_environment(root)
    tampered = json.loads(json.dumps(receipt))
    tampered["files"][0]["size"] += 1

    with pytest.raises(EnvironmentCoverageError, match="receipt hash mismatch"):
        compare_environment_receipts(receipt, tampered)