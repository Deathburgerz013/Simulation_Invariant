#!/usr/bin/env python3
"""Candidate-only patch applicator tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("candidate patching requires POSIX APIs", allow_module_level=True)

from sim.bounded_candidate.patch import apply_candidate_patch
from sim.bounded_candidate.workspace import materialize_candidate
from sim.bounded_candidate.observer import FilesystemObserver, sha256_hex


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_regular_file_patch_applies() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        expected_tree = base / "expected"
        old = b"old-bytes\n"
        new = b"new-bytes\n"
        _write(source / "app.py", old)
        _write(source / "README.md", b"keep\n")
        _write(expected_tree / "app.py", new)
        _write(expected_tree / "README.md", b"keep\n")
        expected_hash = FilesystemObserver(expected_tree).observe_stable().manifest.tree_state_hash
        stable = FilesystemObserver(source).observe_stable()
        workspace = materialize_candidate(source, candidate, stable)
        source_manifest = workspace.bound_source_manifest_hash
        result = apply_candidate_patch(
            workspace.candidate_root,
            "app.py",
            new,
            sha256_hex(old),
            expected_hash,
        )
        assert result.status == "PATCH_APPLIED"
        assert result.approved_for_execution is True
        assert Path(result.candidate_root).joinpath("app.py").read_bytes() == new
        after = FilesystemObserver(source).observe_stable()
        assert after.manifest.manifest_hash == source_manifest


def test_patch_preserves_existing_executable_mode() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        expected_tree = base / "expected"
        old = b"#!/bin/sh\necho old\n"
        new = b"#!/bin/sh\necho new\n"
        _write(source / "tool.sh", old)
        _write(expected_tree / "tool.sh", new)
        os.chmod(source / "tool.sh", 0o755)
        os.chmod(expected_tree / "tool.sh", 0o755)
        stable = FilesystemObserver(source).observe_stable()
        workspace = materialize_candidate(source, candidate, stable)
        expected_hash = (
            FilesystemObserver(expected_tree).observe_stable().manifest.tree_state_hash
        )

        result = apply_candidate_patch(
            workspace.candidate_root,
            "tool.sh",
            new,
            sha256_hex(old),
            expected_hash,
        )

        assert result.status == "PATCH_APPLIED"
        assert os.lstat(Path(result.candidate_root) / "tool.sh").st_mode & 0o777 == 0o755


def test_symlink_target_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        outside = base / "outside.txt"
        outside.write_bytes(b"do-not-touch\n")
        source.mkdir()
        os.symlink(str(outside.resolve()), source / "app.py")
        _write(source / "README.md", b"keep\n")
        stable = FilesystemObserver(source).observe_stable()
        workspace = materialize_candidate(source, candidate, stable)
        source_manifest = workspace.bound_source_manifest_hash
        result = apply_candidate_patch(
            workspace.candidate_root,
            "app.py",
            b"patched\n",
            sha256_hex(b"ignored"),
            "0" * 64,
            discard_on_failure=True,
        )
        assert result.status == "PATCH_REJECTED"
        assert result.reason == "target_is_symlink"
        assert result.approved_for_execution is False
        assert outside.read_bytes() == b"do-not-touch\n"
        after = FilesystemObserver(source).observe_stable()
        assert after.manifest.manifest_hash == source_manifest


def test_symlinked_parent_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        outside_dir = base / "outside_dir"
        _write(outside_dir / "app.py", b"outside-app\n")
        source.mkdir()
        os.symlink(str(outside_dir.resolve()), source / "pkg")
        _write(source / "README.md", b"keep\n")
        stable = FilesystemObserver(source).observe_stable()
        workspace = materialize_candidate(source, candidate, stable)
        source_manifest = workspace.bound_source_manifest_hash
        result = apply_candidate_patch(
            workspace.candidate_root,
            "pkg/app.py",
            b"patched\n",
            sha256_hex(b"outside-app\n"),
            "0" * 64,
        )
        assert result.status == "PATCH_REJECTED"
        assert result.reason == "symlinked_parent"
        assert result.approved_for_execution is False
        assert (outside_dir / "app.py").read_bytes() == b"outside-app\n"
        after = FilesystemObserver(source).observe_stable()
        assert after.manifest.manifest_hash == source_manifest


def test_absolute_and_dotdot_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        _write(source / "app.py", b"x\n")
        stable = FilesystemObserver(source).observe_stable()
        workspace = materialize_candidate(source, candidate, stable)
        a = apply_candidate_patch(
            workspace.candidate_root,
            "/tmp/evil",
            b"x",
            sha256_hex(b"x\n"),
            "0" * 64,
            discard_on_failure=False,
        )
        assert a.status == "PATCH_REJECTED"
        assert a.reason == "absolute_path"
        b = apply_candidate_patch(
            workspace.candidate_root,
            "../app.py",
            b"x",
            sha256_hex(b"x\n"),
            "0" * 64,
            discard_on_failure=False,
        )
        assert b.status == "PATCH_REJECTED"
        assert b.reason == "path_escape"


def run_tests() -> None:
    test_regular_file_patch_applies()
    test_patch_preserves_existing_executable_mode()
    test_symlink_target_is_rejected()
    test_symlinked_parent_is_rejected()
    test_absolute_and_dotdot_rejected()
    print("candidate patch tests passed")


if __name__ == "__main__":
    run_tests()
