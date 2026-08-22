#!/usr/bin/env python3
"""Tests for tree/manifest hash split and disposable candidate workspace."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("candidate workspace requires POSIX APIs", allow_module_level=True)

from sim.bounded_candidate.workspace import materialize_candidate
from sim.bounded_candidate.observer import FilesystemObserver, ObservePolicy, sha256_hex


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_same_tree_different_roots_split_hashes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        a = base / "src_a"
        b = base / "src_b"
        for root in (a, b):
            _write(root / "app.py", b"print(1)\n")
            _write(root / "README.md", b"hi\n")
        ma = FilesystemObserver(a).observe_stable().manifest
        mb = FilesystemObserver(b).observe_stable().manifest
        assert ma.tree_state_hash == mb.tree_state_hash
        assert ma.manifest_hash != mb.manifest_hash
        assert ma.root != mb.root


def test_candidate_mutation_does_not_touch_source() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        original = b"def main():\n    print('hello')\n"
        _write(source / "app.py", original)
        _write(source / "README.md", b"keep\n")

        stable = FilesystemObserver(source).observe_stable()
        assert stable.stability == "STABLE"
        source_before = source.joinpath("app.py").read_bytes()
        source_manifest = stable.manifest.manifest_hash

        workspace = materialize_candidate(source, candidate, stable)
        assert workspace.bound_source_tree_state_hash == stable.manifest.tree_state_hash
        assert workspace.candidate_manifest.tree_state_hash == stable.manifest.tree_state_hash
        assert workspace.candidate_manifest.manifest_hash != source_manifest

        src_ino = os.lstat(source / "app.py").st_ino
        cand_ino = os.lstat(workspace.candidate_root / "app.py").st_ino
        assert src_ino != cand_ino

        (workspace.candidate_root / "app.py").write_bytes(b"changed\n")

        assert source.joinpath("app.py").read_bytes() == original
        assert source.joinpath("app.py").read_bytes() == source_before
        after = FilesystemObserver(source).observe_stable()
        assert after.stability == "STABLE"
        assert after.manifest.manifest_hash == source_manifest
        assert (source / "app.py").read_bytes() != (workspace.candidate_root / "app.py").read_bytes()


def test_source_change_during_copy_aborts(monkey_path: Path | None = None) -> None:
    """If source changes after the bound STABLE observation, materialize must abort.

    Simulated by binding an observation then mutating source before copy call
    is not quite during copy; the contract also reobserves after copy.
    Here we mutate source after a successful materialize is not the case—
    instead copy succeeds only if source still matches. We mutate source
    first so the post-copy reobserve fails... actually materialize copies
    current bytes. To test abort-on-source-change we need a change between
    bound observation and post-copy reobserve.

    Implemented by changing source after we already have STABLE, then calling
    materialize: copy will include new bytes, tree_state will not match bound
    source tree from the stale StableObservation.
    """
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        _write(source / "app.py", b"old\n")
        _write(source / "README.md", b"x\n")
        stable = FilesystemObserver(source).observe_stable()
        _write(source / "app.py", b"new\n")
        try:
            materialize_candidate(source, candidate, stable)
            raise AssertionError("expected CandidateError")
        except Exception as exc:
            assert "tree_state_hash" in str(exc) or "manifest" in str(exc) or "STABLE" in str(exc)
        assert not candidate.exists() or not any(candidate.iterdir())


def test_candidate_preserves_empty_directories_and_modes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = base / "source"
        candidate = base / "candidate"
        empty = source / "empty"
        empty.mkdir(parents=True)
        os.chmod(empty, 0o700)
        stable = FilesystemObserver(source).observe_stable()

        workspace = materialize_candidate(source, candidate, stable)

        copied = workspace.candidate_root / "empty"
        assert copied.is_dir()
        assert os.lstat(copied).st_mode & 0o777 == 0o700
        assert (
            workspace.candidate_manifest.tree_state_hash
            == stable.manifest.tree_state_hash
        )


def run_tests() -> None:
    test_same_tree_different_roots_split_hashes()
    test_candidate_mutation_does_not_touch_source()
    test_source_change_during_copy_aborts()
    test_candidate_preserves_empty_directories_and_modes()
    print("candidate workspace tests passed")


if __name__ == "__main__":
    run_tests()
