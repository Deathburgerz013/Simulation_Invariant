#!/usr/bin/env python3
"""Tests for the read-only filesystem observer."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("filesystem observer requires POSIX APIs", allow_module_level=True)

from sim.bounded_candidate.observer import FilesystemObserver, ObservePolicy, sha256_hex


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _tree_bytes(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                out[str(p.relative_to(root))] = os.readlink(p).encode()
            else:
                out[str(p.relative_to(root))] = p.read_bytes()
    return out


def test_same_tree_same_manifest_hash() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "app.py", b"print(1)\n")
        _write(root / "README.md", b"hi\n")
        a = FilesystemObserver(root).observe()
        b = FilesystemObserver(root).observe()
        assert a.coverage_complete is True
        assert a.status == "OK"
        assert a.manifest_hash == b.manifest_hash
        assert a.policy_hash == b.policy_hash


def test_one_byte_changes_manifest_hash() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "app.py", b"print(1)\n")
        before = FilesystemObserver(root).observe()
        _write(root / "app.py", b"print(2)\n")
        after = FilesystemObserver(root).observe()
        assert before.manifest_hash != after.manifest_hash
        hashes = {e.path: e.content_hash for e in after.entries}
        assert hashes["app.py"] == sha256_hex(b"print(2)\n")


def test_binary_without_decoding() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        payload = bytes(range(256)) + b"\x00\xff"
        _write(root / "blob.bin", payload)
        manifest = FilesystemObserver(root).observe()
        entry = next(e for e in manifest.entries if e.path == "blob.bin")
        assert entry.kind == "regular_file"
        assert entry.size == len(payload)
        assert entry.content_hash == sha256_hex(payload)


def test_parent_escape_cannot_enter_scope() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root = base / "root"
        outside = base / "outside.txt"
        root.mkdir()
        _write(outside, b"secret\n")
        _write(root / "app.py", b"ok\n")
        # A name that would be dangerous if joined naively and followed.
        # The observer must only walk from root.
        manifest = FilesystemObserver(root).observe()
        paths = [e.path for e in manifest.entries]
        assert "app.py" in paths
        assert all(".." not in p.split("/") for p in paths)
        assert not any(p.endswith("outside.txt") for p in paths)
        contents = [e.content_hash for e in manifest.entries]
        assert sha256_hex(b"secret\n") not in contents


def test_symlink_outside_recorded_or_rejected_never_followed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root = base / "root"
        root.mkdir()
        secret = base / "secret.bin"
        _write(secret, b"DO_NOT_HASH_ME")
        _write(root / "app.py", b"ok\n")
        link = root / "escape.link"
        os.symlink(str(secret), link)

        manifest = FilesystemObserver(root).observe()
        entry = next(e for e in manifest.entries if e.path == "escape.link")
        assert entry.kind == "symlink"
        assert entry.content_hash is None
        assert entry.link_target == str(secret)
        hashes = [e.content_hash for e in manifest.entries if e.content_hash]
        assert sha256_hex(b"DO_NOT_HASH_ME") not in hashes


def test_regular_file_swapped_to_symlink_is_not_followed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root = base / "root"
        root.mkdir()
        target = root / "live.txt"
        secret = base / "secret.txt"
        _write(target, b"ordinary")
        _write(secret, b"OUTSIDE-SECRET")

        def swap(rel: str, path: Path) -> None:
            if rel == "live.txt":
                path.unlink()
                os.symlink(secret, path)

        manifest = FilesystemObserver(root, mid_observe=swap).observe()
        assert manifest.status == "UNKNOWN"
        assert manifest.coverage_complete is False
        assert sha256_hex(b"OUTSIDE-SECRET") not in {
            entry.content_hash for entry in manifest.entries
        }


def test_different_exclusion_policies_differ() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "app.py", b"ok\n")
        _write(root / "skip" / "x.txt", b"nope\n")
        default = FilesystemObserver(root).observe()
        excluded = FilesystemObserver(
            root, policy=ObservePolicy(exclude_prefixes=("skip",))
        ).observe()
        assert default.policy_hash != excluded.policy_hash
        assert default.manifest_hash != excluded.manifest_hash
        assert any(e.path == "skip/x.txt" for e in default.entries)
        assert all(e.path != "skip/x.txt" for e in excluded.entries)


def test_change_during_observation_is_unknown() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "live.txt"
        _write(target, b"aaaa")

        def mutate(rel: str, path: Path) -> None:
            if rel == "live.txt":
                path.write_bytes(b"bbbbb")

        manifest = FilesystemObserver(root, mid_observe=mutate).observe()
        assert manifest.coverage_complete is False
        assert manifest.status == "UNKNOWN"
        assert "live.txt" in manifest.unstable_paths
        live = next(e for e in manifest.entries if e.path == "live.txt")
        assert live.content_hash is None


def test_quiet_tree_stabilizes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "a.txt", b"one\n")
        _write(root / "b.txt", b"two\n")
        result = FilesystemObserver(root).observe_stable()
        assert result.stability == "STABLE"
        assert result.manifest.status == "STABLE"
        assert result.passes_used >= 2
        assert result.manifest.coverage_complete is True


def test_stale_hash_never_stable_after_cross_file_mutation() -> None:
    """Mutate a.txt after its first-pass read while b.txt is being observed."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = b"old-a"
        updated = b"new-a-bytes"
        _write(root / "a.txt", original)
        _write(root / "b.txt", b"bbb")
        stale = sha256_hex(original)
        fresh = sha256_hex(updated)
        seen_a_on_pass1 = {"done": False}

        def after(rel: str, path: Path, pass_index: int) -> None:
            if pass_index == 1 and rel == "a.txt":
                seen_a_on_pass1["done"] = True
            if pass_index == 1 and rel == "b.txt" and seen_a_on_pass1["done"]:
                path.parent.joinpath("a.txt").write_bytes(updated)

        policy = ObservePolicy(max_observation_passes=3)
        result = FilesystemObserver(
            root, policy=policy, after_observe_leaf=after
        ).observe_stable()
        hashes = {e.path: e.content_hash for e in result.manifest.entries}
        if result.stability == "STABLE":
            assert hashes.get("a.txt") != stale
            assert hashes.get("a.txt") == fresh
        else:
            assert result.stability == "UNKNOWN"
            assert hashes.get("a.txt") != stale or result.manifest.coverage_complete is False


def test_stability_policy_is_bound() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "a.txt", b"x")
        a = ObservePolicy(max_observation_passes=3)
        b = ObservePolicy(max_observation_passes=4)
        assert a.policy_hash() != b.policy_hash()
        assert a.canonical()["stability_method"] == "consecutive-identical-manifests-v1"
        FilesystemObserver(root)  # bind root only


def test_fifo_is_never_opened_as_regular_file() -> None:
    import os
    import time

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fifo = root / "input.pipe"
        os.mkfifo(fifo)
        started = time.monotonic()
        result = FilesystemObserver(root).observe()
        elapsed = time.monotonic() - started
        assert elapsed < 2
        entry = next(e for e in result.entries if e.path == "input.pipe")
        assert entry.kind == "fifo"
        assert entry.content_hash is None


def test_permission_bits_are_in_tree_identity() -> None:
    import os

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "tool.py"
        _write(path, b"print(1)\n")
        os.chmod(path, 0o644)
        before = FilesystemObserver(root).observe()
        os.chmod(path, 0o755)
        after = FilesystemObserver(root).observe()
        assert before.tree_state_hash != after.tree_state_hash
        entry = next(e for e in after.entries if e.path == "tool.py")
        assert entry.mode == 0o755


def test_partial_read_never_claims_complete_identity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "a.bin", b"AAAAx")
        policy = ObservePolicy(max_read_bytes=4)
        first = FilesystemObserver(root, policy=policy).observe_stable()
        assert first.stability == "UNKNOWN"
        assert first.manifest.coverage_complete is False
        entry = next(e for e in first.manifest.entries if e.path == "a.bin")
        assert entry.content_complete is False

        _write(root / "a.bin", b"AAAAz")
        second = FilesystemObserver(root, policy=policy).observe_stable()
        assert second.stability == "UNKNOWN"
        assert second.manifest.coverage_complete is False


def test_empty_directory_and_mode_are_in_tree_identity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        empty = root / "empty"
        empty.mkdir()
        os.chmod(empty, 0o755)
        with_directory = FilesystemObserver(root).observe_stable()
        directory_entry = next(
            e for e in with_directory.manifest.entries if e.path == "empty"
        )
        assert directory_entry.kind == "directory"
        assert directory_entry.mode == 0o755

        os.chmod(empty, 0o700)
        changed_mode = FilesystemObserver(root).observe_stable()
        assert (
            changed_mode.manifest.tree_state_hash
            != with_directory.manifest.tree_state_hash
        )

        empty.rmdir()
        without_directory = FilesystemObserver(root).observe_stable()
        assert (
            without_directory.manifest.tree_state_hash
            != changed_mode.manifest.tree_state_hash
        )


def test_invalid_observation_bounds_are_rejected() -> None:
    for passes in (-1, 0, 1):
        try:
            ObservePolicy(max_observation_passes=passes)
        except ValueError:
            pass
        else:
            raise AssertionError("observation pass bound below two was accepted")
    try:
        ObservePolicy(max_read_bytes=-1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative read bound was accepted")


def test_observation_is_byte_identical() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root / "app.py", b"print(1)\n")
        _write(root / "blob.bin", bytes(range(256)))
        before = _tree_bytes(root)
        FilesystemObserver(root).observe()
        after = _tree_bytes(root)
        assert before == after


def run_tests() -> None:
    test_same_tree_same_manifest_hash()
    test_one_byte_changes_manifest_hash()
    test_binary_without_decoding()
    test_parent_escape_cannot_enter_scope()
    test_symlink_outside_recorded_or_rejected_never_followed()
    test_regular_file_swapped_to_symlink_is_not_followed()
    test_different_exclusion_policies_differ()
    test_change_during_observation_is_unknown()
    test_quiet_tree_stabilizes()
    test_stale_hash_never_stable_after_cross_file_mutation()
    test_stability_policy_is_bound()
    test_fifo_is_never_opened_as_regular_file()
    test_permission_bits_are_in_tree_identity()
    test_partial_read_never_claims_complete_identity()
    test_empty_directory_and_mode_are_in_tree_identity()
    test_invalid_observation_bounds_are_rejected()
    test_observation_is_byte_identical()
    print("fs_observer tests passed")


if __name__ == "__main__":
    run_tests()
