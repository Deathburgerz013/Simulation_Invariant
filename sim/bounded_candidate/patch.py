#!/usr/bin/env python3
"""Candidate-only patch applicator.

No source authority. Paths are normalized relative names. Every component
is inspected with O_NOFOLLOW. Symlinks and symlinked parents are rejected.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sim.bounded_candidate.observer import (
    FilesystemObserver,
    ObservePolicy,
    bind_root,
    sha256_hex,
)


class PatchRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class PatchResult:
    status: str  # PATCH_APPLIED | PATCH_REJECTED
    reason: str
    candidate_root: Optional[str]
    expected_tree_state_hash: str
    observed_tree_state_hash: Optional[str]
    approved_for_execution: bool


def _normalize_relpath(rel: str) -> list[str]:
    if not isinstance(rel, str) or not rel:
        raise PatchRejected("empty_path")
    if os.path.isabs(rel) or rel.startswith("/") or rel.startswith("\\"):
        raise PatchRejected("absolute_path")
    if "\x00" in rel:
        raise PatchRejected("nul_in_path")
    parts = Path(rel).parts
    if parts[:1] == ("/",) or (parts and parts[0] == ".."):
        raise PatchRejected("path_escape")
    out: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise PatchRejected("path_escape")
        if os.sep in part or (os.altsep and os.altsep in part):
            raise PatchRejected("path_separator_in_component")
        out.append(part)
    if not out:
        raise PatchRejected("empty_path")
    return out


def _hash_fd(fd: int) -> str:
    digest_data = b""
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        digest_data += chunk
    return sha256_hex(digest_data)


def _open_parent_nofollow(root: Path, parts: list[str]) -> tuple[int, str]:
    """Return (parent_dir_fd, final_name). Never follows a symlink."""
    flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags_dir |= os.O_NOFOLLOW
    root_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = root_fd
    try:
        for component in parts[:-1]:
            st = os.stat(component, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                os.close(current)
                raise PatchRejected("symlinked_parent")
            if not stat.S_ISDIR(st.st_mode):
                os.close(current)
                raise PatchRejected("parent_not_directory")
            nxt = os.open(component, flags_dir, dir_fd=current)
            os.close(current)
            current = nxt
        return current, parts[-1]
    except FileNotFoundError:
        os.close(current)
        raise PatchRejected("missing_parent")
    except OSError as exc:
        try:
            os.close(current)
        except OSError:
            pass
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.EPERM}:
            raise PatchRejected("symlink_in_path") from exc
        raise PatchRejected(f"path_open_failed:{exc}") from exc


def apply_candidate_patch(
    candidate_root: str | os.PathLike[str],
    relative_path: str,
    new_content: bytes,
    expected_original_hash: Optional[str],
    expected_tree_state_hash: str,
    *,
    allow_create: bool = False,
    policy: Optional[ObservePolicy] = None,
    discard_on_failure: bool = True,
) -> PatchResult:
    used_policy = policy or ObservePolicy()
    root = bind_root(candidate_root)

    parent_fd = None
    tmp_name = None
    target_mode = 0o644
    try:
        parts = _normalize_relpath(relative_path)
        parent_fd, name = _open_parent_nofollow(root, parts)
        try:
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None

        if st is not None:
            if stat.S_ISLNK(st.st_mode):
                raise PatchRejected("target_is_symlink")
            if not stat.S_ISREG(st.st_mode):
                raise PatchRejected("target_not_regular_file")
            target_mode = st.st_mode & 0o777
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(name, flags, dir_fd=parent_fd)
            try:
                current_hash = _hash_fd(fd)
            finally:
                os.close(fd)
            if expected_original_hash is None:
                raise PatchRejected("missing_original_hash")
            if current_hash != expected_original_hash:
                raise PatchRejected("original_hash_mismatch")
        else:
            if not allow_create:
                raise PatchRejected("target_missing")
            if expected_original_hash not in (None, sha256_hex(b"")):
                raise PatchRejected("create_requires_empty_original_hash")

        tmp_name = f".{name}.patch-tmp-{os.getpid()}"
        flags_w = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags_w |= os.O_NOFOLLOW
        tmp_fd = os.open(tmp_name, flags_w, target_mode, dir_fd=parent_fd)
        try:
            os.fchmod(tmp_fd, target_mode)
            remaining = memoryview(new_content)
            while remaining:
                written = os.write(tmp_fd, remaining)
                if written <= 0:
                    raise PatchRejected("short_write")
                remaining = remaining[written:]
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        os.replace(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_name = None
    except PatchRejected as exc:
        if parent_fd is not None and tmp_name:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd is not None:
            os.close(parent_fd)
            parent_fd = None
        if discard_on_failure:
            shutil.rmtree(root, ignore_errors=True)
        return PatchResult(
            status="PATCH_REJECTED",
            reason=exc.reason,
            candidate_root=None if discard_on_failure else str(root),
            expected_tree_state_hash=expected_tree_state_hash,
            observed_tree_state_hash=None,
            approved_for_execution=False,
        )
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass

    observed = FilesystemObserver(root, policy=used_policy).observe_stable()
    if (
        observed.stability != "STABLE"
        or observed.manifest.tree_state_hash != expected_tree_state_hash
    ):
        if discard_on_failure:
            shutil.rmtree(root, ignore_errors=True)
        return PatchResult(
            status="PATCH_REJECTED",
            reason="tree_state_mismatch_after_patch",
            candidate_root=None if discard_on_failure else str(root),
            expected_tree_state_hash=expected_tree_state_hash,
            observed_tree_state_hash=(
                observed.manifest.tree_state_hash if observed.stability == "STABLE" else None
            ),
            approved_for_execution=False,
        )

    return PatchResult(
        status="PATCH_APPLIED",
        reason="candidate_matches_expected_tree_state",
        candidate_root=str(root),
        expected_tree_state_hash=expected_tree_state_hash,
        observed_tree_state_hash=observed.manifest.tree_state_hash,
        approved_for_execution=True,
    )
