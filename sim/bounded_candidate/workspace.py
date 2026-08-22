#!/usr/bin/env python3
"""Disposable candidate workspace.

Copies bytes from a STABLE source observation into a fresh tree outside
the source. Never writes the source. Never hard-links source files.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from sim.bounded_candidate.observer import (
    FilesystemObserver,
    Manifest,
    ObservePolicy,
    ScopeError,
    StableObservation,
    bind_root,
)


class CandidateError(Exception):
    """Candidate materialization failed. Source must remain untouched."""


@dataclass
class CandidateWorkspace:
    source_root: Path
    candidate_root: Path
    bound_source_manifest_hash: str
    bound_source_tree_state_hash: str
    candidate_manifest: Manifest
    policy: ObservePolicy


def _outside(path: Path, other: Path) -> bool:
    try:
        path.relative_to(other)
        return False
    except ValueError:
        return True


def _copy_tree_bytes(source_root: Path, dest_root: Path, policy: ObservePolicy) -> None:
    dest_root.mkdir(parents=True, exist_ok=False)
    directory_modes: list[tuple[Path, int]] = []
    for dirpath, dirnames, filenames in os.walk(
        source_root, topdown=True, followlinks=False
    ):
        src_dir = Path(dirpath)
        rel_dir = src_dir.relative_to(source_root)
        dst_dir = dest_root if str(rel_dir) == "." else dest_root / rel_dir

        dirnames.sort()
        filenames.sort()
        kept = []
        for name in dirnames:
            child = src_dir / name
            rel = (rel_dir / name).as_posix() if str(rel_dir) != "." else name
            if policy.is_excluded(rel):
                continue
            if child.is_symlink():
                target = os.readlink(child)
                os.symlink(target, dst_dir / name)
                continue
            kept.append(name)
            destination_directory = dst_dir / name
            destination_directory.mkdir(exist_ok=True)
            directory_modes.append(
                (destination_directory, os.lstat(child).st_mode & 0o777)
            )
        dirnames[:] = kept

        for name in filenames:
            child = src_dir / name
            rel = (rel_dir / name).as_posix() if str(rel_dir) != "." else name
            if policy.is_excluded(rel):
                continue
            dest = dst_dir / name
            if child.is_symlink():
                os.symlink(os.readlink(child), dest)
                continue
            if not child.is_file():
                raise CandidateError(f"unsupported source entry: {rel}")
            # Copy bytes into a new inode. Never hard-link.
            shutil.copyfile(child, dest, follow_symlinks=False)
            src_stat = os.lstat(child)
            os.chmod(dest, src_stat.st_mode & 0o777)
            dst_stat = os.lstat(dest)
            if src_stat.st_ino == dst_stat.st_ino and src_stat.st_dev == dst_stat.st_dev:
                raise CandidateError(f"hard link created for {rel}")

    # Apply directory permissions after traversal so restrictive source modes do
    # not prevent construction of the disposable copy.
    for directory, mode in sorted(
        directory_modes, key=lambda item: len(item[0].parts), reverse=True
    ):
        os.chmod(directory, mode)


def materialize_candidate(
    source_root: str | os.PathLike[str],
    candidate_root: str | os.PathLike[str],
    source_stable: StableObservation,
    policy: ObservePolicy | None = None,
) -> CandidateWorkspace:
    if source_stable.stability != "STABLE":
        raise CandidateError("source observation is not STABLE")

    source = bind_root(source_root)
    dest = Path(candidate_root)
    if dest.exists():
        raise CandidateError("candidate destination is not fresh")

    dest_parent = dest.parent.resolve()
    if not dest_parent.is_dir():
        raise CandidateError("candidate parent does not exist")
    dest_resolved = Path(os.path.normpath(str(dest_parent / dest.name)))
    if not _outside(dest_resolved, source) or not _outside(source, dest_resolved):
        raise CandidateError("candidate destination is not outside the source")

    used_policy = policy or ObservePolicy()
    bound_manifest = source_stable.manifest.manifest_hash
    bound_tree = source_stable.manifest.tree_state_hash

    _copy_tree_bytes(source, dest_resolved, used_policy)

    candidate_obs = FilesystemObserver(dest_resolved, policy=used_policy)
    candidate_stable = candidate_obs.observe_stable()
    if candidate_stable.stability != "STABLE":
        shutil.rmtree(dest_resolved, ignore_errors=True)
        raise CandidateError("candidate observation is not STABLE")

    source_again = FilesystemObserver(source, policy=used_policy).observe_stable()
    if source_again.stability != "STABLE":
        shutil.rmtree(dest_resolved, ignore_errors=True)
        raise CandidateError("source no longer STABLE after copy")
    if source_again.manifest.manifest_hash != bound_manifest:
        shutil.rmtree(dest_resolved, ignore_errors=True)
        raise CandidateError("source manifest changed during copy")
    if candidate_stable.manifest.tree_state_hash != bound_tree:
        shutil.rmtree(dest_resolved, ignore_errors=True)
        raise CandidateError("candidate tree_state_hash does not match source")
    if candidate_stable.manifest.manifest_hash == bound_manifest:
        shutil.rmtree(dest_resolved, ignore_errors=True)
        raise CandidateError("candidate and source must not share manifest_hash")

    return CandidateWorkspace(
        source_root=source,
        candidate_root=dest_resolved,
        bound_source_manifest_hash=bound_manifest,
        bound_source_tree_state_hash=bound_tree,
        candidate_manifest=candidate_stable.manifest,
        policy=used_policy,
    )
