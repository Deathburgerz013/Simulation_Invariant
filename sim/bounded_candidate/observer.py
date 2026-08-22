#!/usr/bin/env python3
"""Read-only, scope-bound filesystem observer.

Presents a stable manifest of the declared logical tree fields without
mutating the bound root or claiming coverage that was not obtained.

The tree identity binds relative paths, entry kinds, regular-file bytes,
symlink target text, sizes, and permission bits. It does not claim to bind
ownership, ACLs, extended attributes, timestamps, or special-file contents.

This increment does not apply patches, take write snapshots, or roll back disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat as statmod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

TREE_IDENTITY_SCHEMA = "declared-filesystem-tree-v2"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class ObservePolicy:
    """Explicit observation policy. Bound into policy_hash."""

    exclude_prefixes: Tuple[str, ...] = ()
    exclude_names: Tuple[str, ...] = ()
    max_read_bytes: Optional[int] = None
    stability_method: str = "consecutive-identical-manifests-v1"
    max_observation_passes: int = 3

    def __post_init__(self) -> None:
        if self.max_read_bytes is not None and self.max_read_bytes < 0:
            raise ValueError("max_read_bytes must be non-negative or None")
        if self.max_observation_passes < 2:
            raise ValueError("max_observation_passes must be at least 2")

    def canonical(self) -> dict:
        return {
            "exclude_prefixes": list(self.exclude_prefixes),
            "exclude_names": list(self.exclude_names),
            "max_read_bytes": self.max_read_bytes,
            "follow_symlinks": False,
            "stability_method": self.stability_method,
            "max_observation_passes": self.max_observation_passes,
            "tree_identity_schema": TREE_IDENTITY_SCHEMA,
        }

    def policy_hash(self) -> str:
        return sha256_hex(canonical_json(self.canonical()))

    def is_excluded(self, rel_posix: str) -> bool:
        name = rel_posix.rsplit("/", 1)[-1]
        if name in self.exclude_names:
            return True
        for prefix in self.exclude_prefixes:
            p = prefix.strip("/")
            if rel_posix == p or rel_posix.startswith(p + "/"):
                return True
        return False


@dataclass
class ManifestEntry:
    path: str
    kind: str
    size: int
    content_hash: Optional[str]
    link_target: Optional[str] = None
    mode: Optional[int] = None  # st_mode & 0o777; None if not applicable
    content_complete: Optional[bool] = None


def tree_state_payload(entries: List[ManifestEntry], policy: ObservePolicy) -> dict:
    """Portable logical tree. No resolved root. No observation status."""
    return {
        "tree_identity_schema": TREE_IDENTITY_SCHEMA,
        "entries": [
            {
                "path": e.path,
                "kind": e.kind,
                "size": e.size,
                "content_hash": e.content_hash,
                "link_target": e.link_target,
                "mode": e.mode,
                "content_complete": e.content_complete,
            }
            for e in sorted(entries, key=lambda item: item.path)
        ],
        "scope_policy": {
            "exclude_prefixes": list(policy.exclude_prefixes),
            "exclude_names": list(policy.exclude_names),
            "follow_symlinks": False,
        },
    }


def tree_state_hash(entries: List[ManifestEntry], policy: ObservePolicy) -> str:
    return sha256_hex(canonical_json(tree_state_payload(entries, policy)))


@dataclass
class Manifest:
    root: str
    policy_hash: str
    entries: List[ManifestEntry]
    coverage_complete: bool
    unstable_paths: List[str]
    rejected_paths: List[str]
    status: str  # OK | UNKNOWN | REJECTED | STABLE
    tree_state_hash: str = ""
    observation_passes: int = 1
    stability_method: str = "consecutive-identical-manifests-v1"
    max_observation_passes: int = 3
    manifest_hash: str = ""

    def bind(self) -> None:
        if not self.tree_state_hash:
            raise ValueError("tree_state_hash must be set before bind")
        payload = {
            "root": self.root,
            "policy_hash": self.policy_hash,
            "tree_state_hash": self.tree_state_hash,
            "coverage_complete": self.coverage_complete,
            "unstable_paths": self.unstable_paths,
            "rejected_paths": self.rejected_paths,
            "status": self.status,
            "observation_passes": self.observation_passes,
            "stability_method": self.stability_method,
            "max_observation_passes": self.max_observation_passes,
        }
        self.manifest_hash = sha256_hex(canonical_json(payload))

    def to_dict(self) -> dict:
        self.bind()
        return {
            "root": self.root,
            "policy_hash": self.policy_hash,
            "entries": [asdict(e) for e in self.entries],
            "coverage_complete": self.coverage_complete,
            "unstable_paths": self.unstable_paths,
            "rejected_paths": self.rejected_paths,
            "status": self.status,
            "tree_state_hash": self.tree_state_hash,
            "observation_passes": self.observation_passes,
            "stability_method": self.stability_method,
            "max_observation_passes": self.max_observation_passes,
            "manifest_hash": self.manifest_hash,
        }


class ScopeError(ValueError):
    """Path escaped the bound root."""


def bind_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root).resolve(strict=True)
    if not path.is_dir():
        raise ScopeError(f"root is not a directory: {path}")
    return path


def relative_posix(root: Path, path: Path) -> str:
    """Normalize path relative to root. Reject traversal outside root."""
    # Use the lexical path first so we do not follow the final symlink.
    abs_norm = Path(os.path.normpath(str(path)))
    try:
        rel = abs_norm.relative_to(root)
    except ValueError as exc:
        raise ScopeError(f"path escapes root: {path}") from exc
    rel_posix = rel.as_posix()
    if rel_posix == ".":
        return ""
    if rel_posix.startswith("../") or rel_posix == "..":
        raise ScopeError(f"path escapes root: {path}")
    return rel_posix


def _lstat(path: Path) -> os.stat_result:
    return os.lstat(path)


def _same_identity(a: os.stat_result, b: os.stat_result) -> bool:
    return (
        a.st_ino == b.st_ino
        and a.st_dev == b.st_dev
        and a.st_size == b.st_size
        and a.st_mtime_ns == b.st_mtime_ns
    )


def _hash_regular_file(path: Path, max_read_bytes: Optional[int]) -> Tuple[str, int]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for regular-file observation")
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not statmod.S_ISREG(opened.st_mode):
            raise OSError("observed path is no longer a regular file")
        while True:
            remaining = None if max_read_bytes is None else max_read_bytes - total
            if remaining is not None and remaining <= 0:
                break
            chunk_size = 1024 * 64 if remaining is None else min(1024 * 64, remaining)
            chunk = os.read(fd, chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), total


@dataclass
class StableObservation:
    """Result of bounded consecutive-manifest stabilization.

    STABLE means two bounded consecutive complete observations matched.
    It does not mean the filesystem was atomically frozen.
    """

    stability: str  # STABLE | UNKNOWN
    passes_used: int
    manifest: Manifest
    reason: str


class FilesystemObserver:
    """Read-only observer. Never writes. Does not follow directory symlinks."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        policy: Optional[ObservePolicy] = None,
        mid_observe: Optional[Callable[[str, Path], None]] = None,
        after_observe_leaf: Optional[Callable[[str, Path, int], None]] = None,
    ) -> None:
        self.root = bind_root(root)
        self.policy = policy or ObservePolicy()
        # Test-only hook: called after first lstat, before content read.
        self.mid_observe = mid_observe
        # Test-only hook: called after a leaf has been fully observed.
        self.after_observe_leaf = after_observe_leaf
        self.current_pass = 0

    @property
    def root_identity(self) -> str:
        return self.root.as_posix()

    def observe(self) -> Manifest:
        entries: List[ManifestEntry] = []
        unstable: List[str] = []
        rejected: List[str] = []
        complete = True

        try:
            for dirpath, dirnames, filenames in os.walk(
                self.root,
                topdown=True,
                onerror=lambda err: (_ for _ in ()).throw(err),
                followlinks=False,
            ):
                dir_path = Path(dirpath)
                # Refuse to walk a directory that is a symlink.
                if dir_path != self.root and dir_path.is_symlink():
                    rel = relative_posix(self.root, dir_path)
                    rejected.append(rel)
                    complete = False
                    dirnames[:] = []
                    continue

                # Stabilize walk order; do not follow name-level escapes.
                dirnames.sort()
                filenames.sort()

                kept_dirs: List[str] = []
                for name in dirnames:
                    child = dir_path / name
                    try:
                        rel = relative_posix(self.root, child)
                    except ScopeError:
                        rejected.append(name)
                        complete = False
                        continue
                    if self.policy.is_excluded(rel):
                        continue
                    if child.is_symlink():
                        target = os.readlink(child)
                        entries.append(
                            ManifestEntry(
                                path=rel,
                                kind="symlink",
                                size=0,
                                content_hash=None,
                                link_target=target,
                                mode=int(os.lstat(child).st_mode) & 0o777,
                                content_complete=None,
                            )
                        )
                        # Record only. Never follow, even if the target escapes.
                        continue
                    try:
                        directory_stat = os.lstat(child)
                    except OSError:
                        rejected.append(rel)
                        complete = False
                        continue
                    entries.append(
                        ManifestEntry(
                            path=rel,
                            kind="directory",
                            size=0,
                            content_hash=None,
                            mode=int(directory_stat.st_mode) & 0o777,
                            content_complete=None,
                        )
                    )
                    kept_dirs.append(name)
                dirnames[:] = kept_dirs

                for name in filenames:
                    child = dir_path / name
                    try:
                        rel = relative_posix(self.root, child)
                    except ScopeError:
                        rejected.append(name)
                        complete = False
                        continue
                    if self.policy.is_excluded(rel):
                        continue
                    entry, ok, unstable_this = self._observe_leaf(rel, child)
                    if entry is not None:
                        entries.append(entry)
                    if unstable_this:
                        unstable.append(rel)
                        complete = False
                    if not ok:
                        complete = False
                    if self.after_observe_leaf is not None:
                        self.after_observe_leaf(rel, child, self.current_pass)
        except OSError:
            complete = False

        entries.sort(key=lambda e: e.path)
        unstable.sort()
        rejected.sort()

        status = "OK" if complete and not unstable and not rejected else "UNKNOWN"
        if not complete:
            status = "UNKNOWN"

        manifest = Manifest(
            root=self.root_identity,
            policy_hash=self.policy.policy_hash(),
            entries=entries,
            coverage_complete=complete and status == "OK",
            unstable_paths=unstable,
            rejected_paths=rejected,
            status=status,
            tree_state_hash=tree_state_hash(entries, self.policy),
            observation_passes=max(self.current_pass, 1),
            stability_method=self.policy.stability_method,
            max_observation_passes=self.policy.max_observation_passes,
        )
        manifest.bind()
        return manifest

    def observe_stable(self) -> StableObservation:
        """Require two consecutive matching complete observations.

        STABLE is not an atomic filesystem freeze. Any later mutation must
        recheck the current manifest immediately before acting.
        """
        if self.policy.stability_method != "consecutive-identical-manifests-v1":
            empty = self.observe()
            empty.status = "UNKNOWN"
            empty.coverage_complete = False
            empty.bind()
            return StableObservation(
                stability="UNKNOWN",
                passes_used=1,
                manifest=empty,
                reason="unsupported_stability_method",
            )

        max_passes = self.policy.max_observation_passes
        if max_passes < 2:
            max_passes = 2

        previous: Optional[Manifest] = None
        last = None
        for index in range(1, max_passes + 1):
            self.current_pass = index
            current = self.observe()
            last = current
            if (
                previous is not None
                and previous.coverage_complete
                and current.coverage_complete
                and previous.status == "OK"
                and current.status == "OK"
                and previous.tree_state_hash == current.tree_state_hash
            ):
                current.status = "STABLE"
                current.observation_passes = index
                current.bind()
                return StableObservation(
                    stability="STABLE",
                    passes_used=index,
                    manifest=current,
                    reason="consecutive_identical_complete_tree_state",
                )
            previous = current

        assert last is not None
        last.status = "UNKNOWN"
        last.coverage_complete = False
        last.bind()
        return StableObservation(
            stability="UNKNOWN",
            passes_used=max_passes,
            manifest=last,
            reason="retry_bound_exhausted_or_no_consecutive_match",
        )

    def _symlink_escapes(self, link_path: Path, target: str) -> bool:
        if os.path.isabs(target):
            candidate = Path(os.path.normpath(target))
        else:
            candidate = Path(os.path.normpath(str(link_path.parent / target)))
        try:
            relative_posix(self.root, candidate)
            return False
        except ScopeError:
            return True

    def _observe_leaf(
        self, rel: str, path: Path
    ) -> Tuple[Optional[ManifestEntry], bool, bool]:
        try:
            first = _lstat(path)
        except OSError:
            return None, False, False

        if self.mid_observe is not None:
            self.mid_observe(rel, path)

        mode = first.st_mode

        perm = int(first.st_mode) & 0o777

        if statmod.S_ISLNK(mode):
            target = os.readlink(path)
            entry = ManifestEntry(
                path=rel,
                kind="symlink",
                size=0,
                content_hash=None,
                link_target=target,
                mode=perm,
                content_complete=None,
            )
            try:
                second = _lstat(path)
            except OSError:
                return entry, False, True
            unstable = not _same_identity(first, second)
            return entry, True, unstable

        if statmod.S_ISFIFO(mode):
            return (
                ManifestEntry(
                    path=rel,
                    kind="fifo",
                    size=0,
                    content_hash=None,
                    mode=perm,
                    content_complete=None,
                ),
                True,
                False,
            )
        if statmod.S_ISSOCK(mode):
            return (
                ManifestEntry(
                    path=rel,
                    kind="socket",
                    size=0,
                    content_hash=None,
                    mode=perm,
                    content_complete=None,
                ),
                True,
                False,
            )
        if statmod.S_ISCHR(mode) or statmod.S_ISBLK(mode):
            return (
                ManifestEntry(
                    path=rel,
                    kind="device",
                    size=0,
                    content_hash=None,
                    mode=perm,
                    content_complete=None,
                ),
                True,
                False,
            )
        if not statmod.S_ISREG(mode):
            return (
                ManifestEntry(
                    path=rel,
                    kind="other",
                    size=int(first.st_size),
                    content_hash=None,
                    mode=perm,
                    content_complete=None,
                ),
                False,
                False,
            )

        try:
            content_hash, _read = _hash_regular_file(path, self.policy.max_read_bytes)
        except OSError:
            return None, False, False

        try:
            second = _lstat(path)
        except OSError:
            return None, False, True

        unstable = not _same_identity(first, second)
        if unstable:
            entry = ManifestEntry(
                path=rel,
                kind="regular_file",
                size=int(second.st_size),
                content_hash=None,
                mode=perm,
                content_complete=False,
            )
            return entry, False, True

        content_complete = _read == int(first.st_size)
        entry = ManifestEntry(
            path=rel,
            kind="regular_file",
            size=int(first.st_size),
            content_hash=content_hash,
            mode=perm,
            content_complete=content_complete,
        )
        return entry, content_complete, False
