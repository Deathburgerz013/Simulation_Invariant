#!/usr/bin/env python3
"""Bounded test executor.

PASS requires only declared properties, not universal containment:

- CANDIDATE_APPROVED
- TESTS_PASSED
- SOURCE_UNCHANGED
- SOURCE_WRITE_PROTECTION_VERIFIED  (source absent from execution view)
- NETWORK_NAMESPACE_CREATED
- ENVIRONMENT_ALLOWLIST_APPLIED
- HOST_FILESYSTEM_RESTRICTED
- PROCESS_GROUP_KILL_ARMED

Tests run in a discarded execution clone inside a restricted mount view.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence

from sim.bounded_candidate.workspace import _copy_tree_bytes, _outside
from sim.bounded_candidate.observer import (
    FilesystemObserver,
    ObservePolicy,
    bind_root,
    canonical_json,
    sha256_hex,
)

DEFAULT_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM")
DEFAULT_TIMEOUT = 60
DEFAULT_OUTPUT_LIMIT = 64 * 1024
NETWORK_POLICY = "DENY"
RUNTIME_BINDS = ("/usr", "/lib", "/lib64", "/bin", "/sbin")
JAIL_METHOD = "mount-namespace-chroot-v2"
RESOURCE_LIMITS = {
    "cpu_seconds": 30,
    "file_size_bytes": 8 * 1024 * 1024,
    "open_files": 256,
    "processes": 64,
    "address_space_bytes": 512 * 1024 * 1024,
}
REQUIRED_NAMESPACES = ("mount", "network", "pid")
PRIVILEGE_REQUIREMENT = "successful-namespace-probe-v1"
CAP_SYS_ADMIN_BIT = 21


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment_policy_hash(
    allowlist: Sequence[str],
    network_policy: str,
    timeout_seconds: int,
    output_limit: int,
) -> str:
    payload = {
        "allowlist": list(allowlist),
        "network_policy": network_policy,
        "timeout_seconds": timeout_seconds,
        "output_limit": output_limit,
        "no_shell": True,
        "no_inherited_secrets": True,
        "host_filesystem": "restricted-root-v1",
        "source_in_view": False,
        "runtime_binds": list(RUNTIME_BINDS),
        "jail_method": JAIL_METHOD,
        "resource_limits": RESOURCE_LIMITS,
        "required_namespaces": list(REQUIRED_NAMESPACES),
        "privilege_requirement": PRIVILEGE_REQUIREMENT,
        "automatic_elevation": False,
    }
    return sha256_hex(canonical_json(payload))


def build_env(allowlist: Sequence[str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for key in allowlist:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env["HOME"] = "/work"
    env["TMPDIR"] = "/tmp"
    env["PATH"] = env.get("PATH", "/usr/bin:/bin")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    return env


def resolve_executable(argv: Sequence[str]) -> Path:
    if not argv:
        raise ValueError("empty argv")
    raw = argv[0]
    if os.path.sep in raw or (os.path.altsep and os.path.altsep in raw):
        path = Path(raw)
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()
    found = shutil.which(raw)
    if not found:
        raise FileNotFoundError(f"executable not found: {raw}")
    return Path(found).resolve()


def _under_runtime_bind(path: Path) -> bool:
    resolved = path.resolve()
    for runtime_root in RUNTIME_BINDS:
        root = Path(runtime_root)
        if not root.exists():
            continue
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


@dataclass
class ExecutionReceipt:
    input_tree_state_hash: str
    command_argv: List[str]
    executable_identity: str
    resolved_executable: str
    working_directory: str
    environment_policy_hash: str
    execution_platform: str
    kernel_release: str
    machine: str
    effective_user_id: int
    effective_group_id: int
    cap_sys_admin_effective: bool
    privilege_requirement: str
    required_namespaces: List[str]
    namespace_probe_exit_code: Optional[int]
    namespace_probe_stderr_hash: str
    namespace_probe_passed: bool
    automatic_elevation_attempted: bool
    timeout_seconds: int
    network_policy: str
    exit_code: Optional[int]
    timed_out: bool
    stdout_hash: str
    stderr_hash: str
    output_truncated: bool
    source_manifest_before: str
    source_manifest_after: str
    candidate_approved: bool
    tests_passed: bool
    source_unchanged: bool
    source_write_protection_verified: bool
    network_namespace_created: bool
    environment_allowlist_applied: bool
    host_filesystem_restricted: bool
    process_group_kill_armed: bool
    containment_unavailable: bool
    observation_complete: bool
    execution_clone_input_tree_state_hash: str
    execution_clone_matched_candidate: bool
    verification: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)

    def receipt_hash(self) -> str:
        return sha256_hex(canonical_json(self.to_dict()))


def _bounded_capture(data: bytes, limit: int) -> tuple[bytes, bool]:
    if data is None:
        return b"", False
    if len(data) > limit:
        return data[:limit], True
    return data, False


def _cap_sys_admin_effective() -> bool:
    """Report the declared Linux capability bit without treating UID as proof."""
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("CapEff:"):
                value = int(line.split(":", 1)[1].strip(), 16)
                return bool(value & (1 << CAP_SYS_ADMIN_BIT))
    except (OSError, ValueError):
        pass
    return False


def _probe_namespace_support() -> tuple[int, bytes]:
    """Test the exact namespace primitive; never elevate or mutate policy."""
    try:
        probe = subprocess.run(
            ["unshare", "-m", "-n", "-p", "-f", "--kill-child", "true"],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return 127, str(exc).encode("utf-8", errors="replace")
    return probe.returncode, probe.stderr


def _run_checked(argv: Sequence[str]) -> bool:
    result = subprocess.run(list(argv), capture_output=True)
    return result.returncode == 0


def _bind(src: str, dst: str, read_only: bool) -> bool:
    os.makedirs(dst, exist_ok=True)
    if not _run_checked(["mount", "--bind", src, dst]):
        return False
    if read_only:
        return _run_checked(["mount", "-o", "remount,ro,bind", dst])
    return True


def _apply_rlimits() -> None:
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (RESOURCE_LIMITS["cpu_seconds"], RESOURCE_LIMITS["cpu_seconds"]),
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (RESOURCE_LIMITS["file_size_bytes"], RESOURCE_LIMITS["file_size_bytes"]),
    )
    resource.setrlimit(
        resource.RLIMIT_NOFILE,
        (RESOURCE_LIMITS["open_files"], RESOURCE_LIMITS["open_files"]),
    )
    resource.setrlimit(
        resource.RLIMIT_NPROC,
        (RESOURCE_LIMITS["processes"], RESOURCE_LIMITS["processes"]),
    )
    try:
        resource.setrlimit(
            resource.RLIMIT_AS,
            (
                RESOURCE_LIMITS["address_space_bytes"],
                RESOURCE_LIMITS["address_space_bytes"],
            ),
        )
    except (ValueError, resource.error):
        pass


def _build_restricted_root(clone: Path) -> Optional[Path]:
    # Keep the mount target beneath the execution-clone parent so the parent
    # can remove it after the namespace exits.
    jail = clone.parent / "jail"
    jail.mkdir(mode=0o700, exist_ok=False)
    try:
        if not _run_checked(["mount", "--make-rprivate", "/"]):
            return None
        for host in RUNTIME_BINDS:
            if os.path.isdir(host):
                if not _bind(host, str(jail / host.lstrip("/")), read_only=True):
                    return None
        work = jail / "work"
        if not _bind(str(clone), str(work), read_only=False):
            return None
        os.makedirs(jail / "tmp", exist_ok=True)
        os.makedirs(jail / "home", exist_ok=True)
        os.makedirs(jail / "proc", exist_ok=True)
        os.makedirs(jail / "dev", exist_ok=True)
        if not _run_checked(["mount", "-t", "tmpfs", "-o", "size=16m,mode=755", "tmpfs", str(jail / "tmp")]):
            return None
        if not _run_checked(["mount", "-t", "tmpfs", "-o", "size=1m,mode=755", "tmpfs", str(jail / "home")]):
            return None
        for node in ("null", "zero", "urandom"):
            src = f"/dev/{node}"
            dst = jail / "dev" / node
            if os.path.exists(src):
                dst.touch()
                if not _run_checked(["mount", "--bind", src, str(dst)]):
                    return None
        # Source tree is intentionally not mounted.
        return jail
    except OSError:
        return None


def _contained_child(clone_s: str, payload_s: str) -> int:
    clone = Path(clone_s)
    payload = json.loads(payload_s)
    argv: List[str] = payload["argv"]
    env: Dict[str, str] = payload["env"]
    jail = _build_restricted_root(clone)
    if jail is None:
        sys.stderr.write("CONTAINMENT_UNAVAILABLE: restricted root failed\n")
        return 125
    _apply_rlimits()
    os.chroot(str(jail))
    os.chdir("/work")
    os.execvpe(argv[0], argv, env)
    return 127


def _run_contained(
    clone: Path,
    argv: Sequence[str],
    env: Mapping[str, str],
    timeout_seconds: int,
    output_limit: int,
) -> tuple[Optional[int], bool, bytes, bytes, bool, bool, bool]:
    """exit, timed_out, stdout, stderr, truncated, ns_started, kill_armed."""
    payload = json.dumps({"argv": list(argv), "env": dict(env)})
    launcher = [
        "unshare",
        "-m",
        "-n",
        "-p",
        "-f",
        "--kill-child",
        sys.executable,
        str(Path(__file__).resolve()),
        "--contained-child",
        str(clone),
        payload,
    ]
    probe = subprocess.run(["unshare", "-m", "-n", "-p", "-f", "--kill-child", "true"], capture_output=True)
    if probe.returncode != 0:
        return None, False, b"", b"unshare unavailable", False, False, False

    proc = subprocess.Popen(
        launcher,
        cwd=str(clone),
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    kill_armed = True
    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_exceeded = False

    def kill_group() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.kill()
        except OSError:
            pass

    while selector.get_map() or proc.poll() is None:
        now = time.monotonic()
        if not timed_out and now >= deadline:
            timed_out = True
            kill_group()
        wait = (
            0.05
            if timed_out or output_exceeded
            else min(0.1, max(0.0, deadline - now))
        )
        for key, _mask in selector.select(wait):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            remaining = max(0, output_limit - total)
            captured[key.data].extend(chunk[:remaining])
            total += min(len(chunk), remaining)
            if len(chunk) > remaining and not output_exceeded:
                output_exceeded = True
                kill_group()
        if proc.poll() is not None and not selector.get_map():
            break

    selector.close()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        kill_group()
        proc.wait(timeout=2)
    return (
        None if timed_out else proc.returncode,
        timed_out,
        bytes(captured["stdout"]),
        bytes(captured["stderr"]),
        output_exceeded,
        True,
        kill_armed,
    )


def execute_bounded(
    source_root: str | os.PathLike[str],
    approved_candidate_root: str | os.PathLike[str],
    expected_tree_state_hash: str,
    bound_source_manifest_hash: str,
    command_argv: Sequence[str],
    timeout_seconds: int = DEFAULT_TIMEOUT,
    output_limit: int = DEFAULT_OUTPUT_LIMIT,
    env_allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
    policy: Optional[ObservePolicy] = None,
    mid_clone_hook: Optional[Callable[[Path], None]] = None,
) -> ExecutionReceipt:
    if isinstance(command_argv, str):
        raise ValueError("command must be an argv list, not a shell string")
    argv = list(command_argv)
    used_policy = policy or ObservePolicy()
    source = bind_root(source_root)
    candidate = bind_root(approved_candidate_root)
    if not _outside(candidate, source):
        raise ValueError("candidate must be outside source")

    env_hash = environment_policy_hash(
        env_allowlist, NETWORK_POLICY, timeout_seconds, output_limit
    )
    executable = resolve_executable(argv)
    exec_id = _hash_file(executable)
    executed_argv = list(argv)
    executed_argv[0] = str(executable)
    executable_available = _under_runtime_bind(executable)
    source_hidden_from_runtime = not _under_runtime_bind(source)
    candidate_hidden_from_runtime = not _under_runtime_bind(candidate)
    env = build_env(env_allowlist)
    execution_platform = platform.system()
    kernel_release = platform.release()
    machine = platform.machine()
    effective_uid = os.geteuid()
    effective_gid = os.getegid()
    cap_sys_admin = _cap_sys_admin_effective()
    namespace_probe_exit_code: Optional[int] = None
    namespace_probe_stderr = b""
    namespace_probe_passed = False

    source_before = FilesystemObserver(source, policy=used_policy).observe_stable()
    candidate_obs = FilesystemObserver(candidate, policy=used_policy).observe_stable()
    observation_complete = (
        source_before.stability == "STABLE" and candidate_obs.stability == "STABLE"
    )
    candidate_approved = (
        observation_complete
        and candidate_obs.manifest.tree_state_hash == expected_tree_state_hash
    )
    source_fresh = (
        observation_complete
        and source_before.manifest.manifest_hash == bound_source_manifest_hash
    )

    def receipt(
        *,
        verification: str,
        reason: str,
        exit_code: Optional[int] = None,
        timed_out: bool = False,
        stdout: bytes = b"",
        stderr: bytes = b"",
        truncated: bool = False,
        tests_passed: bool = False,
        source_unchanged: bool = False,
        source_write_protection_verified: bool = False,
        network_namespace_created: bool = False,
        host_filesystem_restricted: bool = False,
        process_group_kill_armed: bool = False,
        containment_unavailable: bool = False,
        observation_ok: bool = observation_complete,
        source_after_hash: str = "",
        execution_clone_input_tree_state_hash: str = "",
        execution_clone_matched_candidate: bool = False,
    ) -> ExecutionReceipt:
        return ExecutionReceipt(
            input_tree_state_hash=expected_tree_state_hash,
            command_argv=executed_argv,
            executable_identity=exec_id,
            resolved_executable=str(executable),
            working_directory=".",
            environment_policy_hash=env_hash,
            execution_platform=execution_platform,
            kernel_release=kernel_release,
            machine=machine,
            effective_user_id=effective_uid,
            effective_group_id=effective_gid,
            cap_sys_admin_effective=cap_sys_admin,
            privilege_requirement=PRIVILEGE_REQUIREMENT,
            required_namespaces=list(REQUIRED_NAMESPACES),
            namespace_probe_exit_code=namespace_probe_exit_code,
            namespace_probe_stderr_hash=sha256_hex(namespace_probe_stderr),
            namespace_probe_passed=namespace_probe_passed,
            automatic_elevation_attempted=False,
            timeout_seconds=timeout_seconds,
            network_policy=NETWORK_POLICY,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout_hash=sha256_hex(stdout),
            stderr_hash=sha256_hex(stderr),
            output_truncated=truncated,
            source_manifest_before=bound_source_manifest_hash,
            source_manifest_after=source_after_hash,
            candidate_approved=candidate_approved,
            tests_passed=tests_passed,
            source_unchanged=source_unchanged,
            source_write_protection_verified=source_write_protection_verified,
            network_namespace_created=network_namespace_created,
            environment_allowlist_applied=True,
            host_filesystem_restricted=host_filesystem_restricted,
            process_group_kill_armed=process_group_kill_armed,
            containment_unavailable=containment_unavailable,
            observation_complete=observation_ok,
            execution_clone_input_tree_state_hash=execution_clone_input_tree_state_hash,
            execution_clone_matched_candidate=execution_clone_matched_candidate,
            verification=verification,
            reason=reason,
        )

    if not observation_complete:
        return receipt(verification="FAIL", reason="incomplete_observation", observation_ok=False)
    if not executable_available:
        return receipt(
            verification="FAIL",
            reason="executable_not_available_in_restricted_runtime",
            containment_unavailable=True,
        )
    if not source_hidden_from_runtime or not candidate_hidden_from_runtime:
        return receipt(
            verification="FAIL",
            reason="source_or_candidate_overlaps_runtime_mount",
            containment_unavailable=True,
        )
    if not source_fresh:
        return receipt(verification="FAIL", reason="source_not_fresh")
    if not candidate_approved:
        return receipt(verification="FAIL", reason="candidate_not_approved")

    namespace_probe_exit_code, namespace_probe_stderr = _probe_namespace_support()
    namespace_probe_passed = namespace_probe_exit_code == 0
    if not namespace_probe_passed:
        return receipt(
            verification="FAIL",
            reason="PRIVILEGE_REQUIRED",
            containment_unavailable=True,
        )

    clone_dir = Path(tempfile.mkdtemp(prefix="exec-clone-"))
    clone_tree_hash = ""
    clone_matched = False
    try:
        clone = clone_dir / "tree"
        _copy_tree_bytes(candidate, clone, used_policy)
        # Independent observation of the execution clone before tests.
        # The clone is another handoff; it must match the approved candidate.
        if mid_clone_hook is not None:
            mid_clone_hook(clone)
        clone_obs = FilesystemObserver(clone, policy=used_policy).observe_stable()
        if clone_obs.stability != "STABLE":
            return receipt(
                verification="FAIL",
                reason="execution_clone_observation_incomplete",
                observation_ok=False,
            )
        clone_tree_hash = clone_obs.manifest.tree_state_hash
        clone_matched = clone_tree_hash == expected_tree_state_hash
        if not clone_matched:
            return receipt(
                verification="FAIL",
                reason="EXECUTION_INPUT_MISMATCH",
                execution_clone_input_tree_state_hash=clone_tree_hash,
                execution_clone_matched_candidate=False,
            )
        exit_code, timed_out, stdout, stderr, truncated, ns_ok, kill_armed = _run_contained(
            clone, executed_argv, env, timeout_seconds, output_limit
        )
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)

    source_after = FilesystemObserver(source, policy=used_policy).observe_stable()
    candidate_after = FilesystemObserver(candidate, policy=used_policy).observe_stable()
    after_complete = (
        source_after.stability == "STABLE" and candidate_after.stability == "STABLE"
    )
    source_unchanged = (
        after_complete
        and source_after.manifest.manifest_hash == bound_source_manifest_hash
    )
    candidate_still = (
        after_complete
        and candidate_after.manifest.tree_state_hash == expected_tree_state_hash
    )
    source_after_hash = source_after.manifest.manifest_hash if after_complete else ""

    jail_ok = ns_ok and exit_code != 125
    source_write_protection_verified = jail_ok and source_unchanged
    host_fs_restricted = jail_ok
    tests_passed = exit_code == 0 and not timed_out and not truncated

    declared = (
        candidate_approved
        and candidate_still
        and after_complete
        and tests_passed
        and source_unchanged
        and source_write_protection_verified
        and ns_ok
        and host_fs_restricted
        and kill_armed
        and not timed_out
        and clone_matched
    )
    if not after_complete:
        return receipt(
            verification="FAIL",
            reason="incomplete_observation_after",
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
            network_namespace_created=ns_ok,
            process_group_kill_armed=kill_armed,
            host_filesystem_restricted=host_fs_restricted,
            containment_unavailable=not jail_ok,
            observation_ok=False,
            source_after_hash=source_after_hash,
            execution_clone_input_tree_state_hash=clone_tree_hash,
            execution_clone_matched_candidate=clone_matched,
        )
    if not declared:
        reason = "declared_properties_not_held"
        if timed_out:
            reason = "timeout"
        elif not jail_ok:
            reason = "containment_unavailable"
        elif truncated:
            reason = "OUTPUT_LIMIT_EXCEEDED"
        elif not source_unchanged:
            reason = "source_mutated"
        elif not tests_passed:
            reason = "tests_failed"
        elif not candidate_still:
            reason = "approved_candidate_changed"
        elif not clone_matched:
            reason = "EXECUTION_INPUT_MISMATCH"
        return receipt(
            verification="FAIL",
            reason=reason,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
            tests_passed=tests_passed,
            source_unchanged=source_unchanged,
            source_write_protection_verified=source_write_protection_verified,
            network_namespace_created=ns_ok,
            host_filesystem_restricted=host_fs_restricted,
            process_group_kill_armed=kill_armed,
            containment_unavailable=not jail_ok,
            source_after_hash=source_after_hash,
            execution_clone_input_tree_state_hash=clone_tree_hash,
            execution_clone_matched_candidate=clone_matched,
        )
    return receipt(
        verification="PASS",
        reason="declared_properties_held",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        tests_passed=True,
        source_unchanged=True,
        source_write_protection_verified=True,
        network_namespace_created=True,
        host_filesystem_restricted=True,
        process_group_kill_armed=True,
        source_after_hash=source_after_hash,
        execution_clone_input_tree_state_hash=clone_tree_hash,
        execution_clone_matched_candidate=True,
    )


def main(argv: List[str]) -> int:
    if argv and argv[0] == "--contained-child":
        return _contained_child(argv[1], argv[2])
    sys.stderr.write("test_executor is a library; use execute_bounded()\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
