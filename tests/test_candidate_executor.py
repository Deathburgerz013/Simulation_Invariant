#!/usr/bin/env python3
"""Bounded executor tests: write integrity, read isolation, timeout group kill."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

if os.name != "posix":
    pytest.skip("bounded executor requires POSIX namespaces", allow_module_level=True)
try:
    _NAMESPACE_PROBE = subprocess.run(
        ["unshare", "-m", "-n", "-p", "-f", "--kill-child", "true"],
        capture_output=True,
        check=False,
    )
except FileNotFoundError:
    pytest.skip("unshare is unavailable", allow_module_level=True)
if _NAMESPACE_PROBE.returncode != 0:
    pytest.skip(
        "mount, network, and PID namespace authority unavailable",
        allow_module_level=True,
    )

from sim.bounded_candidate.workspace import materialize_candidate
from sim.bounded_candidate.observer import FilesystemObserver, sha256_hex
from sim.bounded_candidate.executor import execute_bounded, resolve_executable


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _pair(base: Path, extra=None):
    source = base / "source"
    candidate = base / "candidate"
    _write(source / "app.py", b"def add(a, b):\n    return a + b\n")
    _write(source / "README.md", b"ok\n")
    if extra:
        for rel, data in extra.items():
            _write(source / rel, data)
    stable = FilesystemObserver(source).observe_stable()
    workspace = materialize_candidate(source, candidate, stable)
    return source, workspace


def test_benign_command_can_pass() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, workspace = _pair(Path(tmp))
        receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=workspace.candidate_root,
            expected_tree_state_hash=workspace.bound_source_tree_state_hash,
            bound_source_manifest_hash=workspace.bound_source_manifest_hash,
            command_argv=["python3", "-c", "print('ok')"],
            timeout_seconds=20,
        )
        assert receipt.verification == "PASS", receipt
        assert receipt.tests_passed is True
        assert receipt.source_unchanged is True
        assert receipt.host_filesystem_restricted is True
        assert receipt.network_namespace_created is True
        assert receipt.environment_allowlist_applied is True
        assert receipt.source_write_protection_verified is True
        assert receipt.process_group_kill_armed is True
        assert receipt.namespace_probe_passed is True
        assert receipt.namespace_probe_exit_code == 0
        assert receipt.required_namespaces == ["mount", "network", "pid"]
        assert receipt.privilege_requirement == "successful-namespace-probe-v1"
        assert receipt.automatic_elevation_attempted is False
        assert receipt.execution_platform
        assert receipt.kernel_release
        actual_executable = resolve_executable(["python3"])
        assert Path(receipt.resolved_executable) == actual_executable
        assert receipt.executable_identity == sha256_hex(actual_executable.read_bytes())


def test_absolute_path_source_write_never_passes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        original = b"def add(a, b):\n    return a + b\n"
        attack = (
            "from pathlib import Path\n"
            f"p = Path({str((base / 'source' / 'app.py').resolve())!r})\n"
            "p.write_text('pwned')\n"
        )
        source, workspace = _pair(base, extra={"attack.py": attack.encode()})
        receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=workspace.candidate_root,
            expected_tree_state_hash=workspace.bound_source_tree_state_hash,
            bound_source_manifest_hash=workspace.bound_source_manifest_hash,
            command_argv=["python3", "attack.py"],
            timeout_seconds=20,
        )
        assert receipt.verification == "FAIL"
        assert source.joinpath("app.py").read_bytes() == original


def test_outside_secret_read_never_passes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        secret = base / "outside.secret"
        secret.write_text("TOPSECRET-VALUE")
        attack = (
            "from pathlib import Path\n"
            f"print(Path({str(secret.resolve())!r}).read_text())\n"
        )
        source, workspace = _pair(base, extra={"read_secret.py": attack.encode()})
        receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=workspace.candidate_root,
            expected_tree_state_hash=workspace.bound_source_tree_state_hash,
            bound_source_manifest_hash=workspace.bound_source_manifest_hash,
            command_argv=["python3", "read_secret.py"],
            timeout_seconds=20,
        )
        assert receipt.verification == "FAIL"
        assert receipt.exit_code != 0
        assert receipt.tests_passed is False
        assert receipt.reason == "tests_failed"


def test_descendant_timeout_does_not_pass() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, workspace = _pair(Path(tmp))
        start = time.time()
        receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=workspace.candidate_root,
            expected_tree_state_hash=workspace.bound_source_tree_state_hash,
            bound_source_manifest_hash=workspace.bound_source_manifest_hash,
            command_argv=[
                "python3",
                "-c",
                "import os,time\n"
                "os.fork()\n"
                "time.sleep(30)\n",
            ],
            timeout_seconds=2,
        )
        elapsed = time.time() - start
        assert elapsed < 15
        assert receipt.verification == "FAIL"
        assert receipt.timed_out is True
        assert receipt.process_group_kill_armed is True


def test_wrong_expected_hash_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, workspace = _pair(Path(tmp))
        receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=workspace.candidate_root,
            expected_tree_state_hash="0" * 64,
            bound_source_manifest_hash=workspace.bound_source_manifest_hash,
            command_argv=["python3", "-c", "print('ok')"],
        )
        assert receipt.verification == "FAIL"
        assert receipt.candidate_approved is False
        assert receipt.reason == "candidate_not_approved"


def test_output_limit_is_enforced_during_execution() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, workspace = _pair(Path(tmp))
        receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=workspace.candidate_root,
            expected_tree_state_hash=workspace.bound_source_tree_state_hash,
            bound_source_manifest_hash=workspace.bound_source_manifest_hash,
            command_argv=[
                "python3",
                "-c",
                "import sys; sys.stdout.write('x' * 1000000)",
            ],
            timeout_seconds=20,
            output_limit=1024,
        )
        assert receipt.verification == "FAIL"
        assert receipt.output_truncated is True
        assert receipt.tests_passed is False
        assert receipt.reason == "OUTPUT_LIMIT_EXCEEDED"


def test_missing_namespace_privilege_fails_explicitly_without_elevation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, workspace = _pair(Path(tmp))
        with patch(
            "sim.bounded_candidate.executor._probe_namespace_support",
            return_value=(1, b"operation not permitted"),
        ), patch("sim.bounded_candidate.executor._run_contained") as run_contained:
            receipt = execute_bounded(
                source_root=source,
                approved_candidate_root=workspace.candidate_root,
                expected_tree_state_hash=workspace.bound_source_tree_state_hash,
                bound_source_manifest_hash=workspace.bound_source_manifest_hash,
                command_argv=["/usr/bin/python3", "-c", "print('ok')"],
            )
        assert receipt.verification == "FAIL"
        assert receipt.reason == "PRIVILEGE_REQUIRED"
        assert receipt.namespace_probe_passed is False
        assert receipt.namespace_probe_exit_code == 1
        assert receipt.namespace_probe_stderr_hash == sha256_hex(
            b"operation not permitted"
        )
        assert receipt.automatic_elevation_attempted is False
        assert receipt.containment_unavailable is True
        run_contained.assert_not_called()


def run_tests() -> None:
    test_benign_command_can_pass()
    test_absolute_path_source_write_never_passes()
    test_outside_secret_read_never_passes()
    test_descendant_timeout_does_not_pass()
    test_wrong_expected_hash_fails()
    test_output_limit_is_enforced_during_execution()
    test_missing_namespace_privilege_fails_explicitly_without_elevation()
    print("test executor tests passed")


if __name__ == "__main__":
    run_tests()
