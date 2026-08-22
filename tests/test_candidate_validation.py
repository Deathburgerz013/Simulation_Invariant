#!/usr/bin/env python3
"""Adversarial and honest tests for VALIDATED_CANDIDATE integration."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("candidate validation requires POSIX namespaces", allow_module_level=True)
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

from sim.bounded_candidate.observer import FilesystemObserver, sha256_hex
from sim.bounded_candidate.validation import Proposal, validate_candidate, verify_packet_receipts
from sim.bounded_candidate.executor import ExecutionReceipt


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _honest_setup(base: Path):
    source = base / "source"
    expected = base / "expected"
    old = b"def main():\n    print('hello')\n"
    new = b"def main():\n    print('hello world')\n"
    _write(source / "app.py", old)
    _write(source / "README.md", b"keep\n")
    _write(expected / "app.py", new)
    _write(expected / "README.md", b"keep\n")
    source_stable = FilesystemObserver(source).observe_stable()
    expected_stable = FilesystemObserver(expected).observe_stable()
    assert source_stable.stability == "STABLE"
    assert expected_stable.stability == "STABLE"
    proposal = Proposal(
        relative_path="app.py",
        new_content=new,
        expected_original_hash=sha256_hex(old),
        expected_tree_state_hash=expected_stable.manifest.tree_state_hash,
        source_manifest_hash=source_stable.manifest.manifest_hash,
        source_tree_state_hash=source_stable.manifest.tree_state_hash,
    )
    return source, proposal, old, new


def test_honest_path_validated_candidate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source, proposal, old, new = _honest_setup(base)
        packet = validate_candidate(
            source,
            proposal,
            test_argv=["python3", "-c", "print('ok')"],
            timeout_seconds=20,
        )
        assert packet.status == "VALIDATED_CANDIDATE", packet
        assert packet.promotion_authority == "NONE"
        assert packet.write_authority == "NONE"
        assert packet.next_action == "STOP"
        assert packet.type == "bounded_candidate_validation"
        assert source.joinpath("app.py").read_bytes() == old
        assert packet.source_manifest_after_hash == packet.source_manifest_hash
        assert packet.packet_hash


def test_source_change_after_proposal_is_stale() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source, proposal, old, new = _honest_setup(base)

        def mutate_source(src: Path) -> None:
            (src / "app.py").write_bytes(b"mutated-after-proposal\n")

        packet = validate_candidate(
            source,
            proposal,
            test_argv=["python3", "-c", "print('ok')"],
            post_proposal_source_hook=mutate_source,
            timeout_seconds=20,
        )
        assert packet.status == "STALE_SOURCE"
        assert packet.promotion_authority == "NONE"
        assert packet.write_authority == "NONE"


def test_candidate_change_after_approval_is_stale() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source, proposal, old, new = _honest_setup(base)

        def mutate_candidate(cand: Path) -> None:
            (cand / "app.py").write_bytes(b"mutated-candidate\n")

        packet = validate_candidate(
            source,
            proposal,
            test_argv=["python3", "-c", "print('ok')"],
            post_approval_candidate_hook=mutate_candidate,
            timeout_seconds=20,
        )
        assert packet.status == "STALE_CANDIDATE"
        assert packet.write_authority == "NONE"


def test_execution_clone_mismatch() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source, proposal, old, new = _honest_setup(base)

        def corrupt_clone(clone: Path) -> None:
            (clone / "app.py").write_bytes(b"wrong-clone-bytes\n")

        packet = validate_candidate(
            source,
            proposal,
            test_argv=["python3", "-c", "print('ok')"],
            mid_clone_hook=corrupt_clone,
            timeout_seconds=20,
        )
        assert packet.status == "EXECUTION_INPUT_MISMATCH"
        assert packet.write_authority == "NONE"


def test_wrong_expected_hash_never_validated() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source, proposal, old, new = _honest_setup(base)
        bad = Proposal(
            relative_path=proposal.relative_path,
            new_content=proposal.new_content,
            expected_original_hash=proposal.expected_original_hash,
            expected_tree_state_hash="0" * 64,
            source_manifest_hash=proposal.source_manifest_hash,
            source_tree_state_hash=proposal.source_tree_state_hash,
        )
        packet = validate_candidate(
            source,
            bad,
            test_argv=["python3", "-c", "print('ok')"],
            timeout_seconds=20,
        )
        assert packet.status != "VALIDATED_CANDIDATE"
        assert packet.write_authority == "NONE"
        assert source.joinpath("app.py").read_bytes() == old


def test_tests_exit_zero_against_wrong_candidate_never_validated() -> None:
    """Even if the test command exits 0, a wrong expected hash cannot validate."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source, proposal, old, new = _honest_setup(base)
        bad = Proposal(
            relative_path=proposal.relative_path,
            new_content=proposal.new_content,
            expected_original_hash=proposal.expected_original_hash,
            expected_tree_state_hash="f" * 64,
            source_manifest_hash=proposal.source_manifest_hash,
            source_tree_state_hash=proposal.source_tree_state_hash,
        )
        packet = validate_candidate(
            source,
            bad,
            test_argv=["python3", "-c", "print('ok')"],
            timeout_seconds=20,
        )
        assert packet.status != "VALIDATED_CANDIDATE"
        assert packet.promotion_authority == "NONE"


def test_packet_field_tamper_invalidates_packet_hash() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, proposal, old, new = _honest_setup(Path(tmp))
        packet = validate_candidate(
            source,
            proposal,
            test_argv=["python3", "-c", "print('ok')"],
            timeout_seconds=20,
        )
        assert packet.status == "VALIDATED_CANDIDATE"
        assert packet.verify_hash() is True
        original_packet_hash = packet.packet_hash
        packet.test_receipt_hash = "0" * 64
        assert packet.packet_hash == original_packet_hash
        assert packet.verify_hash() is False


def _forged_test_receipt(packet, proposal) -> ExecutionReceipt:
    return ExecutionReceipt(
        input_tree_state_hash=proposal.expected_tree_state_hash,
        command_argv=["python3", "-c", "print('ok')"],
        executable_identity="forged",
        resolved_executable="/usr/bin/python3",
        working_directory=".",
        environment_policy_hash="y",
        execution_platform="Linux",
        kernel_release="test-kernel",
        machine="test-machine",
        effective_user_id=0,
        effective_group_id=0,
        cap_sys_admin_effective=True,
        privilege_requirement="successful-namespace-probe-v1",
        required_namespaces=["mount", "network", "pid"],
        namespace_probe_exit_code=0,
        namespace_probe_stderr_hash="",
        namespace_probe_passed=True,
        automatic_elevation_attempted=False,
        timeout_seconds=20,
        network_policy="DENY",
        exit_code=0,
        timed_out=False,
        stdout_hash="",
        stderr_hash="",
        output_truncated=False,
        source_manifest_before=packet.source_manifest_hash,
        source_manifest_after=packet.source_manifest_after_hash,
        candidate_approved=True,
        tests_passed=True,
        source_unchanged=True,
        source_write_protection_verified=True,
        network_namespace_created=True,
        environment_allowlist_applied=True,
        host_filesystem_restricted=True,
        process_group_kill_armed=True,
        containment_unavailable=False,
        observation_complete=True,
        execution_clone_input_tree_state_hash=packet.execution_clone_input_tree_state_hash,
        execution_clone_matched_candidate=True,
        verification="PASS",
        reason="forged",
    )


def test_honest_subordinate_receipts_verify() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, proposal, old, new = _honest_setup(Path(tmp))
        packet = validate_candidate(
            source, proposal, test_argv=["python3", "-c", "print('ok')"], timeout_seconds=20
        )
        assert packet.status == "VALIDATED_CANDIDATE"
        assert (
            verify_packet_receipts(
                packet,
                proposal=proposal,
                materialization_receipt=packet.materialization_receipt,
                patch_receipt=packet.patch_receipt,
                test_receipt=packet.test_receipt,
            )
            is True
        )


def test_forged_execution_receipt_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, proposal, old, new = _honest_setup(Path(tmp))
        packet = validate_candidate(
            source, proposal, test_argv=["python3", "-c", "print('ok')"], timeout_seconds=20
        )
        assert (
            verify_packet_receipts(
                packet,
                proposal=proposal,
                materialization_receipt=packet.materialization_receipt,
                patch_receipt=packet.patch_receipt,
                test_receipt=_forged_test_receipt(packet, proposal),
            )
            is False
        )


def test_forged_patch_receipt_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, proposal, old, new = _honest_setup(Path(tmp))
        packet = validate_candidate(
            source, proposal, test_argv=["python3", "-c", "print('ok')"], timeout_seconds=20
        )
        assert (
            verify_packet_receipts(
                packet,
                proposal=proposal,
                materialization_receipt=packet.materialization_receipt,
                patch_receipt={"tampered": True},
                test_receipt=packet.test_receipt,
            )
            is False
        )


def test_forged_materialization_receipt_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source, proposal, old, new = _honest_setup(Path(tmp))
        packet = validate_candidate(
            source, proposal, test_argv=["python3", "-c", "print('ok')"], timeout_seconds=20
        )
        assert (
            verify_packet_receipts(
                packet,
                proposal=proposal,
                materialization_receipt={"tampered": True},
                patch_receipt=packet.patch_receipt,
                test_receipt=packet.test_receipt,
            )
            is False
        )


def run_tests() -> None:
    test_honest_path_validated_candidate()
    test_source_change_after_proposal_is_stale()
    test_candidate_change_after_approval_is_stale()
    test_execution_clone_mismatch()
    test_wrong_expected_hash_never_validated()
    test_tests_exit_zero_against_wrong_candidate_never_validated()
    test_packet_field_tamper_invalidates_packet_hash()
    test_honest_subordinate_receipts_verify()
    test_forged_execution_receipt_fails()
    test_forged_patch_receipt_fails()
    test_forged_materialization_receipt_fails()
    print("integrated validation tests passed")


if __name__ == "__main__":
    run_tests()
