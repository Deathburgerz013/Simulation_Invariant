#!/usr/bin/env python3
"""Bounded candidate validation integration.

Produces VALIDATED_CANDIDATE only. No write authority. No promotion authority.
next_action=STOP means this validation task finished — not that the source
may be rewritten.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from sim.bounded_candidate.patch import PatchResult, apply_candidate_patch
from sim.bounded_candidate.workspace import CandidateError, CandidateWorkspace, materialize_candidate
from sim.bounded_candidate.observer import (
    FilesystemObserver,
    ObservePolicy,
    StableObservation,
    bind_root,
    canonical_json,
    sha256_hex,
)
from sim.bounded_candidate.executor import ExecutionReceipt, execute_bounded


def _hash_obj(obj: object) -> str:
    return sha256_hex(canonical_json(obj))


@dataclass
class Proposal:
    relative_path: str
    new_content: bytes
    expected_original_hash: str
    expected_tree_state_hash: str
    source_manifest_hash: str
    source_tree_state_hash: str

    def to_bindable(self) -> dict:
        return {
            "relative_path": self.relative_path,
            "new_content_hash": sha256_hex(self.new_content),
            "expected_original_hash": self.expected_original_hash,
            "expected_tree_state_hash": self.expected_tree_state_hash,
            "source_manifest_hash": self.source_manifest_hash,
            "source_tree_state_hash": self.source_tree_state_hash,
        }

    def proposal_hash(self) -> str:
        return _hash_obj(self.to_bindable())


@dataclass
class ValidationPacket:
    type: str
    source_manifest_hash: str
    source_tree_state_hash: str
    proposal_hash: str
    materialization_receipt_hash: str
    patch_receipt_hash: str
    expected_tree_state_hash: str
    approved_candidate_manifest_hash: str
    execution_clone_input_tree_state_hash: str
    test_receipt_hash: str
    source_manifest_after_hash: str
    candidate_manifest_after_hash: str
    status: str
    promotion_authority: str
    write_authority: str
    next_action: str
    reason: str
    packet_hash: str = ""

    def compute_hash(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if k != "packet_hash"}
        return _hash_obj(payload)

    def bind(self) -> None:
        self.packet_hash = self.compute_hash()

    def verify_hash(self) -> bool:
        expected = self.compute_hash()
        if not self.packet_hash:
            return False
        return secrets.compare_digest(expected, self.packet_hash)

    def to_dict(self) -> dict:
        if not self.packet_hash:
            self.bind()
        return asdict(self)


def _materialization_receipt(workspace: CandidateWorkspace) -> dict:
    return {
        "bound_source_manifest_hash": workspace.bound_source_manifest_hash,
        "bound_source_tree_state_hash": workspace.bound_source_tree_state_hash,
        "candidate_manifest_hash": workspace.candidate_manifest.manifest_hash,
        "candidate_tree_state_hash": workspace.candidate_manifest.tree_state_hash,
        "source_root": str(workspace.source_root),
        "candidate_root": str(workspace.candidate_root),
    }


def _patch_receipt(result: PatchResult, relative_path: str, content_hash: str) -> dict:
    return {
        "status": result.status,
        "reason": result.reason,
        "relative_path": relative_path,
        "new_content_hash": content_hash,
        "expected_tree_state_hash": result.expected_tree_state_hash,
        "observed_tree_state_hash": result.observed_tree_state_hash,
        "approved_for_execution": result.approved_for_execution,
        "candidate_root": result.candidate_root,
    }


def _fail_packet(
    *,
    reason: str,
    status: str,
    source_manifest_hash: str = "",
    source_tree_state_hash: str = "",
    proposal_hash: str = "",
    materialization_receipt_hash: str = "",
    patch_receipt_hash: str = "",
    expected_tree_state_hash: str = "",
    approved_candidate_manifest_hash: str = "",
    execution_clone_input_tree_state_hash: str = "",
    test_receipt_hash: str = "",
    source_manifest_after_hash: str = "",
    candidate_manifest_after_hash: str = "",
) -> ValidationPacket:
    packet = ValidationPacket(
        type="bounded_candidate_validation",
        source_manifest_hash=source_manifest_hash,
        source_tree_state_hash=source_tree_state_hash,
        proposal_hash=proposal_hash,
        materialization_receipt_hash=materialization_receipt_hash,
        patch_receipt_hash=patch_receipt_hash,
        expected_tree_state_hash=expected_tree_state_hash,
        approved_candidate_manifest_hash=approved_candidate_manifest_hash,
        execution_clone_input_tree_state_hash=execution_clone_input_tree_state_hash,
        test_receipt_hash=test_receipt_hash,
        source_manifest_after_hash=source_manifest_after_hash,
        candidate_manifest_after_hash=candidate_manifest_after_hash,
        status=status,
        promotion_authority="NONE",
        write_authority="NONE",
        next_action="STOP",
        reason=reason,
    )
    packet.bind()
    return packet


def validate_candidate(
    source_root: str | os.PathLike[str],
    proposal: Proposal,
    test_argv: Sequence[str],
    *,
    policy: Optional[ObservePolicy] = None,
    timeout_seconds: int = 30,
    mid_clone_hook: Optional[Callable[[Path], None]] = None,
    post_approval_candidate_hook: Optional[Callable[[Path], None]] = None,
    post_proposal_source_hook: Optional[Callable[[Path], None]] = None,
) -> ValidationPacket:
    """Full bounded cycle. Never writes the source. Never promotes."""
    used_policy = policy or ObservePolicy()
    source = bind_root(source_root)

    # 1. Source STABLE
    source_stable = FilesystemObserver(source, policy=used_policy).observe_stable()
    if source_stable.stability != "STABLE":
        return _fail_packet(
            reason="source_not_stable",
            status="HUMAN_REVIEW",
        )
    source_manifest_hash = source_stable.manifest.manifest_hash
    source_tree_state_hash = source_stable.manifest.tree_state_hash

    # 2. Proposal must be bound to this source state
    if proposal.source_manifest_hash != source_manifest_hash:
        return _fail_packet(
            reason="proposal_not_bound_to_source_manifest",
            status="STALE_SOURCE",
            source_manifest_hash=source_manifest_hash,
            source_tree_state_hash=source_tree_state_hash,
            proposal_hash=proposal.proposal_hash(),
            expected_tree_state_hash=proposal.expected_tree_state_hash,
        )
    if proposal.source_tree_state_hash != source_tree_state_hash:
        return _fail_packet(
            reason="proposal_not_bound_to_source_tree",
            status="STALE_SOURCE",
            source_manifest_hash=source_manifest_hash,
            source_tree_state_hash=source_tree_state_hash,
            proposal_hash=proposal.proposal_hash(),
            expected_tree_state_hash=proposal.expected_tree_state_hash,
        )

    if post_proposal_source_hook is not None:
        post_proposal_source_hook(source)
        # Detect stale source early
        check = FilesystemObserver(source, policy=used_policy).observe_stable()
        if (
            check.stability != "STABLE"
            or check.manifest.manifest_hash != source_manifest_hash
        ):
            return _fail_packet(
                reason="source_changed_after_proposal",
                status="STALE_SOURCE",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                expected_tree_state_hash=proposal.expected_tree_state_hash,
            )

    candidate_path = Path(tempfile.mkdtemp(prefix="candidate-")) / "tree"
    workspace: Optional[CandidateWorkspace] = None
    try:
        # 3. Materialize disposable candidate
        try:
            workspace = materialize_candidate(
                source, candidate_path, source_stable, policy=used_policy
            )
        except CandidateError as exc:
            return _fail_packet(
                reason=f"materialization_failed:{exc}",
                status="HUMAN_REVIEW",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                expected_tree_state_hash=proposal.expected_tree_state_hash,
            )

        mat_receipt = _materialization_receipt(workspace)
        mat_hash = _hash_obj(mat_receipt)
        if workspace.bound_source_tree_state_hash != source_tree_state_hash:
            return _fail_packet(
                reason="candidate_did_not_match_source_tree",
                status="HUMAN_REVIEW",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
            )

        # 4. Candidate-only patch
        patch_result = apply_candidate_patch(
            workspace.candidate_root,
            proposal.relative_path,
            proposal.new_content,
            proposal.expected_original_hash,
            proposal.expected_tree_state_hash,
            policy=used_policy,
            discard_on_failure=False,
        )
        patch_rec = _patch_receipt(
            patch_result, proposal.relative_path, sha256_hex(proposal.new_content)
        )
        patch_hash = _hash_obj(patch_rec)
        if patch_result.status != "PATCH_APPLIED" or not patch_result.approved_for_execution:
            if workspace.candidate_root.exists():
                shutil.rmtree(workspace.candidate_root, ignore_errors=True)
            return _fail_packet(
                reason=f"patch_rejected:{patch_result.reason}",
                status="HUMAN_REVIEW",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
            )

        approved_candidate = Path(patch_result.candidate_root)  # type: ignore[arg-type]
        approved_obs = FilesystemObserver(approved_candidate, policy=used_policy).observe_stable()
        if approved_obs.stability != "STABLE":
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason="approved_candidate_not_stable",
                status="HUMAN_REVIEW",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
            )
        if approved_obs.manifest.tree_state_hash != proposal.expected_tree_state_hash:
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason="approved_candidate_tree_mismatch",
                status="HUMAN_REVIEW",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
                approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
            )

        if post_approval_candidate_hook is not None:
            post_approval_candidate_hook(approved_candidate)
            # Will be caught as STALE_CANDIDATE by executor or post check

        # 5–7. Bounded tests against execution clone of approved candidate
        test_receipt = execute_bounded(
            source_root=source,
            approved_candidate_root=approved_candidate,
            expected_tree_state_hash=proposal.expected_tree_state_hash,
            bound_source_manifest_hash=source_manifest_hash,
            command_argv=test_argv,
            timeout_seconds=timeout_seconds,
            policy=used_policy,
            mid_clone_hook=mid_clone_hook,
        )
        test_hash = test_receipt.receipt_hash()

        if test_receipt.reason == "EXECUTION_INPUT_MISMATCH":
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason="EXECUTION_INPUT_MISMATCH",
                status="EXECUTION_INPUT_MISMATCH",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
                approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
                execution_clone_input_tree_state_hash=test_receipt.execution_clone_input_tree_state_hash,
                test_receipt_hash=test_hash,
            )

        if test_receipt.verification != "PASS":
            status = "HUMAN_REVIEW"
            if test_receipt.reason == "source_not_fresh" or test_receipt.reason == "source_mutated":
                status = "STALE_SOURCE"
            elif test_receipt.reason == "approved_candidate_changed":
                status = "STALE_CANDIDATE"
            elif test_receipt.reason == "candidate_not_approved":
                status = "STALE_CANDIDATE"
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason=f"tests_not_passed:{test_receipt.reason}",
                status=status,
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
                approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
                execution_clone_input_tree_state_hash=test_receipt.execution_clone_input_tree_state_hash,
                test_receipt_hash=test_hash,
                source_manifest_after_hash=test_receipt.source_manifest_after,
            )

        # 8. Final freshness recheck
        source_after = FilesystemObserver(source, policy=used_policy).observe_stable()
        candidate_after = FilesystemObserver(approved_candidate, policy=used_policy).observe_stable()
        if source_after.stability != "STABLE" or candidate_after.stability != "STABLE":
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason="final_observation_incomplete",
                status="HUMAN_REVIEW",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
                approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
                execution_clone_input_tree_state_hash=test_receipt.execution_clone_input_tree_state_hash,
                test_receipt_hash=test_hash,
            )
        if source_after.manifest.manifest_hash != source_manifest_hash:
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason="source_changed_before_packet",
                status="STALE_SOURCE",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
                approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
                execution_clone_input_tree_state_hash=test_receipt.execution_clone_input_tree_state_hash,
                test_receipt_hash=test_hash,
                source_manifest_after_hash=source_after.manifest.manifest_hash,
                candidate_manifest_after_hash=candidate_after.manifest.manifest_hash,
            )
        if candidate_after.manifest.tree_state_hash != proposal.expected_tree_state_hash:
            shutil.rmtree(approved_candidate, ignore_errors=True)
            return _fail_packet(
                reason="candidate_changed_before_packet",
                status="STALE_CANDIDATE",
                source_manifest_hash=source_manifest_hash,
                source_tree_state_hash=source_tree_state_hash,
                proposal_hash=proposal.proposal_hash(),
                materialization_receipt_hash=mat_hash,
                patch_receipt_hash=patch_hash,
                expected_tree_state_hash=proposal.expected_tree_state_hash,
                approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
                execution_clone_input_tree_state_hash=test_receipt.execution_clone_input_tree_state_hash,
                test_receipt_hash=test_hash,
                source_manifest_after_hash=source_after.manifest.manifest_hash,
                candidate_manifest_after_hash=candidate_after.manifest.manifest_hash,
            )

        packet = ValidationPacket(
            type="bounded_candidate_validation",
            source_manifest_hash=source_manifest_hash,
            source_tree_state_hash=source_tree_state_hash,
            proposal_hash=proposal.proposal_hash(),
            materialization_receipt_hash=mat_hash,
            patch_receipt_hash=patch_hash,
            expected_tree_state_hash=proposal.expected_tree_state_hash,
            approved_candidate_manifest_hash=approved_obs.manifest.manifest_hash,
            execution_clone_input_tree_state_hash=test_receipt.execution_clone_input_tree_state_hash,
            test_receipt_hash=test_hash,
            source_manifest_after_hash=source_after.manifest.manifest_hash,
            candidate_manifest_after_hash=candidate_after.manifest.manifest_hash,
            status="VALIDATED_CANDIDATE",
            promotion_authority="NONE",
            write_authority="NONE",
            next_action="STOP",
            reason="all_declared_conditions_held",
        )
        packet.bind()
        packet.materialization_receipt = mat_receipt
        packet.patch_receipt = patch_rec
        packet.test_receipt = test_receipt
        return packet
    except Exception as exc:
        if candidate_path.parent.exists():
            shutil.rmtree(candidate_path.parent, ignore_errors=True)
        return _fail_packet(
            reason=f"integration_error:{type(exc).__name__}:{exc}",
            status="HUMAN_REVIEW",
            source_manifest_hash=source_manifest_hash if "source_manifest_hash" in dir() else "",
            source_tree_state_hash=source_tree_state_hash if "source_tree_state_hash" in dir() else "",
            proposal_hash=proposal.proposal_hash(),
            expected_tree_state_hash=proposal.expected_tree_state_hash,
        )


def verify_packet_receipts(
    packet: ValidationPacket,
    *,
    proposal: Proposal,
    materialization_receipt: dict,
    patch_receipt: dict,
    test_receipt: ExecutionReceipt,
) -> bool:
    """Recompute subordinate hashes; any alteration invalidates the packet."""
    if packet.proposal_hash != proposal.proposal_hash():
        return False
    if packet.materialization_receipt_hash != _hash_obj(materialization_receipt):
        return False
    if packet.patch_receipt_hash != _hash_obj(patch_receipt):
        return False
    if packet.test_receipt_hash != test_receipt.receipt_hash():
        return False
    rebound = ValidationPacket(**{k: v for k, v in asdict(packet).items() if k != "packet_hash"})
    rebound.bind()
    return rebound.packet_hash == packet.packet_hash
