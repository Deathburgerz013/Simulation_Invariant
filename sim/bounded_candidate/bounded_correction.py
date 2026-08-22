#!/usr/bin/env python3
"""Bounded self-correcting starter with append-only receipts.

Addresses the closed-score-loop problem:
- Observes a bound project state (in-memory files here; swap observer for disk).
- Hashes and binds that state.
- Audits against explicit invariants (not self-reported scores).
- Proposes one bounded patch.
- Verifies the proposal before mutation.
- Snapshots for rollback.
- Applies exactly one correction.
- Reobserves and compares before/after evidence.
- Appends a receipt. Never rewrites prior receipts.
- Stops the current bounded task when no verified difference remains.
- Does not claim the process is universally finished. Re-run when evidence changes.

This is a sketch. Real use requires a filesystem/test observer and
invariants that actually inspect code, tests, and the environment.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_state(files: Dict[str, str]) -> bytes:
    """Deterministic bind of presented files."""
    items = sorted(files.items())
    blob = json.dumps(items, separators=(",", ":"), ensure_ascii=False)
    return blob.encode("utf-8")


def hash_state(files: Dict[str, str]) -> str:
    return sha256_hex(canonical_state(files))


# ---------------------------------------------------------------------------
# Receipt: append-only record. Fields match the essential record requested.
# ---------------------------------------------------------------------------
@dataclass
class Receipt:
    seq: int
    ts: str
    state_before_hash: str
    detected_problem: Optional[str]
    evidence: List[str]
    proposed_correction: Optional[str]
    expected_difference: Optional[str]
    expected_state_after_hash: str
    state_after_hash: str
    observed_difference: Optional[str]
    verification: str  # PASS | FAIL | UNKNOWN | NO_ACTION
    rollback: str  # NOT_NEEDED | APPLIED | UNAVAILABLE | AVAILABLE
    next_action: str  # CONTINUE | STOP | HUMAN_REVIEW
    prev_receipt_hash: str
    boundary_event: Optional[str] = None
    steps_attempted: Optional[int] = None
    step_bound: Optional[int] = None
    receipt_hash: str = ""

    def to_canonical(self) -> bytes:
        payload = {
            "seq": self.seq,
            "ts": self.ts,
            "state_before_hash": self.state_before_hash,
            "detected_problem": self.detected_problem,
            "evidence": self.evidence,
            "proposed_correction": self.proposed_correction,
            "expected_difference": self.expected_difference,
            "expected_state_after_hash": self.expected_state_after_hash,
            "state_after_hash": self.state_after_hash,
            "observed_difference": self.observed_difference,
            "verification": self.verification,
            "rollback": self.rollback,
            "next_action": self.next_action,
            "prev_receipt_hash": self.prev_receipt_hash,
            "boundary_event": self.boundary_event,
            "steps_attempted": self.steps_attempted,
            "step_bound": self.step_bound,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )

    def bind(self) -> None:
        self.receipt_hash = sha256_hex(self.to_canonical())


# ---------------------------------------------------------------------------
# In-memory project. Replace with a real directory walker + test runner.
# ---------------------------------------------------------------------------
class InMemoryProject:
    def __init__(self, files: Dict[str, str]) -> None:
        self.files = dict(files)
        self.snapshot: Optional[Dict[str, str]] = None

    def observe(self) -> Dict[str, str]:
        return dict(self.files)

    def take_snapshot(self) -> None:
        self.snapshot = deepcopy(self.files)

    def rollback(self) -> bool:
        if self.snapshot is None:
            return False
        self.files = deepcopy(self.snapshot)
        return True

    def apply_patch(self, path: str, new_content: str) -> None:
        self.files[path] = new_content


class MutatingProject(InMemoryProject):
    """Defective adapter: applies the approved path change plus an unapproved mutation."""

    def apply_patch(self, path: str, new_content: str) -> None:
        super().apply_patch(path, new_content)
        self.files["README.md"] = "unapproved mutation\n"


# ---------------------------------------------------------------------------
# Explicit invariants. Each returns (problem_id | None, evidence).
# These are examples only. Plug in real checks (tests, types, deps).
# ---------------------------------------------------------------------------
def _body_after_shebang(content: str) -> str:
    if content.startswith("#!"):
        nl = content.find("\n")
        return content[nl + 1 :] if nl >= 0 else ""
    return content


def check_module_docstring(files: Dict[str, str]) -> tuple[Optional[str], List[str]]:
    path = "app.py"
    content = files.get(path, "")
    body = _body_after_shebang(content).lstrip()
    if not body.startswith('"""'):
        return (
            "missing_module_docstring",
            [f"{path} has no module docstring after optional shebang"],
        )
    return None, []


def check_shebang(files: Dict[str, str]) -> tuple[Optional[str], List[str]]:
    path = "app.py"
    content = files.get(path, "")
    if not content.startswith("#!"):
        return "missing_shebang", [f"{path} has no shebang"]
    return None, []


INVARIANT_CHECKS: List[Callable[[Dict[str, str]], tuple[Optional[str], List[str]]]] = [
    check_module_docstring,
    check_shebang,
]


def audit(files: Dict[str, str]) -> tuple[Optional[str], List[str]]:
    """External-style audit: first failing invariant wins. One correction per cycle."""
    for check in INVARIANT_CHECKS:
        problem, evidence = check(files)
        if problem:
            return problem, evidence
    return None, []


def propose(problem: str, files: Dict[str, str]) -> tuple[str, str, str]:
    """Return (path, new_content, expected_difference). Bounded, one file."""
    path = "app.py"
    content = files[path]
    if problem == "missing_module_docstring":
        addition = '"""Demo application. Bounded self-correction target."""\n'
        if content.startswith("#!"):
            nl = content.find("\n")
            head = content[: nl + 1] if nl >= 0 else content + "\n"
            rest = content[nl + 1 :] if nl >= 0 else ""
            return path, head + addition + rest, "insert module docstring after shebang"
        return path, addition + content, "insert module docstring at top of app.py"
    if problem == "missing_shebang":
        addition = "#!/usr/bin/env python3\n"
        return path, addition + content, "insert shebang at top of app.py"
    raise ValueError(f"no proposal for {problem}")


def verify_proposal(path: str, new_content: str, problem: str) -> bool:
    """Check the proposed bytes would satisfy the failing invariant, before mutate."""
    trial = {path: new_content}
    if problem == "missing_module_docstring":
        found, _ = check_module_docstring(trial)
        return found is None
    if problem == "missing_shebang":
        found, _ = check_shebang(trial)
        return found is None
    return False


# ---------------------------------------------------------------------------
# Bounded runner
# ---------------------------------------------------------------------------
class BoundedSelfCorrect:
    def __init__(self, project: InMemoryProject) -> None:
        self.project = project
        self.receipts: List[Receipt] = []  # append-only
        self.current_task_status = "UNKNOWN"

    def last_receipt_hash(self) -> str:
        if not self.receipts:
            return "0" * 64
        return self.receipts[-1].receipt_hash

    def append_receipt(self, receipt: Receipt) -> None:
        receipt.prev_receipt_hash = self.last_receipt_hash()
        receipt.bind()
        self.receipts.append(receipt)  # add only

    def current_task_finished(self) -> bool:
        """True only for this bounded run when no verified difference remains."""
        return self.current_task_status in {"PASS", "NO_ACTION"}

    def future_corrections_permitted(self) -> bool:
        """Always. Re-evaluate when evidence or environment changes."""
        return True

    def run_bounded(self, max_steps: int = 8) -> str:
        """
        Execute the 11-step loop until STOP or max_steps.
        Returns the final next_action.
        """
        if type(max_steps) is not int or max_steps < 0:
            raise ValueError("max_steps must be a non-negative integer")
        for _ in range(max_steps):
            # 1. Observe
            before = self.project.observe()
            # 2. Hash and bind
            before_hash = hash_state(before)
            # 3. Audit
            problem, evidence = audit(before)

            if problem is None:
                receipt = Receipt(
                    seq=len(self.receipts) + 1,
                    ts=utc_now(),
                    state_before_hash=before_hash,
                    detected_problem=None,
                    evidence=["no invariant failed under present scope"],
                    proposed_correction=None,
                    expected_difference=None,
                    expected_state_after_hash=before_hash,
                    state_after_hash=before_hash,
                    observed_difference=None,
                    verification="NO_ACTION",
                    rollback="NOT_NEEDED",
                    next_action="STOP",
                    prev_receipt_hash="",
                )
                self.append_receipt(receipt)
                self.current_task_status = "NO_ACTION"
                return "STOP"

            # 4. Propose one bounded patch and bind the exact expected whole state
            path, new_content, expected = propose(problem, before)
            expected_after = dict(before)
            expected_after[path] = new_content
            expected_after_hash = hash_state(expected_after)

            # 5. Verify proposal before mutation
            if not verify_proposal(path, new_content, problem):
                receipt = Receipt(
                    seq=len(self.receipts) + 1,
                    ts=utc_now(),
                    state_before_hash=before_hash,
                    detected_problem=problem,
                    evidence=evidence,
                    proposed_correction=expected,
                    expected_difference=expected,
                    expected_state_after_hash=expected_after_hash,
                    state_after_hash=before_hash,
                    observed_difference=None,
                    verification="FAIL",
                    rollback="NOT_NEEDED",
                    next_action="HUMAN_REVIEW",
                    prev_receipt_hash="",
                )
                self.append_receipt(receipt)
                self.current_task_status = "FAILED"
                return "HUMAN_REVIEW"

            # 6. Snapshot
            self.project.take_snapshot()
            # 7. Apply exactly one correction
            self.project.apply_patch(path, new_content)
            # 8. Reobserve
            after = self.project.observe()
            after_hash = hash_state(after)

            # Exact transition binding: observed post-state must equal approved post-state
            if after_hash != expected_after_hash:
                rolled = self.project.rollback()
                receipt = Receipt(
                    seq=len(self.receipts) + 1,
                    ts=utc_now(),
                    state_before_hash=before_hash,
                    detected_problem=problem,
                    evidence=evidence
                    + ["OBSERVED_STATE_DID_NOT_MATCH_APPROVED_STATE"],
                    proposed_correction=expected,
                    expected_difference=expected,
                    expected_state_after_hash=expected_after_hash,
                    state_after_hash=after_hash,
                    observed_difference="OBSERVED_STATE_DID_NOT_MATCH_APPROVED_STATE",
                    verification="FAIL",
                    rollback="APPLIED" if rolled else "UNAVAILABLE",
                    next_action="HUMAN_REVIEW",
                    prev_receipt_hash="",
                )
                self.append_receipt(receipt)
                self.current_task_status = "FAILED"
                return "HUMAN_REVIEW"

            observed = f"{path} content changed; hash {before_hash[:12]} -> {after_hash[:12]}"
            still_problem, _ = audit(after)
            if still_problem == problem:
                rolled = self.project.rollback()
                receipt = Receipt(
                    seq=len(self.receipts) + 1,
                    ts=utc_now(),
                    state_before_hash=before_hash,
                    detected_problem=problem,
                    evidence=evidence,
                    proposed_correction=expected,
                    expected_difference=expected,
                    expected_state_after_hash=expected_after_hash,
                    state_after_hash=hash_state(self.project.observe()),
                    observed_difference=observed,
                    verification="FAIL",
                    rollback="APPLIED" if rolled else "UNAVAILABLE",
                    next_action="HUMAN_REVIEW",
                    prev_receipt_hash="",
                )
                self.append_receipt(receipt)
                self.current_task_status = "FAILED"
                return "HUMAN_REVIEW"

            verification = (
                "PASS" if still_problem is None or still_problem != problem else "UNKNOWN"
            )
            next_action = "CONTINUE" if still_problem else "STOP"
            receipt = Receipt(
                seq=len(self.receipts) + 1,
                ts=utc_now(),
                state_before_hash=before_hash,
                detected_problem=problem,
                evidence=evidence,
                proposed_correction=expected,
                expected_difference=expected,
                expected_state_after_hash=expected_after_hash,
                state_after_hash=after_hash,
                observed_difference=observed,
                verification=verification,
                rollback="AVAILABLE",
                next_action=next_action,
                prev_receipt_hash="",
            )
            # 10. Append receipt
            self.append_receipt(receipt)
            self.current_task_status = verification
            # 11. Stop if no verified improvement remains
            if next_action == "STOP":
                return "STOP"
        # The external step bound ended this run. This is neither PASS nor
        # completion, and it must not disappear as a bare loop return.
        bounded_state = self.project.observe()
        bounded_hash = hash_state(bounded_state)
        remaining_problem, remaining_evidence = audit(bounded_state)
        receipt = Receipt(
            seq=len(self.receipts) + 1,
            ts=utc_now(),
            state_before_hash=bounded_hash,
            detected_problem=remaining_problem,
            evidence=remaining_evidence
            + [f"BOUND_EXHAUSTED after {max_steps} step(s)"],
            proposed_correction=None,
            expected_difference=None,
            expected_state_after_hash=bounded_hash,
            state_after_hash=bounded_hash,
            observed_difference="BOUND_EXHAUSTED",
            verification="UNKNOWN",
            rollback="NOT_NEEDED",
            next_action="HUMAN_REVIEW",
            prev_receipt_hash="",
            boundary_event="BOUND_EXHAUSTED",
            steps_attempted=max_steps,
            step_bound=max_steps,
        )
        self.append_receipt(receipt)
        self.current_task_status = "UNKNOWN"
        return "HUMAN_REVIEW"

    def dump_receipts(self) -> str:
        return json.dumps([asdict(r) for r in self.receipts], indent=2)


def test_unapproved_secondary_mutation_fails_and_rolls_back() -> None:
    original = {
        "app.py": "def main():\n    print('hello')\n",
        "README.md": "original\n",
    }
    project = MutatingProject(original)
    runner = BoundedSelfCorrect(project)

    assert runner.run_bounded() == "HUMAN_REVIEW"
    assert project.observe() == original

    receipt = runner.receipts[-1]
    assert receipt.verification == "FAIL"
    assert receipt.rollback == "APPLIED"
    assert (
        receipt.observed_difference
        == "OBSERVED_STATE_DID_NOT_MATCH_APPROVED_STATE"
    )
    assert receipt.expected_state_after_hash != receipt.state_after_hash
    assert receipt.next_action == "HUMAN_REVIEW"


def test_honest_adapter_reaches_stop() -> None:
    project = InMemoryProject(
        {
            "app.py": "def main():\n    print('hello')\n",
            "README.md": "original\n",
        }
    )
    runner = BoundedSelfCorrect(project)
    assert runner.run_bounded() == "STOP"
    assert runner.current_task_finished() is True
    last = runner.receipts[-1]
    assert last.expected_state_after_hash == last.state_after_hash
    assert last.verification in {"PASS", "NO_ACTION"}


def test_bound_exhaustion_is_an_explicit_chained_receipt() -> None:
    project = InMemoryProject(
        {
            "app.py": "def main():\n    print('hello')\n",
            "README.md": "original\n",
        }
    )
    runner = BoundedSelfCorrect(project)
    assert runner.run_bounded(max_steps=1) == "HUMAN_REVIEW"
    assert runner.current_task_finished() is False
    assert runner.future_corrections_permitted() is True
    assert len(runner.receipts) == 2
    correction, boundary = runner.receipts
    assert correction.next_action == "CONTINUE"
    assert boundary.boundary_event == "BOUND_EXHAUSTED"
    assert boundary.verification == "UNKNOWN"
    assert boundary.next_action == "HUMAN_REVIEW"
    assert boundary.steps_attempted == 1
    assert boundary.step_bound == 1
    assert boundary.state_before_hash == boundary.state_after_hash
    assert boundary.prev_receipt_hash == correction.receipt_hash
    assert boundary.receipt_hash
    assert check_shebang(project.observe())[0] == "missing_shebang"


def test_zero_bound_emits_receipt_without_mutation() -> None:
    original = {"app.py": "print('unchanged')\n"}
    project = InMemoryProject(original)
    runner = BoundedSelfCorrect(project)
    assert runner.run_bounded(max_steps=0) == "HUMAN_REVIEW"
    assert project.observe() == original
    assert len(runner.receipts) == 1
    assert runner.receipts[0].boundary_event == "BOUND_EXHAUSTED"
    assert runner.receipts[0].steps_attempted == 0


def test_invalid_bound_is_rejected_before_receipt_or_mutation() -> None:
    original = {"app.py": "print('unchanged')\n"}
    for invalid in (-1, True):
        project = InMemoryProject(original)
        runner = BoundedSelfCorrect(project)
        try:
            runner.run_bounded(max_steps=invalid)
        except ValueError as exc:
            assert str(exc) == "max_steps must be a non-negative integer"
        else:
            raise AssertionError("invalid max_steps was accepted")
        assert project.observe() == original
        assert runner.receipts == []


def run_tests() -> None:
    test_unapproved_secondary_mutation_fails_and_rolls_back()
    test_honest_adapter_reaches_stop()
    test_bound_exhaustion_is_an_explicit_chained_receipt()
    test_zero_bound_emits_receipt_without_mutation()
    test_invalid_bound_is_rejected_before_receipt_or_mutation()
    print("tests passed")


def main() -> None:
    # Starting project that fails both example invariants.
    project = InMemoryProject(
        {
            "app.py": "def main():\n    print('hello')\n",
            "README.md": "demo target for bounded correction\n",
        }
    )
    runner = BoundedSelfCorrect(project)

    print("Starting bounded self-correction.")
    print("Add-only receipts. One correction per cycle.")
    print("Current task may STOP. Future re-evaluation remains open.\n")

    action = runner.run_bounded()
    print(f"bounded_run next_action={action}")
    print(f"current_task_finished={runner.current_task_finished()}")
    print(f"future_corrections_permitted={runner.future_corrections_permitted()}")
    print(f"final_status={runner.current_task_status}")
    print(f"final_state_hash={hash_state(project.observe())}")
    print("\n--- append-only receipts ---")
    print(runner.dump_receipts())
    print("\n--- resulting app.py ---")
    print(project.files["app.py"])


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_tests()
    else:
        main()
