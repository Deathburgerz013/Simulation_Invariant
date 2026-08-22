#!/usr/bin/env python3
"""Adversarial tests for the durable append-only receipt ledger API."""

from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("durable ledger requires POSIX file locking", allow_module_level=True)

from sim.bounded_candidate.bounded_correction import BoundedSelfCorrect, InMemoryProject
from sim.bounded_candidate.validation import ValidationPacket
from sim.bounded_candidate.ledger import (
    GENESIS_HASH,
    ReceiptLedgerError,
    append_receipt,
    append_validation_packet,
    verify_ledger,
)


def _must_raise(reason: str, call) -> None:
    try:
        call()
    except ReceiptLedgerError as exc:
        assert str(exc) == reason, exc
    else:
        raise AssertionError(f"expected ReceiptLedgerError: {reason}")


def _append_worker(path: str, number: int) -> None:
    append_receipt(path, ledger_id="concurrent-ledger", payload={"number": number})


def _packet() -> ValidationPacket:
    packet = ValidationPacket(
        type="bounded_candidate_validation",
        source_manifest_hash="a" * 64,
        source_tree_state_hash="b" * 64,
        proposal_hash="c" * 64,
        materialization_receipt_hash="d" * 64,
        patch_receipt_hash="e" * 64,
        expected_tree_state_hash="f" * 64,
        approved_candidate_manifest_hash="1" * 64,
        execution_clone_input_tree_state_hash="2" * 64,
        test_receipt_hash="3" * 64,
        source_manifest_after_hash="a" * 64,
        candidate_manifest_after_hash="1" * 64,
        status="VALIDATED_CANDIDATE",
        promotion_authority="NONE",
        write_authority="NONE",
        next_action="STOP",
        reason="declared_properties_held",
    )
    packet.bind()
    return packet


def test_reopen_and_chain() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        first = append_receipt(
            path, ledger_id="ledger-a", payload={"status": "FAIL", "step": 1}
        )
        second = append_receipt(
            path,
            ledger_id="ledger-a",
            payload={"status": "PASS", "step": 2},
            expected_head_hash=first.record_hash,
        )
        result = verify_ledger(path)
        assert result.valid is True
        assert result.record_count == 2
        assert result.ledger_id == "ledger-a"
        assert result.head_hash == second.record_hash
        assert first.prev_record_hash == GENESIS_HASH
        assert second.prev_record_hash == first.record_hash


def test_payload_tamper_detected_and_append_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        append_receipt(path, ledger_id="ledger-a", payload={"value": "original"})
        value = json.loads(path.read_text(encoding="utf-8"))
        value["payload"]["value"] = "tampered"
        path.write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
        result = verify_ledger(path)
        assert result.valid is False
        assert result.error == "payload_hash_mismatch"
        before = path.read_bytes()
        _must_raise(
            "payload_hash_mismatch",
            lambda: append_receipt(path, ledger_id="ledger-a", payload={"next": 2}),
        )
        assert path.read_bytes() == before


def test_truncated_tail_detected_and_append_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        append_receipt(path, ledger_id="ledger-a", payload={"value": 1})
        path.write_bytes(path.read_bytes()[:-1])
        assert verify_ledger(path).error == "truncated_tail"
        before = path.read_bytes()
        _must_raise(
            "truncated_tail",
            lambda: append_receipt(path, ledger_id="ledger-a", payload={"value": 2}),
        )
        assert path.read_bytes() == before


def test_expected_head_and_ledger_identity_are_enforced() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        append_receipt(path, ledger_id="ledger-a", payload={"value": 1})
        _must_raise(
            "expected_head_mismatch",
            lambda: append_receipt(
                path,
                ledger_id="ledger-a",
                payload={"value": 2},
                expected_head_hash="0" * 64,
            ),
        )
        _must_raise(
            "ledger_id_mismatch",
            lambda: append_receipt(path, ledger_id="ledger-b", payload={"value": 2}),
        )


def test_symlink_ledger_rejected_without_touching_target() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        outside = root / "outside.txt"
        outside.write_bytes(b"unchanged")
        link = root / "ledger.jsonl"
        os.symlink(outside, link)
        _must_raise(
            "ledger_is_symlink",
            lambda: append_receipt(link, ledger_id="ledger-a", payload={"value": 1}),
        )
        assert outside.read_bytes() == b"unchanged"


def test_symlink_parent_rejected_without_touching_target() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        outside = root / "outside"
        outside.mkdir()
        linked_parent = root / "linked"
        os.symlink(outside, linked_parent)
        ledger = linked_parent / "ledger.jsonl"
        _must_raise(
            "ledger_parent_is_symlink_or_not_directory",
            lambda: append_receipt(
                ledger, ledger_id="ledger-a", payload={"value": 1}
            ),
        )
        assert not (outside / "ledger.jsonl").exists()


def test_hard_link_ledger_rejected_without_append() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = root / "original.jsonl"
        original.write_bytes(b"")
        linked = root / "linked.jsonl"
        os.link(original, linked)
        _must_raise(
            "ledger_has_multiple_hard_links",
            lambda: append_receipt(
                linked, ledger_id="ledger-a", payload={"value": 1}
            ),
        )
        assert original.read_bytes() == b""


def test_concurrent_appends_are_serialized() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        processes = [
            multiprocessing.Process(target=_append_worker, args=(str(path), number))
            for number in range(8)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        result = verify_ledger(path)
        assert result.valid is True
        assert result.record_count == 8


def test_validation_packet_requires_valid_bound_hash() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        packet = _packet()
        record = append_validation_packet(
            path, ledger_id="validation-ledger", packet=packet
        )
        assert record.payload["source_write_authority"] == "NONE"
        assert record.payload["promotion_authority"] == "NONE"
        packet.test_receipt_hash = "0" * 64
        _must_raise(
            "validation_packet_hash_invalid",
            lambda: append_validation_packet(
                path, ledger_id="validation-ledger", packet=packet
            ),
        )
        assert verify_ledger(path).record_count == 1


def test_hash_valid_authority_contradiction_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        packet = _packet()
        packet.write_authority = "GRANTED"
        packet.bind()
        assert packet.verify_hash() is True
        _must_raise(
            "validation_packet_write_authority_invalid",
            lambda: append_validation_packet(
                path, ledger_id="validation-ledger", packet=packet
            ),
        )
        assert not path.exists()

        packet = _packet()
        packet.promotion_authority = "GRANTED"
        packet.bind()
        assert packet.verify_hash() is True
        _must_raise(
            "validation_packet_promotion_authority_invalid",
            lambda: append_validation_packet(
                path, ledger_id="validation-ledger", packet=packet
            ),
        )
        assert not path.exists()


def test_external_whole_file_replacement_is_not_overclaimed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        first = append_receipt(path, ledger_id="ledger-a", payload={"value": 1})
        retained_head = first.record_hash
        path.unlink()
        replacement = append_receipt(path, ledger_id="ledger-a", payload={"value": 9})
        assert verify_ledger(path).valid is True
        assert replacement.record_hash != retained_head
        _must_raise(
            "expected_head_mismatch",
            lambda: append_receipt(
                path,
                ledger_id="ledger-a",
                payload={"value": 10},
                expected_head_hash=retained_head,
            ),
        )


def test_bound_exhaustion_receipt_can_be_durably_appended() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipts.jsonl"
        runner = BoundedSelfCorrect(
            InMemoryProject({"app.py": "print('unchanged')\n"})
        )
        assert runner.run_bounded(max_steps=0) == "HUMAN_REVIEW"
        boundary = runner.receipts[-1]
        record = append_receipt(
            path,
            ledger_id="bounded-run-ledger",
            payload={"receipt_kind": "BOUND_EXHAUSTED", "receipt": asdict(boundary)},
        )
        assert record.payload["receipt"]["boundary_event"] == "BOUND_EXHAUSTED"
        assert verify_ledger(path).valid is True


def run_tests() -> None:
    test_reopen_and_chain()
    test_payload_tamper_detected_and_append_refused()
    test_truncated_tail_detected_and_append_refused()
    test_expected_head_and_ledger_identity_are_enforced()
    test_symlink_ledger_rejected_without_touching_target()
    test_symlink_parent_rejected_without_touching_target()
    test_hard_link_ledger_rejected_without_append()
    test_concurrent_appends_are_serialized()
    test_validation_packet_requires_valid_bound_hash()
    test_hash_valid_authority_contradiction_is_rejected()
    test_external_whole_file_replacement_is_not_overclaimed()
    test_bound_exhaustion_receipt_can_be_durably_appended()
    print("receipt ledger tests passed")


if __name__ == "__main__":
    run_tests()
