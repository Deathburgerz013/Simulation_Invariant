import base64
import hashlib
import json
from pathlib import Path

import pytest

from sim.__main__ import main as package_main
from sim.environment_monitor import build_monitor_packet
from sim.observation_packets import (
    OBSERVATION_TYPE,
    ObservationPacketError,
    build_observation_packet,
    main as observation_main,
    verify_observation_packet,
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: dict) -> str:
    return digest(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )


def test_packet_presents_exact_binary_bytes_and_receipt(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    content = b"\x00\xffalpha\x80omega"
    (root / "asset.bin").write_bytes(content)

    packet = build_observation_packet(
        root,
        "asset.bin",
        max_bytes=5,
    )

    assert packet["type"] == OBSERVATION_TYPE
    assert packet["version"] == 1
    assert packet["path"] == "asset.bin"
    assert packet["source_size"] == len(content)
    assert packet["source_sha256"] == digest(content)
    assert packet["presented_range"] == {"start": 0, "end": 5}
    assert base64.b64decode(packet["content_base64"]) == content[:5]
    assert packet["content_sha256"] == digest(content[:5])
    assert packet["utf8_text"] is None
    assert packet["next_offset"] == 5
    assert packet["inspection_receipt"]["complete_byte_coverage"] is False
    assert packet["semantic_understanding_claimed"] is False
    assert packet["accepted"] is False
    assert packet["truth_claimed"] is False
    assert packet["write_authority"] == "NONE"
    assert packet["execution_authority"] == "NONE"
    assert verify_observation_packet(root, packet) == packet

    body = dict(packet)
    packet_hash = body.pop("packet_hash")
    assert packet_hash == canonical_hash(body)


def test_utf8_preview_is_exact_when_presented_bytes_decode(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "text.txt").write_text("alpha β\n", encoding="utf-8")

    packet = build_observation_packet(root, "text.txt", max_bytes=64)

    assert packet["utf8_text"] == (root / "text.txt").read_bytes().decode("utf-8")
    assert base64.b64decode(packet["content_base64"]).decode("utf-8") == packet[
        "utf8_text"
    ]
    assert packet["next_offset"] is None
    assert packet["inspection_receipt"]["complete_byte_coverage"] is True


def test_packet_is_deterministic_and_source_is_unchanged(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    source = root / "source.bin"
    source.write_bytes(bytes(range(64)))
    before = source.read_bytes()

    first = build_observation_packet(root, "source.bin", max_bytes=16)
    second = build_observation_packet(root, "source.bin", max_bytes=16)

    assert first == second
    assert source.read_bytes() == before


def test_empty_file_produces_complete_empty_observation(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "empty.txt").write_bytes(b"")

    packet = build_observation_packet(root, "empty.txt", max_bytes=8)

    assert packet["presented_range"] is None
    assert packet["content_base64"] == ""
    assert packet["content_sha256"] == digest(b"")
    assert packet["utf8_text"] == ""
    assert packet["next_offset"] is None
    assert packet["inspection_receipt"]["complete_byte_coverage"] is True
    assert verify_observation_packet(root, packet) == packet


@pytest.mark.parametrize("max_bytes", [0, -1, True, "8", None])
def test_invalid_max_bytes_are_rejected(tmp_path, max_bytes):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")

    with pytest.raises(ObservationPacketError, match="max_bytes"):
        build_observation_packet(root, "source.txt", max_bytes=max_bytes)


@pytest.mark.parametrize("start", [-1, 6, 7, True, "0"])
def test_invalid_start_offsets_are_rejected(tmp_path, start):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")

    with pytest.raises(ObservationPacketError, match="start"):
        build_observation_packet(
            root,
            "source.txt",
            start=start,
            max_bytes=3,
        )


@pytest.mark.parametrize(
    "path",
    ["missing.txt", "../outside.txt", "/absolute.txt", "a/../source.txt"],
)
def test_invalid_source_paths_are_rejected(tmp_path, path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")

    with pytest.raises(ObservationPacketError):
        build_observation_packet(root, path, max_bytes=3)


def test_tampered_packet_is_rejected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")
    packet = build_observation_packet(root, "source.txt", max_bytes=3)
    tampered = json.loads(json.dumps(packet))
    tampered["content_base64"] = base64.b64encode(b"bad").decode("ascii")

    with pytest.raises(ObservationPacketError, match="packet hash mismatch"):
        verify_observation_packet(root, tampered)


def test_rehashed_forged_content_is_rejected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")
    packet = build_observation_packet(root, "source.txt", max_bytes=3)
    forged = json.loads(json.dumps(packet))
    forged_bytes = b"bad"
    forged["content_base64"] = base64.b64encode(forged_bytes).decode("ascii")
    forged["content_sha256"] = digest(forged_bytes)
    body = dict(forged)
    body.pop("packet_hash")
    forged["packet_hash"] = canonical_hash(body)

    with pytest.raises(ObservationPacketError, match="presented content mismatch"):
        verify_observation_packet(root, forged)


def test_packet_becomes_stale_when_source_changes(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    source = root / "source.txt"
    source.write_bytes(b"source")
    packet = build_observation_packet(root, "source.txt", max_bytes=3)
    source.write_bytes(b"change")

    with pytest.raises(ObservationPacketError, match="source identity mismatch"):
        verify_observation_packet(root, packet)


def test_continuation_accumulates_one_complete_receipt(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    content = b"abcdefgh"
    (root / "source.txt").write_bytes(content)

    first = build_observation_packet(root, "source.txt", max_bytes=4)
    second = build_observation_packet(
        root,
        "source.txt",
        max_bytes=4,
        prior_receipt=first["inspection_receipt"],
    )

    assert first["presented_range"] == {"start": 0, "end": 4}
    assert first["next_offset"] == 4
    assert second["presented_range"] == {"start": 4, "end": 8}
    assert base64.b64decode(second["content_base64"]) == content[4:]
    assert second["next_offset"] is None
    assert second["inspection_receipt"]["complete_byte_coverage"] is True
    assert second["inspection_receipt"]["covered_byte_count"] == len(content)

    monitor = build_monitor_packet(
        root,
        inspection_receipts=[second["inspection_receipt"]],
    )
    assert monitor["coverage"]["coverage_complete"] is True
    assert monitor["next_boundary"] is None


def test_explicit_start_can_fill_a_gap_in_prior_receipt(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"abcdefgh")
    tail = build_observation_packet(
        root,
        "source.txt",
        start=4,
        max_bytes=4,
    )

    head = build_observation_packet(
        root,
        "source.txt",
        start=0,
        max_bytes=4,
        prior_receipt=tail["inspection_receipt"],
    )

    assert head["inspection_receipt"]["complete_byte_coverage"] is True
    assert head["next_offset"] is None


def test_prior_receipt_for_other_path_is_rejected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "a.txt").write_bytes(b"aaaa")
    (root / "b.txt").write_bytes(b"bbbb")
    prior = build_observation_packet(root, "a.txt", max_bytes=2)

    with pytest.raises(ObservationPacketError, match="same source path"):
        build_observation_packet(
            root,
            "b.txt",
            max_bytes=2,
            prior_receipt=prior["inspection_receipt"],
        )


def test_overlapping_continuation_is_rejected(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"abcdefgh")
    prior = build_observation_packet(root, "source.txt", max_bytes=4)

    with pytest.raises(ObservationPacketError, match="overlap"):
        build_observation_packet(
            root,
            "source.txt",
            start=2,
            max_bytes=4,
            prior_receipt=prior["inspection_receipt"],
        )


def test_observation_cli_and_package_dispatch_emit_packet(tmp_path, capsys):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"source")

    direct_result = observation_main(
        [str(root), "source.txt", "--max-bytes", "3"]
    )
    direct = json.loads(capsys.readouterr().out)
    package_result = package_main(
        ["inspect", str(root), "source.txt", "--max-bytes", "3"]
    )
    package = json.loads(capsys.readouterr().out)

    assert direct_result == 0
    assert package_result == 0
    assert direct == package
    assert direct["type"] == OBSERVATION_TYPE


def test_cli_loads_prior_packet_for_continuation(tmp_path, capsys):
    root = tmp_path / "environment"
    root.mkdir()
    (root / "source.txt").write_bytes(b"abcdefgh")
    first = build_observation_packet(root, "source.txt", max_bytes=4)
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(json.dumps(first), encoding="utf-8")

    result = observation_main(
        [
            str(root),
            "source.txt",
            "--max-bytes",
            "4",
            "--prior",
            str(prior_path),
        ]
    )

    packet = json.loads(capsys.readouterr().out)
    assert result == 0
    assert packet["presented_range"] == {"start": 4, "end": 8}
    assert packet["inspection_receipt"]["complete_byte_coverage"] is True


def test_cli_reports_bounded_error(tmp_path, capsys):
    root = tmp_path / "environment"
    root.mkdir()

    result = observation_main([str(root), "missing.txt"])

    captured = capsys.readouterr()
    error = json.loads(captured.err)
    assert result == 2
    assert captured.out == ""
    assert error["type"] == "simulation_observation_error"
    assert error["accepted"] is False
    assert error["write_authority"] == "NONE"
    assert error["execution_authority"] == "NONE"
