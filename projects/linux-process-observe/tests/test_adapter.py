from __future__ import annotations

import json
from pathlib import Path

import pytest

from linux_process_observe.adapters import ADAPTER_CONTRACT, build_telemetry_events
from linux_process_observe.cli import main
from linux_process_observe.models import EvidenceEnvelope
from linux_process_observe.snapshot import load_envelope


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def test_process_diff_maps_to_stable_telemetry_events() -> None:
    diff = load_envelope(GOLDEN / "diff" / "process_diff.json", input_name="process-diff")

    actual = build_telemetry_events(diff)
    expected = _load_jsonl(GOLDEN / "diff" / "telemetry_events.jsonl")

    assert actual == expected
    assert {
        "timestamp",
        "event_type",
        "source",
        "target",
        "status",
    } <= actual[0].keys()
    assert {event["metadata"]["time_semantics"] for event in actual} == {
        "snapshot_diff_observed_at"
    }
    assert {event["metadata"]["adapter_contract"] for event in actual} == {
        ADAPTER_CONTRACT
    }
    assert {event["timestamp"] for event in actual} == {diff.observed_at}


def test_adapter_uses_pid_fallback_for_unlinked_socket_context() -> None:
    diff = EvidenceEnvelope(
        schema="stacknil.system-evidence.v1",
        source="procfs+ss",
        host_id="lab-host",
        observed_at="2026-07-05T00:05:00Z",
        records=[
            {
                "record_type": "process_socket_link_change",
                "change_type": "added",
                "identity": "pid=68|udp|UNCONN|0.0.0.0:68|0.0.0.0:*",
                "before": None,
                "after": {
                    "record_type": "process_socket_link",
                    "linked": False,
                    "process_id": None,
                    "pid": 68,
                    "protocol": "udp",
                    "state": "UNCONN",
                    "local_address": "0.0.0.0",
                    "local_port": 68,
                    "remote_address": "0.0.0.0",
                    "remote_port": "*",
                },
                "changes": {},
            }
        ],
    )

    event = build_telemetry_events(diff)[0]

    assert event["source"] == "lab-host:pid:68"
    assert event["target"] == "udp UNCONN 0.0.0.0:68 -> 0.0.0.0:*"


def test_adapter_rejects_malformed_diff_record() -> None:
    payload = json.loads((GOLDEN / "diff" / "process_diff.json").read_text(encoding="utf-8"))
    payload["records"][0]["after"].pop("executable")
    diff = EvidenceEnvelope.from_mapping(payload)

    with pytest.raises(ValueError, match="record 1 missing non-empty executable"):
        build_telemetry_events(diff)


def test_adapter_rejects_missing_or_mismatched_process_identity() -> None:
    payload = _load_diff_payload()
    payload["records"][0]["after"].pop("process_id")
    diff = EvidenceEnvelope.from_mapping(payload)

    with pytest.raises(ValueError, match="record 1 missing non-empty process_id"):
        build_telemetry_events(diff)

    payload = _load_diff_payload()
    payload["records"][0]["after"]["process_id"] = "lab-host:330:9999"
    diff = EvidenceEnvelope.from_mapping(payload)

    with pytest.raises(ValueError, match="record 1 process_id must match identity"):
        build_telemetry_events(diff)


def test_adapter_rejects_undocumented_socket_change_type() -> None:
    payload = _load_diff_payload()
    payload["records"][3]["change_type"] = "modified"
    diff = EvidenceEnvelope.from_mapping(payload)

    with pytest.raises(
        ValueError,
        match=(
            "record 4 has unsupported change_type=modified "
            "for record_type=process_socket_link_change"
        ),
    ):
        build_telemetry_events(diff)


def test_adapter_rejects_invalid_change_shape_and_inner_record_type() -> None:
    payload = _load_diff_payload()
    payload["records"][0]["before"] = dict(payload["records"][0]["after"])
    diff = EvidenceEnvelope.from_mapping(payload)

    with pytest.raises(
        ValueError,
        match="record 1 added change requires before=null and after=object",
    ):
        build_telemetry_events(diff)

    payload = _load_diff_payload()
    payload["records"][0]["after"]["record_type"] = "process_socket_link"
    diff = EvidenceEnvelope.from_mapping(payload)

    with pytest.raises(
        ValueError,
        match="record 1 inner record_type must be process",
    ):
        build_telemetry_events(diff)


def test_cli_adapt_writes_jsonl_and_reports_malformed_input(tmp_path: Path, capsys) -> None:
    output_path = tmp_path / "telemetry_events.jsonl"
    assert (
        main(
            [
                "adapt",
                "--input",
                str(GOLDEN / "diff" / "process_diff.json"),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    assert _load_jsonl(output_path) == _load_jsonl(GOLDEN / "diff" / "telemetry_events.jsonl")
    assert "adapt wrote 7 telemetry events" in capsys.readouterr().err

    malformed_path = tmp_path / "malformed.json"
    payload = json.loads((GOLDEN / "diff" / "process_diff.json").read_text(encoding="utf-8"))
    payload["records"][0]["after"].pop("executable")
    malformed_path.write_text(json.dumps(payload), encoding="utf-8")
    assert (
        main(
            [
                "adapt",
                "--input",
                str(malformed_path),
                "--output",
                str(tmp_path / "not-written.jsonl"),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert "error command=adapt input=process-diff" in captured.err
    assert "type=ValueError" in captured.err


def test_cli_adapt_attributes_output_path_errors(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "output-dir"
    output_dir.mkdir()

    assert (
        main(
            [
                "adapt",
                "--input",
                str(GOLDEN / "diff" / "process_diff.json"),
                "--output",
                str(output_dir),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert "error command=adapt input=output" in captured.err
    assert "type=ValueError" in captured.err
    assert "output path is a directory" in captured.err


def _load_diff_payload() -> dict[str, object]:
    return json.loads((GOLDEN / "diff" / "process_diff.json").read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
