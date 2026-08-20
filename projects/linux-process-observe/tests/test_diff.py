from pathlib import Path
import json

import pytest

from linux_process_observe.diff import build_diff_envelope
from linux_process_observe.models import EvidenceEnvelope
from linux_process_observe.report import build_markdown_report
from linux_process_observe.snapshot import build_snapshot_artifacts


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def test_process_and_socket_diff_matches_golden() -> None:
    before_processes, before_links = _build("baseline", "2026-07-05T00:00:00Z")
    after_processes, after_links = _build("changed", "2026-07-05T00:05:00Z")

    diff = build_diff_envelope(
        before_processes=before_processes,
        after_processes=after_processes,
        before_links=before_links,
        after_links=after_links,
    )

    assert diff.to_dict() == _load_json(GOLDEN / "diff" / "process_diff.json")
    assert build_markdown_report(diff) == (GOLDEN / "diff" / "report.md").read_text(encoding="utf-8")


def test_diff_rejects_cross_host_artifacts() -> None:
    before_processes, before_links = _build("baseline", "2026-07-05T00:00:00Z")
    after_processes, after_links = _build("changed", "2026-07-05T00:05:00Z")
    after_processes = EvidenceEnvelope(
        schema=after_processes.schema,
        source=after_processes.source,
        host_id="different-host",
        observed_at=after_processes.observed_at,
        records=after_processes.records,
    )

    with pytest.raises(ValueError, match="same host_id"):
        build_diff_envelope(
            before_processes=before_processes,
            after_processes=after_processes,
            before_links=before_links,
            after_links=after_links,
        )


def test_diff_rejects_duplicate_socket_link_identity() -> None:
    before_processes, before_links = _build("baseline", "2026-07-05T00:00:00Z")
    after_processes, after_links = _build("changed", "2026-07-05T00:05:00Z")
    before_links.records.append(dict(before_links.records[0]))

    with pytest.raises(ValueError, match="duplicate process_socket_link identity"):
        build_diff_envelope(
            before_processes=before_processes,
            after_processes=after_processes,
            before_links=before_links,
            after_links=after_links,
        )


@pytest.mark.parametrize(
    ("phase", "mismatched_time"),
    [
        ("before", "2026-07-05T00:01:00Z"),
        ("after", "2026-07-05T00:06:00Z"),
    ],
)
def test_diff_rejects_mismatched_process_and_link_observation_times(
    phase: str,
    mismatched_time: str,
) -> None:
    before_processes, before_links = _build("baseline", "2026-07-05T00:00:00Z")
    after_processes, after_links = _build("changed", "2026-07-05T00:05:00Z")
    if phase == "before":
        before_links = _with_observed_at(before_links, mismatched_time)
    else:
        after_links = _with_observed_at(after_links, mismatched_time)

    with pytest.raises(ValueError, match=f"{phase} process and link artifacts must represent the same observation time"):
        build_diff_envelope(
            before_processes=before_processes,
            after_processes=after_processes,
            before_links=before_links,
            after_links=after_links,
        )


@pytest.mark.parametrize(
    ("before_time", "after_time"),
    [
        ("2026-07-05T00:05:00Z", "2026-07-05T00:05:00Z"),
        ("2026-07-05T00:10:00Z", "2026-07-05T00:05:00Z"),
    ],
    ids=["equal", "reversed"],
)
def test_diff_rejects_non_increasing_observation_times(before_time: str, after_time: str) -> None:
    before_processes, before_links = _build("baseline", before_time)
    after_processes, after_links = _build("changed", after_time)

    with pytest.raises(ValueError, match="before observed_at must be earlier than after observed_at"):
        build_diff_envelope(
            before_processes=before_processes,
            after_processes=after_processes,
            before_links=before_links,
            after_links=after_links,
        )


def test_diff_compares_observation_times_as_instants() -> None:
    before_processes, before_links = _build("baseline", "2026-07-05T00:00:00Z")
    after_processes, after_links = _build("changed", "2026-07-05T00:05:00Z")
    before_links = _with_observed_at(before_links, "2026-07-05T08:00:00+08:00")
    after_links = _with_observed_at(after_links, "2026-07-05T08:05:00+08:00")

    diff = build_diff_envelope(
        before_processes=before_processes,
        after_processes=after_processes,
        before_links=before_links,
        after_links=after_links,
    )

    assert diff.to_dict() == _load_json(GOLDEN / "diff" / "process_diff.json")


def test_diff_accepts_strictly_ordered_subsecond_snapshots() -> None:
    before_processes, before_links = _build("baseline", "2026-07-05T00:00:00.100000Z")
    after_processes, after_links = _build("changed", "2026-07-05T00:00:00.200000Z")

    diff = build_diff_envelope(
        before_processes=before_processes,
        after_processes=after_processes,
        before_links=before_links,
        after_links=after_links,
    )

    assert diff.observed_at == "2026-07-05T00:00:00.200000Z"


def _build(name: str, observed_at: str) -> tuple[EvidenceEnvelope, EvidenceEnvelope]:
    return build_snapshot_artifacts(
        proc_root=FIXTURES / name / "proc",
        ss_path=FIXTURES / name / "ss.txt",
        host_id="lab-host",
        observed_at=observed_at,
    )


def _with_observed_at(envelope: EvidenceEnvelope, observed_at: str) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        schema=envelope.schema,
        source=envelope.source,
        host_id=envelope.host_id,
        observed_at=observed_at,
        records=envelope.records,
    )


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
