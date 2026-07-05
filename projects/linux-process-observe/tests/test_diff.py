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


def _build(name: str, observed_at: str) -> tuple[EvidenceEnvelope, EvidenceEnvelope]:
    return build_snapshot_artifacts(
        proc_root=FIXTURES / name / "proc",
        ss_path=FIXTURES / name / "ss.txt",
        host_id="lab-host",
        observed_at=observed_at,
    )


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
