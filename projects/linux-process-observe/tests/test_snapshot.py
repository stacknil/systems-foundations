from pathlib import Path
import json

import pytest

from linux_process_observe.models import EvidenceEnvelope
from linux_process_observe.snapshot import EvidenceInputError, build_snapshot_artifacts


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def test_snapshot_artifacts_match_baseline_golden() -> None:
    processes, links = build_snapshot_artifacts(
        proc_root=FIXTURES / "baseline" / "proc",
        ss_path=FIXTURES / "baseline" / "ss.txt",
        host_id="lab-host",
        observed_at="2026-07-05T08:00:00+08:00",
    )

    assert processes.to_dict() == _load_json(GOLDEN / "baseline" / "process_snapshot.json")
    assert links.to_dict() == _load_json(GOLDEN / "baseline" / "process_socket_links.json")
    assert any(item["linked"] is False and item["local_port"] == 68 for item in links.records)


def test_snapshot_artifacts_match_changed_golden() -> None:
    processes, links = build_snapshot_artifacts(
        proc_root=FIXTURES / "changed" / "proc",
        ss_path=FIXTURES / "changed" / "ss.txt",
        host_id="lab-host",
        observed_at="2026-07-05T00:05:00Z",
    )

    assert processes.to_dict() == _load_json(GOLDEN / "changed" / "process_snapshot.json")
    assert links.to_dict() == _load_json(GOLDEN / "changed" / "process_socket_links.json")


def test_snapshot_requires_timezone_aware_observation_time() -> None:
    with pytest.raises(EvidenceInputError, match="observed_at must include a timezone"):
        build_snapshot_artifacts(
            proc_root=FIXTURES / "baseline" / "proc",
            ss_path=FIXTURES / "baseline" / "ss.txt",
            host_id="lab-host",
            observed_at="2026-07-05T00:00:00",
        )


def test_snapshot_preserves_subsecond_observation_time() -> None:
    processes, links = build_snapshot_artifacts(
        proc_root=FIXTURES / "baseline" / "proc",
        ss_path=FIXTURES / "baseline" / "ss.txt",
        host_id="lab-host",
        observed_at="2026-07-05T08:00:00.123456+08:00",
    )

    assert processes.observed_at == "2026-07-05T00:00:00.123456Z"
    assert links.observed_at == "2026-07-05T00:00:00.123456Z"


def test_snapshot_rejects_observation_time_beyond_microsecond_precision() -> None:
    with pytest.raises(EvidenceInputError, match="observed_at supports at most 6 fractional second digits"):
        build_snapshot_artifacts(
            proc_root=FIXTURES / "baseline" / "proc",
            ss_path=FIXTURES / "baseline" / "ss.txt",
            host_id="lab-host",
            observed_at="2026-07-05T00:00:00.1234567Z",
        )


def test_loaded_envelope_requires_timezone_aware_observation_time() -> None:
    with pytest.raises(ValueError, match="observed_at must include a timezone"):
        EvidenceEnvelope.from_mapping(
            {
                "schema": "stacknil.system-evidence.v1",
                "source": "procfs",
                "host_id": "lab-host",
                "observed_at": "2026-07-05T00:00:00",
                "records": [],
            }
        )


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
