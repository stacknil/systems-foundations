from __future__ import annotations

from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_socket_observe.snapshot import build_snapshot


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def test_snapshot_outputs_match_golden_files() -> None:
    baseline = build_snapshot(
        ss_path=FIXTURES / "baseline" / "ss.txt",
        ip_addr_path=FIXTURES / "baseline" / "ip_addr.json",
        ip_link_path=FIXTURES / "baseline" / "ip_link.json",
        ip_neigh_path=FIXTURES / "baseline" / "ip_neigh.json",
        ip_link_stats_path=FIXTURES / "baseline" / "ip_link_stats.txt",
    )
    changed = build_snapshot(
        ss_path=FIXTURES / "changed" / "ss.txt",
        ip_addr_path=FIXTURES / "changed" / "ip_addr.json",
        ip_link_path=FIXTURES / "changed" / "ip_link.json",
        ip_neigh_path=FIXTURES / "changed" / "ip_neigh.json",
        ip_link_stats_path=FIXTURES / "changed" / "ip_link_stats.txt",
    )

    assert baseline.to_dict() == _load_json(GOLDEN / "baseline_snapshot.json")
    assert changed.to_dict() == _load_json(GOLDEN / "changed_snapshot.json")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
