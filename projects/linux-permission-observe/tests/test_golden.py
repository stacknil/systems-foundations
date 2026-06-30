from __future__ import annotations

from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_permission_observe.snapshot import build_snapshot


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
GOLDEN = PROJECT_ROOT / "tests" / "golden"


def test_snapshot_outputs_match_golden_files() -> None:
    baseline = build_snapshot(
        files_path=FIXTURES / "baseline" / "files.tsv",
        groups_path=FIXTURES / "baseline" / "groups.txt",
        sudoers_path=FIXTURES / "baseline" / "sudoers.txt",
    )
    changed = build_snapshot(
        files_path=FIXTURES / "changed" / "files.tsv",
        groups_path=FIXTURES / "changed" / "groups.txt",
        sudoers_path=FIXTURES / "changed" / "sudoers.txt",
    )

    assert baseline.to_dict() == _load_json(GOLDEN / "baseline_snapshot.json")
    assert changed.to_dict() == _load_json(GOLDEN / "changed_snapshot.json")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))

