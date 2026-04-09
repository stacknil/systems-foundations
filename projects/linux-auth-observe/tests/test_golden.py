from __future__ import annotations

from pathlib import Path
import json
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_auth_observe.cli import main


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
GOLDEN = PROJECT_ROOT / "tests" / "golden"
STABLE_KEYS = (
    "ts",
    "host",
    "collector",
    "parser",
    "event_family",
    "event_type",
    "outcome",
    "user",
    "src_ip",
    "src_port",
    "service",
    "unit",
    "pid",
    "program",
    "message",
    "raw",
)


def test_existing_fixture_families_match_golden_outputs(tmp_path: Path) -> None:
    cases = [
        ("ubuntu_auth.log", "ubuntu_auth.golden.jsonl"),
        ("rhel_secure.log", "rhel_secure.golden.jsonl"),
        ("journal_sample.jsonl", "journal_sample.golden.jsonl"),
    ]

    for fixture_name, golden_name in cases:
        output_path = tmp_path / f"{fixture_name}.jsonl"
        exit_code = main(
            [
                "normalize",
                "--input",
                str(FIXTURES / fixture_name),
                "--source",
                "auto",
                "--year",
                "2026",
                "--timezone",
                "Asia/Shanghai",
                "--output",
                str(output_path),
            ]
        )

        assert exit_code == 0
        actual_rows = [_stable_view(payload) for payload in _load_jsonl(output_path)]
        expected_rows = [_stable_view(payload) for payload in _load_jsonl(GOLDEN / golden_name)]
        assert actual_rows == expected_rows


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _stable_view(payload: dict[str, object]) -> dict[str, object]:
    return {key: payload.get(key) for key in STABLE_KEYS}
