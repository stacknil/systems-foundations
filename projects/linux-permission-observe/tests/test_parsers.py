from __future__ import annotations

from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_permission_observe.parsers import parse_files_tsv, parse_groups, parse_sudoers


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_file_group_and_sudoers_parsing_basics() -> None:
    files = parse_files_tsv((FIXTURES / "baseline" / "files.tsv").read_text(encoding="utf-8"))
    groups = parse_groups((FIXTURES / "baseline" / "groups.txt").read_text(encoding="utf-8"))
    sudoers = parse_sudoers((FIXTURES / "baseline" / "sudoers.txt").read_text(encoding="utf-8"))

    assert files[0].path == "/etc/ssh/sshd_config"
    assert files[0].mode == "0644"
    assert next(item for item in groups if item.name == "deploy").members == ["alice", "deploybot"]
    deploybot_rule = next(item for item in sudoers if item.subject == "deploybot")
    assert deploybot_rule.tags == ["NOPASSWD"]
    assert deploybot_rule.commands == ["/usr/bin/systemctl restart app"]


def test_malformed_inputs_raise_clear_errors() -> None:
    with pytest.raises(ValueError, match="invalid mode on files TSV line 2"):
        parse_files_tsv((FIXTURES / "malformed" / "files_bad.tsv").read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="malformed sudoers line 1"):
        parse_sudoers((FIXTURES / "malformed" / "sudoers_bad.txt").read_text(encoding="utf-8"))

