import json
from pathlib import Path

import pytest

from linux_process_observe.adapters import build_telemetry_events
from linux_process_observe.cli import main
from linux_process_observe.diff import build_diff_envelope
from linux_process_observe.models import EVIDENCE_SCHEMA, EvidenceEnvelope, ProcessRecord
from linux_process_observe.parsers.procfs import parse_procfs_root
from linux_process_observe.parsers.ss_text import parse_ss_text
from linux_process_observe.snapshot import build_snapshot_artifacts, link_processes_to_sockets, write_envelope


HOST = "example-host"
T0 = "2026-07-05T00:00:00Z"
T1 = "2026-07-05T00:05:00Z"


def _process(pid=120, ticks=1200, name="worker-a"):
    return ProcessRecord("process", f"{HOST}:{pid}:{ticks}", pid, 0, None, name,
                         "S", 1001, 1001, 1001, 1001, f"/opt/example/bin/{name}",
                         [f"/opt/example/bin/{name}"], ticks)


def _ss(refs=(("worker-a", 120),)):
    users = ",".join(f'("{name}",pid={pid},fd={3+i})' for i, (name, pid) in enumerate(refs))
    return f"tcp LISTEN 0 64 127.0.0.1:9000 0.0.0.0:* users:({users})\n"


def _pair(time, processes=None, observations=None):
    processes = [_process()] if processes is None else processes
    observations = parse_ss_text(_ss()) if observations is None else observations
    return (EvidenceEnvelope(EVIDENCE_SCHEMA, "procfs", HOST, time, [p.to_dict() for p in processes]),
            EvidenceEnvelope(EVIDENCE_SCHEMA, "procfs+ss", HOST, time,
                             [link.to_dict() for link in link_processes_to_sockets(processes, observations)]))


def _diff(before, after):
    return build_diff_envelope(before_processes=before[0], before_links=before[1],
                               after_processes=after[0], after_links=after[1])


def _export(root: Path, process: ProcessRecord, directory=None):
    target = root / (directory or str(process.pid))
    target.mkdir(parents=True)
    (target / "status").write_text(f"Name:\t{process.name}\nState:\tS\nPPid:\t0\nUid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\n", encoding="utf-8")
    fields = ["S", "0"] + ["0"] * 17 + [str(process.start_time_ticks)]
    (target / "stat").write_text(f"{process.pid} ({process.name}) " + " ".join(fields), encoding="utf-8")
    (target / "exe").write_text(process.executable, encoding="utf-8")
    (target / "cmdline").write_bytes(process.executable.encode() + b"\0")


@pytest.mark.parametrize("reported_name", ["worker-a", "worker-b"])
def test_reported_ss_name_is_preserved_through_cli_diff_and_adapt(tmp_path, reported_name):
    proc = tmp_path / "proc"
    _export(proc, _process())
    ss = tmp_path / "ss.txt"
    ss.write_text(_ss(((reported_name, 120),)), encoding="utf-8")
    after = build_snapshot_artifacts(proc_root=proc, ss_path=ss, host_id=HOST, observed_at=T1)
    link = after[1].records[0]
    assert link["process_name"] == reported_name
    assert link["linked"] is True
    assert link["process_id"] == _process().process_id
    assert (link["executable"], link["uid"], link["gid"]) == (_process().executable, 1001, 1001)
    before = _pair(T0, [], [])
    paths = []
    for label, pair in [("before", before), ("after", after)]:
        for kind, envelope in zip(["processes", "links"], pair):
            path = tmp_path / f"{label}-{kind}.json"
            write_envelope(envelope, path)
            paths.extend([f"--{label}-{kind}", str(path)])
    output = tmp_path / "diff"
    assert main(["diff", *paths, "--output-dir", str(output)]) == 0
    telemetry = output / "events.jsonl"
    assert main(["adapt", "--input", str(output / "process_diff.json"), "--output", str(telemetry)]) == 0
    rows = [json.loads(line) for line in telemetry.read_text().splitlines()]
    assert [row["event_type"] for row in rows] == ["process_added", "socket_link_added"]
    assert {row["source"] for row in rows} == {_process().process_id}
    assert {row["metadata"]["time_semantics"] for row in rows} == {"snapshot_diff_observed_at"}
    assert "Process/socket links: +1 / -0" in (output / "report.md").read_text()


def test_same_name_does_not_add_an_instance_verification_claim():
    processes, links = _pair(T1)
    assert links.records[0]["linked"] is True
    assert "verified" not in links.records[0]
    assert "confidence" not in links.records[0]
    assert _diff(_pair(T0), (processes, links)).records == []


def test_observed_start_change_and_shared_socket_references_remain_distinct():
    diff = _diff(_pair(T0), _pair(T1, [_process(ticks=2200)]))
    assert [(row["record_type"], row["change_type"]) for row in diff.records] == [
        ("process_change", "added"), ("process_change", "removed"),
        ("process_socket_link_change", "added"), ("process_socket_link_change", "removed")]
    processes = [_process(), _process(pid=220, ticks=2200, name="worker-b")]
    observations = parse_ss_text(_ss((("worker-b", 220), ("worker-a", 120))))
    assert link_processes_to_sockets(processes, observations) == link_processes_to_sockets(list(reversed(processes)), observations)
    assert [row.pid for row in link_processes_to_sockets(processes, observations)] == [120, 220]


@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_pid_candidates_are_rejected_without_selecting_by_order(reverse):
    processes = [_process(), _process(ticks=2200, name="worker-b")]
    if reverse:
        processes.reverse()
    with pytest.raises(ValueError, match="duplicate procfs pid"):
        link_processes_to_sockets(processes, parse_ss_text(_ss()))


def test_numeric_directory_aliases_do_not_create_two_instances_for_one_pid(tmp_path):
    _export(tmp_path, _process(), "120")
    _export(tmp_path, _process(ticks=2200, name="worker-b"), "0120")
    with pytest.raises(ValueError, match="duplicate procfs pid"):
        parse_procfs_root(tmp_path, host_id=HOST)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_diff_rejects_process_id_that_disagrees_with_observed_fields(phase):
    before, after = _pair(T0), _pair(T1)
    selected = before if phase == "before" else after
    selected[0].records[0]["process_id"] = "example-host:999:9999"
    with pytest.raises(ValueError, match="process_id must match host_id, pid and start_time_ticks"):
        _diff(before, after)


def test_diff_rejects_multiple_valid_identities_for_the_same_pid():
    before, after = _pair(T0), _pair(T1)
    after[0].records.append(_process(ticks=2200).to_dict())
    with pytest.raises(ValueError, match="duplicate process pid"):
        _diff(before, after)


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize(("field", "value"), [("pid", 999), ("executable", "/opt/example/bin/other"), ("uid", 0), ("gid", 0)])
def test_matching_times_do_not_admit_contradictory_procfs_context(phase, field, value):
    before, after = _pair(T0), _pair(T1)
    selected = before if phase == "before" else after
    selected[1].records[0][field] = value
    with pytest.raises(ValueError, match=f"linked socket {field} must match procfs process"):
        _diff(before, after)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_matching_times_do_not_admit_a_dangling_linked_identity(phase):
    before, after = _pair(T0), _pair(T1)
    selected = before if phase == "before" else after
    selected[1].records[0]["process_id"] = "example-host:120:9999"
    with pytest.raises(ValueError, match="linked socket process_id must reference the paired process artifact"):
        _diff(before, after)


@pytest.mark.parametrize("field", ["process_id", "executable", "uid", "gid"])
def test_unlinked_socket_cannot_claim_procfs_identity_or_context(field):
    before, after = _pair(T0), _pair(T1, observations=parse_ss_text(_ss((("unknown", 999),))))
    after[1].records[0][field] = _process().to_dict().get(field, 1001)
    with pytest.raises(ValueError, match="unlinked socket must not claim procfs identity or context"):
        _diff(before, after)


def test_adapter_rejects_a_self_consistent_label_with_contradictory_process_fields():
    diff = _diff(_pair(T0, [], []), _pair(T1))
    change = diff.records[0]
    change["identity"] = change["after"]["process_id"] = "example-host:999:9999"
    with pytest.raises(ValueError, match="process_id must match host_id, pid and start_time_ticks"):
        build_telemetry_events(diff)


def test_adapter_rejects_socket_change_identity_that_disagrees_with_observation():
    diff = _diff(_pair(T0, [], []), _pair(T1))
    diff.records[-1]["identity"] = "different-observation"
    with pytest.raises(ValueError, match="socket identity must match observation"):
        build_telemetry_events(diff)


def test_ss_name_only_change_preserves_context_without_inventing_a_link_event():
    before = _pair(T0)
    after = _pair(T1, observations=parse_ss_text(_ss((("worker-b", 120),))))
    assert after[1].records[0]["process_name"] == "worker-b"
    assert after[1].records[0]["linked"] is True
    assert _diff(before, after).records == []


def test_absent_pid_retains_an_unlinked_observation_and_pid_fallback():
    after = _pair(T1, observations=parse_ss_text(_ss((("worker-b", 999),))))
    link = after[1].records[0]
    assert link["linked"] is False and link["pid"] == 999
    assert all(link[field] is None for field in ("process_id", "executable", "uid", "gid"))
    events = build_telemetry_events(_diff(_pair(T0, [], []), after))
    assert events[-1]["source"] == f"{HOST}:pid:999"


@pytest.mark.parametrize(("field", "value"), [("pid", True), ("start_time_ticks", "1200")])
def test_non_integer_identity_components_are_rejected(field, value):
    before, after = _pair(T0), _pair(T1)
    after[0].records[0][field] = value
    with pytest.raises(ValueError, match="integer pid and start_time_ticks"):
        _diff(before, after)


@pytest.mark.parametrize(("field", "value"), [("uid", 0), ("process_id", "example-host:120:9999")])
def test_cli_rejects_contradictory_artifacts_without_creating_outputs(tmp_path, capsys, field, value):
    before, after = _pair(T0), _pair(T1)
    after[1].records[0][field] = value
    args = []
    inputs = {}
    for phase, pair in [("before", before), ("after", after)]:
        for kind, envelope in zip(["processes", "links"], pair):
            path = tmp_path / f"{phase}-{kind}.json"
            write_envelope(envelope, path)
            inputs[path] = path.read_bytes()
            args.extend([f"--{phase}-{kind}", str(path)])
    output = tmp_path / "not-created"
    assert main(["diff", *args, "--output-dir", str(output)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error command=diff input=artifacts" in captured.err
    assert "Traceback" not in captured.err
    assert not output.exists()
    assert all(path.read_bytes() == data for path, data in inputs.items())
