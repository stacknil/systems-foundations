"""Bounded native scenarios; only this run's own supervisor/fixture children are targeted."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

from oracle import check, corruptions


def landlock_profile_supported(capabilities):
    return (capabilities["landlock"] == "SUPPORTED_AND_TESTED" and
            capabilities["landlock_abi"] >= 3)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def external_limits(sanitized=False):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 4))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if not sanitized:
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))


def owned_children():
    # Only direct children of this watchdog, never a host-wide process scan.
    path = Path(f"/proc/self/task/{os.getpid()}/children")
    return [int(value) for value in path.read_text().split()]


def signal_exact(descriptor, sig):
    try:
        signal.pidfd_send_signal(descriptor, sig)
    except ProcessLookupError:
        pass


def census():
    unexpected = 0
    end = time.monotonic() + 0.2
    while time.monotonic() < end:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return unexpected, 0
        if pid:
            unexpected += 1
        else:
            time.sleep(0.002)
    return unexpected, len(owned_children())


def native_case(binary, output, capabilities, label, scenario, allowed, *,
                profile="direct", fault="none", timeout=300, cancel=-1,
                output_limit=256, send=None, expected_out=None,
                expected_err=None, expected_child_exit=None, expected_child_signal=None,
                sanitized=False):
    case_dir = output / label
    scratch = case_dir / "scratch"
    scratch.mkdir(parents=True)
    request_id, run_id = "request-" + label, "run-" + label
    argv = [str(binary), "--scenario", scenario, "--profile", profile,
            "--fault", fault, "--request-id", request_id, "--run-id", run_id,
            "--timeout-ms", str(timeout), "--cancel-after-ms", str(cancel),
            "--output-limit", str(output_limit)]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "TMPDIR": str(scratch),
                   "ASAN_OPTIONS": "allocator_may_return_null=1:detect_leaks=1:"
                   "quarantine_size_mb=8:hard_rss_limit_mb=128",
                   "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
    before_fds = len(os.listdir("/proc/self/fd"))
    started = time.monotonic()
    # Give the supervisor an unexpected inherited FD; its child must not inherit it.
    sentinel = os.open("/dev/null", os.O_RDONLY)
    os.dup2(sentinel, 57, inheritable=True)
    os.close(sentinel)
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, pass_fds=(57,),
                               preexec_fn=lambda: external_limits(sanitized))
    os.close(57)
    descriptor = os.pidfd_open(process.pid)
    if send is not None:
        ready_deadline = time.monotonic() + 0.4
        while time.monotonic() < ready_deadline and process.poll() is None:
            child_path = Path(f"/proc/{process.pid}/task/{process.pid}/children")
            try:
                if child_path.read_text().strip():
                    break
            except FileNotFoundError:
                break
            time.sleep(0.002)
        if send == "term":
            time.sleep(0.015)
            signal_exact(descriptor, signal.SIGTERM)
        elif send == "interrupt":
            for _ in range(35):
                if process.poll() is not None:
                    break
                signal_exact(descriptor, signal.SIGUSR1)
                time.sleep(0.002)
    fired = False
    try:
        raw, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        fired = True
        signal_exact(descriptor, signal.SIGKILL)
        raw, stderr = process.communicate(timeout=2)
    finally:
        os.close(descriptor)
    unexpected, survivors = census()
    # Last-resort recovery targets only unreaped children of this exclusive watchdog.
    if survivors:
        for pid in owned_children():
            child_fd = os.pidfd_open(pid)
            signal_exact(child_fd, signal.SIGKILL)
            os.close(child_fd)
        for _ in range(100):
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                time.sleep(0.002)
    wall = time.monotonic() - started
    observer = {"request_id": request_id, "run_id": run_id, "scenario": scenario,
                "profile": profile, "allowed_states": allowed, "cli_exit": process.returncode,
                "watchdog_fired": fired, "unexpected_reaped": unexpected,
                "surviving_adopted": survivors,
                "scratch_delta": [p.name for p in scratch.iterdir()],
                "wall_seconds": wall, "external_cpu_hard_seconds": 4,
                "external_fsize_bytes": 2 * 1024 * 1024,
                "external_as_bytes": None if sanitized else 384 * 1024 * 1024,
                "asan_rss_watchdog_mb": 128 if sanitized else None}
    if expected_out is not None:
        observer["expected_stdout"] = expected_out
    if expected_err is not None:
        observer["expected_stderr"] = expected_err
    if expected_child_exit is not None:
        observer["expected_child_exit"] = expected_child_exit
    if expected_child_signal is not None:
        observer["expected_child_signal"] = expected_child_signal
    (case_dir / "stdout.json").write_bytes(raw)
    (case_dir / "stderr.txt").write_bytes(stderr)
    save(case_dir / "observer.json", observer)
    assert len(os.listdir("/proc/self/fd")) == before_fds, "watchdog leaked descriptors"
    assert not stderr, (label, stderr.decode(errors="replace")[:500])
    document = json.loads(raw)
    problems = check(document, observer, capabilities)
    save(case_dir / "oracle.json", {"accepted": not problems, "errors": problems})
    assert not problems, (label, problems, document["outcome"])
    assert wall < 5, (label, wall)
    return document, observer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--supervisor", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sanitized", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() != 0, "unprivileged execution required"
    # A private watchdog subreaper catches any descendant the supervisor failed to reap.
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    output = args.output.resolve()
    if output.exists():
        # No deletion: each CTest invocation retains a separate receipt directory.
        output = output.with_name(output.name + "-" + str(os.getpid()))
    output.mkdir(parents=True)
    probe = subprocess.run([str(args.probe)], capture_output=True, timeout=8,
                           preexec_fn=external_limits)
    assert probe.returncode == 0, probe.stderr.decode(errors="replace")
    capabilities = json.loads(probe.stdout)
    save(output / "capabilities.json", capabilities)
    results = {}
    documents = {}

    def run(label, scenario, states, **kwargs):
        document, observer = native_case(args.supervisor, output, capabilities,
                                        label, scenario, states,
                                        sanitized=args.sanitized, **kwargs)
        results[label] = {"status": "PASS", "state": document["outcome"]["state"],
                          "elapsed_ms": document["outcome"]["elapsed_ms"],
                          "adopted_reaped": document["cleanup"]["adopted_reaped"],
                          "interrupted_calls": document["observed"]["interrupted_calls"],
                          "cleanup_interruptions": document["observed"]["cleanup_interruptions"],
                          "signal_notifications": document["observed"]["signal_notifications"],
                          "cleanup_signal_notifications": document["observed"]["cleanup_signal_notifications"],
                          "oracle": "accepted"}
        documents[label] = (document, observer)
        return document

    run("normal", "normal", ["COMPLETED"], expected_out="normal\n", expected_err="")
    run("nonzero", "nonzero", ["EXITED_NONZERO"], expected_child_exit=42)
    run("signal", "signal", ["SIGNALED"], expected_child_signal=signal.SIGUSR2)
    run("E01-immediate", "immediate", ["COMPLETED"], expected_out="normal\n")
    run("E01-before-pidfd", "normal", ["LAUNCH_FAILED"], fault="exit_before_pidfd")
    run("pidfd-failure", "normal", ["LAUNCH_FAILED"], fault="pidfd")
    for index, schedule in enumerate((0, 2, 20, 35)):
        run("E02-cancel-" + str(index), "short",
            ["COMPLETED", "CANCELLED"], cancel=schedule)
    for index, deadline in enumerate((1, 20, 40)):
        run("E03-timeout-" + str(index), "short",
            ["COMPLETED", "TIMED_OUT"], timeout=deadline)
    run("E04-exec", "normal", ["LAUNCH_FAILED"], fault="exec")
    run("E05-stdout-closed", "close-stdout", ["COMPLETED"],
        expected_out="", expected_err="stderr-retained\n")
    run("partial", "partial", ["COMPLETED"], expected_out="abc", expected_err="error")
    run("broken-pipe", "broken-pipe", ["SIGNALED"], expected_child_signal=signal.SIGPIPE)
    run("E06-output", "flood", ["COMPLETED"], timeout=1000,
        expected_out="x" * 262144, expected_err="x" * 262144)
    run("zero-capture", "normal", ["COMPLETED"], output_limit=0, expected_out="normal\n")
    run("E07-tree", "tree", ["TIMED_OUT"], timeout=80,
        expected_out="cooperating-descendant-started\n")
    assert results["E07-tree"]["adopted_reaped"] == 1
    run("E08-orphan", "orphan", ["COMPLETED"])
    assert results["E08-orphan"]["adopted_reaped"] == 1
    results["E09-detached"] = {"status": "NOT_RUN",
                             "reason": "no verified delegated secondary containment; no detached fixture supplied",
                             "static_control": "strict-tree refuses before fork; process-group limit documented"}
    run("E10-cpu", "cpu", ["SIGNALED"], timeout=2200, expected_child_signal=signal.SIGXCPU)
    run("E10-memory", "memory", ["COMPLETED"], expected_out="allocation-denied-ENOMEM\n")
    run("E10-fsize", "fsize", ["SIGNALED"], expected_child_signal=signal.SIGXFSZ)
    run("E10-nofile", "nofile", ["COMPLETED"], expected_out="open-denied-EMFILE\n")
    run("core-disabled", "abnormal", ["SIGNALED"], expected_child_signal=signal.SIGABRT)
    run("E11-unavailable", "normal", ["POLICY_UNAVAILABLE"], fault="landlock_unavailable")
    run("E12-seccomp-failure", "normal", ["LAUNCH_FAILED"], profile="seccomp", fault="seccomp_setup")
    run("E13-strict", "normal", ["POLICY_UNAVAILABLE"], profile="strict-tree")
    run("E14-interrupted", "ignore-term", ["TIMED_OUT"], timeout=30, send="interrupt")
    assert results["E14-interrupted"]["signal_notifications"] > 0
    assert results["E14-interrupted"]["cleanup_signal_notifications"] > 0
    run("E15-inherit", "normal", ["CONTAINMENT_UNCONFIRMED"], fault="inherit_fd")
    pid = os.fork()
    if pid == 0:
        signal.alarm(2)
        os._exit(0)
    pidfd = os.pidfd_open(pid)
    os.waitpid(pid, 0)
    stale = False
    try:
        signal.pidfd_send_signal(pidfd, 0)
    except ProcessLookupError:
        stale = True
    os.close(pidfd)
    assert stale
    results["E16-stale"] = {"status": "PASS", "evidence": "own reaped child pidfd returns ESRCH; no numeric retarget"}
    run("E19-parent-term", "sleep", ["CANCELLED"], timeout=500, send="term")
    run("E20-artifact", "artifact-failure", ["EXITED_NONZERO"], expected_child_exit=42)
    for abi in (1, 2, 3, 7):
        assert landlock_profile_supported({"landlock": "SUPPORTED_AND_TESTED",
                                           "landlock_abi": abi}) == (abi >= 3)
    assert not landlock_profile_supported({"landlock": "UNAVAILABLE", "landlock_abi": 7})
    if landlock_profile_supported(capabilities):
        run("landlock", "landlock", ["COMPLETED"], profile="landlock",
            expected_out="read-write-dir-create-remove-truncate:allowed-and-denied\n")
    else:
        results["landlock"] = {"status": "UNSUPPORTED", "reason": "full profile requires tested Landlock ABI >= 3"}
    if capabilities["seccomp"] == "SUPPORTED_AND_TESTED":
        run("seccomp", "seccomp", ["COMPLETED"], profile="seccomp",
            expected_out="getppid-denied-EPERM;getpid-allowed\n")
        run("seccomp-control", "seccomp", ["COMPLETED"], expected_out="getppid-allowed\n")
    else:
        results["seccomp"] = {"status": "UNSUPPORTED", "reason": "actual capability probe"}
    negative = {}
    failed, failure_observer = documents["E12-seccomp-failure"]
    for field in ("no_new_privs", "limits_setup", "landlock", "seccomp"):
        changed = json.loads(json.dumps(failed))
        changed["features"][field] = True
        problems = check(changed, failure_observer, capabilities)
        negative["unconfirmed_" + field] = {"rejected": bool(problems), "errors": problems}
        assert problems, "unconfirmed_" + field
    refused, refusal_observer = documents["E13-strict"]
    for field in ("pidfd", "waitid_pidfd", "group_confirmed", "no_new_privs",
                  "limits_setup", "landlock", "seccomp", "cgroup"):
        changed = json.loads(json.dumps(refused))
        changed["features"][field] = True
        problems = check(changed, refusal_observer, capabilities)
        negative["unspawned_" + field] = {"rejected": bool(problems), "errors": problems}
        assert problems, "unspawned_" + field
    baseline, observer = documents["normal"]
    for label, changed in corruptions(baseline):
        problems = check(changed, observer, capabilities)
        negative[label] = {"rejected": bool(problems), "errors": problems}
        assert problems, label
    results["E17-false-enforcement"] = {"status": "PASS", "evidence": "oracle rejects cgroup/seccomp/Landlock flag corruptions"}
    results["E18-report-status"] = {"status": "PASS", "evidence": "oracle rejects termination/exit corruptions"}
    save(output / "negative-controls.json", negative)
    save(output / "results.json", results)
    print(json.dumps({"passed": sum(row["status"] == "PASS" for row in results.values()),
                      "not_run": [key for key, row in results.items() if row["status"] != "PASS"],
                      "negative_controls_rejected": len(negative),
                      "evidence_directory": str(output)}))


if __name__ == "__main__":
    main()
