"""Independent manifest/observer checker. Does not import or invoke a C++ classifier."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path

EXIT = {"COMPLETED": 0, "EXITED_NONZERO": 1, "SIGNALED": 2, "TIMED_OUT": 3,
        "CANCELLED": 4, "LAUNCH_FAILED": 5, "POLICY_UNAVAILABLE": 6,
        "CONTAINMENT_UNCONFIRMED": 7, "SUPERVISOR_ERROR": 8}
LIMITS = ("cpu_soft", "cpu_hard", "address_space", "file_size", "open_files", "core_size")


def check(document: dict, observer: dict, capabilities: dict) -> list[str]:
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    try:
        require(document["schema"] == "exec-boundary.execution.v1", "schema")
        require(set(document) == {"schema", "request", "setup", "features", "outcome",
                                 "termination", "cleanup", "observed", "output",
                                 "enforcement_profile", "unsupported"}, "top-level shape")
        request, setup = document["request"], document["setup"]
        outcome, features = document["outcome"], document["features"]
        cleanup, observed = document["cleanup"], document["observed"]
        for field in ("no_new_privs", "limits_setup", "landlock", "seccomp"):
            if features[field]:
                require(setup["confirmed"], "unconfirmed setup control: " + field)
        state = outcome["state"]
        require(request["run_id"] == observer["run_id"], "run identity")
        require(request["request_id"] == observer["request_id"], "request identity")
        require(request["scenario"] == observer["scenario"], "scenario identity")
        require(request["profile"] == observer["profile"], "requested policy")
        require(state in observer["allowed_states"], "independent expected outcome")
        require(observer["cli_exit"] == EXIT.get(state), "CLI/report contradiction")
        if "expected_child_exit" in observer:
            require(outcome["exit_code"] == observer["expected_child_exit"], "expected child exit")
        if "expected_child_signal" in observer:
            require(outcome["signal"] == observer["expected_child_signal"], "expected child signal")
        require(observer["watchdog_fired"] is False, "external watchdog")
        require(observer["surviving_adopted"] == 0, "external child census")
        require(observer["unexpected_reaped"] == 0, "supervisor failed reaping obligation")
        require(cleanup["complete"] and cleanup["pipes_closed"], "cleanup incomplete")
        require(cleanup["owned_fd_delta"] == 0, "descriptor leak")
        require(cleanup["artifacts_removed"] and observer["scratch_delta"] == [],
                "temporary artifacts")
        require(cleanup["whole_tree_confirmed"] is False, "unsupported whole-tree claim")
        require(features["cgroup"] is False, "unsupported cgroup claim")
        if setup["spawned"]:
            require(cleanup["direct_child_reaped"], "direct child not reaped")
        else:
            for field in ("pidfd", "waitid_pidfd", "group_confirmed", "no_new_privs",
                          "limits_setup", "landlock", "seccomp", "cgroup"):
                require(features[field] is False, "unspawned control claimed: " + field)
        if cleanup["group_cleanup_attempted"]:
            require(cleanup["group_identity_pinned"] and features["group_confirmed"],
                    "unbound process group targeting")
        for field, capability in (("pidfd", "pidfd"), ("waitid_pidfd", "waitid_pidfd"),
                                  ("landlock", "landlock"), ("seccomp", "seccomp")):
            if features[field]:
                require(capabilities[capability] == "SUPPORTED_AND_TESTED",
                        "unsupported capability active: " + field)
        require(outcome["exit_code"] is None or outcome["signal"] is None,
                "exit and signal mutually exclusive")
        if outcome["wait_code"] == 1:
            require(outcome["exit_code"] == outcome["wait_status"] and
                    outcome["signal"] is None, "observed exit status")
        elif outcome["wait_code"] in (2, 3):
            require(outcome["signal"] == outcome["wait_status"] and
                    outcome["exit_code"] is None, "observed signal status")
        if state == "COMPLETED":
            require(setup["exec_observed"] and outcome["exit_code"] == 0 and
                    outcome["signal"] is None and not outcome["timed_out"] and
                    not outcome["cancelled"], "completed classification")
        elif state == "EXITED_NONZERO":
            require(setup["exec_observed"] and isinstance(outcome["exit_code"], int) and
                    outcome["exit_code"] > 0 and outcome["signal"] is None,
                    "nonzero classification")
        elif state == "SIGNALED":
            require(setup["exec_observed"] and isinstance(outcome["signal"], int) and
                    outcome["signal"] > 0 and outcome["exit_code"] is None,
                    "signaled classification")
        elif state == "TIMED_OUT":
            require(outcome["timed_out"] and document["termination"]["term_attempted"] and
                    outcome["elapsed_ms"] >= request["timeout_ms"], "timeout classification")
        elif state == "CANCELLED":
            require(outcome["cancelled"] and document["termination"]["term_attempted"],
                    "cancellation classification")
        elif state == "POLICY_UNAVAILABLE":
            require(not setup["spawned"] and not setup["exec_observed"] and
                    not setup["confirmed"], "policy refusal launched child")
        elif state == "LAUNCH_FAILED":
            require(not setup["exec_observed"], "failed launch claims exec witness")
        if setup["exec_observed"]:
            require(observed["child_pid"] == observed["pgid"] == observed["sid"] and
                    observed["child_pid"] > 1, "dedicated session/group")
            require(setup["confirmed"] and features["pidfd"] and features["waitid_pidfd"],
                    "exec without setup or exact wait")
            require(features["no_new_privs"] and observed["nnp"] == 1,
                    "no_new_privs enforcement")
            require(features["limits_setup"], "resource setup absent")
            for field in LIMITS:
                require(request["limits"][field] == observed[field],
                        "resource limit differs: " + field)
            require(observed["core_size"] == 0, "core dump limit")
            if state != "CONTAINMENT_UNCONFIRMED":
                require(observed["unexpected_fds"] == 0, "unexpected inherited descriptor")
            expected_mode = 2 if features["seccomp"] else observed["inherited_seccomp"]
            require(observed["seccomp"] == expected_mode,
                    "seccomp installed/inherited/observed mismatch")
        if features["landlock"]:
            require(request["profile"] == "landlock" and features["landlock_abi"] >= 3,
                    "Landlock profile/ABI")
            require(set(features["landlock_rights"]) ==
                    {"READ_FILE", "READ_DIR", "WRITE_FILE", "MAKE_REG", "REMOVE_FILE", "TRUNCATE"},
                    "Landlock rights")
        else:
            require(features["landlock_rights"] == [], "unenforced Landlock rights")
        if setup["exec_observed"] and state in ("COMPLETED", "EXITED_NONZERO", "SIGNALED"):
            require(features["landlock"] == (request["profile"] == "landlock"),
                    "silent Landlock downgrade")
            require(features["seccomp"] == (request["profile"] == "seccomp"),
                    "silent seccomp downgrade")
        for channel in ("stdout", "stderr"):
            captured = document["output"][channel]
            raw = bytes.fromhex(captured["hex"])
            require(len(raw) == captured["captured_bytes"] <= request["output_limit"],
                    "bounded output " + channel)
            require(captured["total_bytes"] >= len(raw), "output byte accounting")
            require(captured["truncated"] == (captured["total_bytes"] > len(raw)),
                    "output truncation metadata")
            expected = observer.get("expected_" + channel)
            if expected is not None:
                expected = expected.encode()
                require(raw == expected[:request["output_limit"]], "fixture output " + channel)
                require(captured["total_bytes"] == len(expected), "fixture output total")
        require(outcome["elapsed_ms"] <= request["timeout_ms"] + 1200,
                "bounded cleanup time")
    except (KeyError, TypeError, ValueError) as error:
        errors.append("malformed contract: " + str(error))
    return errors


def corruptions(document):
    edits = {
        "termination_reason": ("outcome", "state", "SIGNALED"),
        "exit_code": ("outcome", "exit_code", 42),
        "capability_flag": ("features", "cgroup", True),
        "cleanup_status": ("cleanup", "direct_child_reaped", False),
        "resource_state": ("observed", "open_files", 999),
        "run_identity": ("request", "run_id", "wrong-run"),
        "truncation_metadata": ("output", "stdout", None),
        "false_seccomp": ("features", "seccomp", True),
        "false_landlock": ("features", "landlock", True),
    }
    for name, (section, field, value) in edits.items():
        changed = copy.deepcopy(document)
        if name == "truncation_metadata":
            changed[section][field]["truncated"] = not changed[section][field]["truncated"]
        else:
            changed[section][field] = value
        yield name, changed


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("observer", type=Path)
    parser.add_argument("capabilities", type=Path)
    args = parser.parse_args()
    problems = check(*(json.loads(path.read_text()) for path in
                       (args.manifest, args.observer, args.capabilities)))
    print(json.dumps({"accepted": not problems, "errors": problems}))
    raise SystemExit(bool(problems))
