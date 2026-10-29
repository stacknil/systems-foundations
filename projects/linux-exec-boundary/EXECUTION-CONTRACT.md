# Execution contract

## Problem and invariant

A successful fork does not prove exec succeeded, a numeric PID is not a lasting
target, and a successful group kill does not establish whole-tree containment.
Reports separate attempted setup, acknowledged controls and observed outcome.
A strict unsupported profile is refused before launching a fixture.

This is a single-request, dedicated-supervisor-process API. The caller must not
run concurrent requests, create unrelated children concurrently, run another
reaper or install SIGCHLD ignore/SA_NOCLDWAIT. Existing direct children and an
already active subreaper cause refusal. The CLI owns the complete process and
uses fixed fixture arguments; the C++ header is not a general embedding SDK.

## ExecutionRequest

- request_id and run_id: required 1-64 character alphanumeric, hyphen or
  underscore labels. They are run labels, not durable OS identities.
- approved_executable: CMake's local fixture, opened O_PATH/CLOEXEC before fork
  and executed through that descriptor using execveat.
- arguments: exactly boundary_fixture and one allowlisted synthetic scenario.
- environment: exactly LANG=C and LC_ALL=C; stdin is /dev/null.
- working_directory: a newly owned mkdtemp directory under caller TMPDIR.
  Only this invocation's directory is removed.
- timeout_ms: 1-3000, measured from execute entry with steady_clock.
- output_limit: 0-16384 retained bytes per stream. Total observed bytes remain
  distinct from retained bytes.
- limits: CPU soft/hard 1/2 seconds, AS 32-256 MiB, FSIZE at most 1 MiB,
  NOFILE 16-64, CORE zero. CLI defaults: AS 128 MiB, FSIZE 4096 (1024 for the
  file-size scenario), NOFILE 32.
- profile: direct, landlock or seccomp. strict-tree and unknown profiles refuse
  execution. cancel_after_ms supplies a bounded synthetic cancellation
  schedule; SIGTERM/SIGINT provide external cancellation.
- injected_fault: a transparent, allowlisted lab control recorded in results.

## Design decisions

The child closes unexpected descriptors with close_range. Standard I/O, the
CLOEXEC executable/error descriptors, the launch gate and an intentional
fixture-witness descriptor are the only setup descriptors. The fixture closes
its witness descriptor before the scenario and reports unexpected descriptors.

Fork does not atomically return a pidfd. The child waits on the gate while the
parent opens its pidfd and retains exclusive unreaped-child ownership. A child
that exits early remains a zombie until this parent reaps it, preventing PID
reuse under the stated SIGCHLD/reaper preconditions. Acquisition failure aborts
launch and recovery targets only the still-owned unreaped direct child. There
is no silent numeric-target execution fallback. Atomic clone3/CLONE_PIDFD is
not claimed or required.

The child creates its own session. The parent confirms PGID=SID=child PID before
opening the gate, and validates both values again before group signals. Other
existing-session processes cannot join this dedicated session. The leader
remains unreaped during group cleanup, pinning its identity. A descendant can
still create another session; this is not whole-tree containment.

Child setup sets limits, no_new_privs and requested restrictions, then
acknowledges success. A separate post-exec fixture witness reports PID/PGID/SID,
observed no_new_privs/seccomp mode, resource values and descriptor census.
Neither an ack nor EOF alone proves exec. The witness is trusted synthetic
instrumentation, not authentication against a malicious replacement binary.

## Result and classification

Schema: exec-boundary.execution.v1. Request/run identity, stage/errno,
request-local features, inherited/observed policy, raw waitid status, stop
decisions, bounded capture, cleanup evidence and unsupported controls remain
separate.

| State | CLI exit | Condition |
| --- | ---: | --- |
| COMPLETED | 0 | Exec witnessed, normal zero exit, no stop decision |
| EXITED_NONZERO | 1 | Exec witnessed, normal nonzero exit |
| SIGNALED | 2 | Exec witnessed, kernel signal termination observed |
| TIMED_OUT | 3 | Deadline stop decision preceded observed termination |
| CANCELLED | 4 | Cancellation stop decision preceded observed termination |
| LAUNCH_FAILED | 5 | Spawn/exec/setup failed or no valid exec witness |
| POLICY_UNAVAILABLE | 6 | Requested control refused before fork |
| CONTAINMENT_UNCONFIRMED | 7 | Cleanup or inherited-FD boundary unconfirmed |
| SUPERVISOR_ERROR | 8 | Supervisor precondition/accounting/artifact failure |

Unconfirmed containment takes precedence over nominal completion. A timeout or
cancellation decision is retained even if later setup/exit evidence arrives;
an exit/stop race may report that decision with exit zero. This does not assert
that a signal caused the exit. Raw child exit/signal is not the CLI status.

Inherited seccomp mode 2 does not establish request-local installation.
features.seccomp means this request successfully installed the filter;
inherited and post-exec modes are separate. Landlock has no general policy
introspection API: successful setup and controlled post-exec allowed/denied
operations support the narrow claim.

Cleanup waits are bounded observations, not hard real-time guarantees for
uninterruptible kernel tasks. Missing reaping within the window is
CONTAINMENT_UNCONFIRMED. Parent SIGTERM requests cancellation. SIGKILL, machine
failure and hostile supervisor modification are outside the guarantee.

## Compatibility and validation

No saved-evidence schema, source label, fixture, golden, adapter or root workflow
changes. The independent checker consumes manifests and watchdog observations;
it never calls this classifier to derive expected answers. It rejects false
termination, capability, cleanup, resource, identity and truncation claims.

Matrices retain conditional results and NOT_RUN. Repeated schedules are race
controls, not independent semantic coverage. See REPRODUCTION.md and the
independent audit for actual execution evidence.
