# Linux execution boundary lab

A C++20 Linux supervisor for bounded, locally compiled synthetic fixtures. It
examines process identity, launch failure, deadlines, cancellation, resource
limits and truthful enforcement reports. This is an empirical lab, not a
production sandbox or a container runtime.

The standalone CLI only launches its CMake-built sibling fixture. There is no
arbitrary executable or shell-command option. Use a non-root Linux user and a
native filesystem. Do not run the build under sudo.

## Build and reproduce

~~~sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure

build/capability_probe
build/exec_boundary --scenario normal --run-id example-run > execution.json
python3 tools/render_report.py execution.json execution.md
~~~

Python 3.11+ supplies the dependency-free watchdog and independent manifest
checker. No downloaded executable, third-party C++ library, cloud account or
root CI change is needed. [REPRODUCTION.md](REPRODUCTION.md) includes Clang,
sanitizer and evidence commands.

## Boundaries and results

- Forked children wait on a parent gate until their pidfd and dedicated
  session/process group are established. An open executable descriptor pins the
  inode for execveat; it does not authenticate executable contents.
- A post-exec fixture witness is required for a successful launch claim. Pipe
  EOF alone is insufficient.
- Deadlines use steady_clock. Output retention is bounded separately for stdout
  and stderr; excess bytes are counted and discarded while deadline checks
  continue. This is a capture limit, not a producer-output quota.
- The unreaped leader pins process-group identity during cleanup. Direct
  children and adopted cooperating descendants are reaped. A process group does
  not contain descendants that create another session.
- Landlock and a narrow seccomp getppid denial experiment are installed before
  exec, or execution fails. They do not form a general-purpose sandbox.
- Strict whole-tree requests return POLICY_UNAVAILABLE before fork. The tested
  WSL2 environment has no writable cgroup delegation. The native detached-
  descendant case is NOT_RUN without verified secondary containment.

CLI exit codes 0-8 map to COMPLETED, EXITED_NONZERO, SIGNALED, TIMED_OUT,
CANCELLED, LAUNCH_FAILED, POLICY_UNAVAILABLE, CONTAINMENT_UNCONFIRMED and
SUPERVISOR_ERROR. The child exit code/signal is reported separately.

The checked-in JSON files describe the qualification environment, not another
kernel. Re-run the capability probe. Dynamic PIDs, elapsed times and race
winners are not deterministic identities.

See [EXECUTION-CONTRACT.md](EXECUTION-CONTRACT.md),
[THREAT-MODEL.md](THREAT-MODEL.md), [CAPABILITY-MATRIX.json](CAPABILITY-MATRIX.json),
[FAILURE-MATRIX.json](FAILURE-MATRIX.json) and
[INDEPENDENT-AUDIT.md](INDEPENDENT-AUDIT.md).

The four saved-evidence Python mini-labs remain independent and unchanged.
