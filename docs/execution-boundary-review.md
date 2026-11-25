# Review the Linux execution boundary

Start in [the C++20 lab](../projects/linux-exec-boundary/README.md). Build as an ordinary Linux user on a native filesystem and run CTest. The tests launch a fixed, locally built child and collect independent observations alongside the supervisor's manifest.

| Review question | Evidence to inspect |
| --- | --- |
| Who owns the child after fork, and when did exec succeed? | [Execution contract](../projects/linux-exec-boundary/EXECUTION-CONTRACT.md) and the post-exec fixture witness |
| Which kernel controls actually took effect? | [Capability matrix](../projects/linux-exec-boundary/CAPABILITY-MATRIX.json), including Landlock access checks and the request-local seccomp probe |
| What happens at an output, CPU, address-space or time limit? | [Failure matrix](../projects/linux-exec-boundary/FAILURE-MATRIX.json) and the watchdog results for the current kernel |
| Which descriptors and processes survive cleanup? | [Repeated lifecycle test](../projects/linux-exec-boundary/tests/lifecycle.cpp), descriptor delta, direct-child wait status and descendant census |
| Can a failed setup be reported as successful enforcement? | [Independent audit](../projects/linux-exec-boundary/INDEPENDENT-AUDIT.md) and [rejected observations](../projects/linux-exec-boundary/NEGATIVE-CONTROLS.json) |

Follow the [reproduction commands](../projects/linux-exec-boundary/REPRODUCTION.md) to generate the capability probe, manifest and Markdown report. A clean GCC build of the merged lab passed both CTests. All 155 tests across the four Python labs also passed. The normal CLI example reported a post-exec witness, a reaped direct child and zero owned-descriptor delta. The [PR compiler matrix](https://github.com/stacknil/systems-foundations/actions/runs/40954448399) records the hosted GCC and Clang runs.

Whole-tree admission refuses before fork without verified containment. The native detached-descendant case remains unexecuted. Local sanitizer results, hosted compiler results and conditional kernel coverage have separate scopes.
