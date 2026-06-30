# 408 to Linux security

## Purpose

408-style operating system knowledge becomes useful for security work when it turns into evidence:

- which process existed
- which file changed
- which permission allowed access
- which socket exposed a service
- which log preserves the event

This note maps low-level Linux concepts to the kind of evidence a defender or reviewer can inspect.

## Process

An OS process is a running execution context. In security review, process evidence helps answer what was running and under which identity.

Useful evidence:

- process name and arguments
- PID and parent PID
- effective user and group
- service manager unit when available
- open sockets or files

Security questions:

- Is this process expected for the host role?
- Is it running as a user with more privilege than needed?
- Does it match a known service, package, or deployment?
- Did it appear near an auth, permission, or network-state change?

## File

Files are where system state, configuration, scripts, logs, keys, and data live. File evidence often explains what changed, not just what executed.

Useful evidence:

- path
- file type
- owner and group
- mode bits
- size or hash when available
- modification metadata when collected safely

Security questions:

- Did a sensitive file become writable by a broader group?
- Did a new executable appear in a trusted path?
- Did ownership change away from the expected system account?
- Does a config file change explain a new process or socket state?

## Permission

Permissions connect users, groups, and files. They are the bridge between "the object exists" and "who could change or execute it."

Useful evidence:

- numeric mode, such as `0644` or `0755`
- owner user
- owner group
- group membership
- sudoers rules

Security questions:

- Did `chmod` make a file world-writable or executable?
- Did `chown` move control to a less expected user?
- Did group membership add a user to an administrative group?
- Did sudoers grant passwordless or broad command access?

## Socket

Sockets expose local processes to local or remote communication. A socket is not proof of compromise, but it is strong evidence of runtime network posture.

Useful evidence:

- protocol and state
- local address and port
- peer address and port
- process context from `ss`
- interface and address state from `iproute2`

Security questions:

- Did a listening port appear?
- Did a service move from loopback-only to externally reachable?
- Did a process start talking to a new remote endpoint?
- Is the bound process expected for that port?

## Log

Logs preserve event evidence after volatile state disappears. They connect process, file, permission, and socket observations to time.

Useful evidence:

- timestamp
- host
- service or unit
- user
- source IP when present
- raw message

Security questions:

- Does an auth event line up with a process or permission change?
- Did sudo or su activity happen before a file drift?
- Did service start or failure logs line up with a new listening socket?
- Is the raw log line preserved for reviewer traceability?

## Bridge pattern

Use this chain when turning foundations knowledge into security evidence:

1. Identify the low-level object: process, file, permission, socket, or log.
2. Normalize the state into a small stable record.
3. Compare state over time when possible.
4. Ask what changed and whether the change matches host intent.
5. Preserve raw evidence or command output beside the normalized artifact.

The goal is not to claim full detection coverage. The goal is to make lower-level evidence assumptions explicit enough that later tools, such as LogLens or telemetry-lab, can build on them.

