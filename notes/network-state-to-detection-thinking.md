# SF-01: network state to detection thinking

## Purpose

`linux-socket-observe` shows how local network state changed between two saved snapshots.

Detection thinking starts after that diff: ask what the new or changed state could mean, what benign explanation might exist, and what extra evidence should be checked before treating it as suspicious.

This note is not a detection rule set. It is a small bridge from snapshot diff output to reviewer-friendly investigation questions.

## From diff to question

| Diff signal | Detection question | First benign checks |
| --- | --- | --- |
| Listening port appeared | Did a new service start accepting connections? | Package update, service restart, planned deployment, temporary admin tool |
| Remote endpoint changed | Did an existing process start talking to a new peer? | DNS change, failover, new client, expected control-plane endpoint |
| Unexpected process binding | Is the process name or PID expected for this port and address? | Service manager unit, container runtime, renamed process, wrapper script |
| Local-only vs external exposure | Did a service move from loopback-only to externally reachable? | Config change, bind address default, reverse proxy change, interface/address change |

## Listening port appeared

A new listening socket means the host is now accepting connections on a local address and port that did not appear in the earlier snapshot.

Useful fields:

- `sockets[].state`
- `sockets[].local_address`
- `sockets[].local_port`
- `sockets[].processes`
- `sockets[].pids`

Detection prompts:

- Is the port expected for this host role?
- Is the bind address narrow, such as `127.0.0.1`, or broad, such as `0.0.0.0` or `::`?
- Is the process name expected for that port?
- Did the interface or address set change at the same time?

Evidence to preserve:

- the before and after snapshot JSON
- the Markdown diff
- the raw `ss` line from the fixture or command output when available
- related service manager or auth evidence from the same time window

## Remote endpoint changed

A changed established socket can mean normal client churn, but it can also show a process communicating with a new destination.

Useful fields:

- `sockets[].peer_address`
- `sockets[].peer_port`
- `sockets[].processes`
- `sockets[].pids`

Detection prompts:

- Is the new peer address in an expected network range?
- Is the peer port expected for the process?
- Did only the remote endpoint change, or did the process binding also change?
- Is this a long-running connection, a short client session, or a listening socket being compared as state?

Be careful: a snapshot pair does not prove persistence or intent. It only proves that the state differed at the two capture points.

## Unexpected process binding

A process binding is suspicious when the process name, PID, local address, or port does not fit the expected host role.

Examples of questions:

- Why is a scripting runtime listening on a network-facing address?
- Why did a service move from one port to another?
- Why is a process without an expected service name bound to a privileged port?
- Does the process match a known unit or package on the host?

The `processes` and `pids` fields are useful context, not perfect identity guarantees. PIDs can be reused, process names can be misleading, and snapshots may miss short-lived activity.

## Local-only vs external exposure

Bind address changes are often more important than port changes.

Common exposure patterns:

- `127.0.0.1:PORT` means loopback-only IPv4.
- `::1:PORT` means loopback-only IPv6.
- `0.0.0.0:PORT` means all IPv4 interfaces.
- `:::PORT` or `[::]:PORT` means broad IPv6 binding, depending on how the tool prints the endpoint.
- a specific interface address, such as `192.0.2.10:PORT`, means the service is bound to that local address.

Detection prompts:

- Did a service move from loopback-only to all interfaces?
- Did a service bind to a new interface after an address was added?
- Did the interface state or MTU change at the same time?
- Is this exposure expected, documented, and covered by host or network policy?

## What this mini-lab can and cannot prove

It can show:

- a socket was added or removed between two snapshots
- a local or remote endpoint changed
- interface, address, or neighbor state changed
- best-effort process context from `ss`

It cannot show by itself:

- packet contents
- exact process start time
- long-term persistence
- whether a connection was malicious
- historical state outside the two snapshots

Use the diff as a triage lead, then pivot to logs, service metadata, package history, change records, and other evidence.
