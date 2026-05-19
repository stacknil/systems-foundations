# ss and iproute2 basics

## Why these inputs matter

Linux networking state is often easiest to inspect from local command output rather than packet capture.

This mini-lab focuses on two common sources:

- `ss` for current socket state
- `iproute2` commands for interface, address, and neighbor state

## What each command contributes

- `ss` shows listening and established sockets, queue depth, endpoints, and best-effort process context
- `ip -j link show` shows interface identity and link state
- `ip -j addr show` shows addresses assigned to each interface
- `ip -j neigh show` shows neighbor cache entries such as ARP or NDP state
- `ip -s -s link show` can add interface counters if you want a richer snapshot

## Why JSON plus text

The `ip -j ...` commands already provide structured JSON, so they are a good fit for deterministic normalization.

`ss` is commonly available as text output, so this mini-lab normalizes a bounded text format instead of reaching into kernel tables directly.

## Intentional limits

- no `/proc/net/tcp`
- no packet capture or pcap parsing
- no live capture
- no raw sockets or packet sockets

The goal is a small, reviewable snapshot lab for state comparison, not full network forensics.
