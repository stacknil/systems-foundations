# v0.2.0 Release Notes

## Title

Second Credible Mini-Lab

## Summary

`systems-foundations` adds a second focused mini-lab: `projects/linux-socket-observe`.

This release packages a narrow workflow for reviewing local Linux networking state from saved command-output snapshots:

- build one normalized JSON snapshot from `ss` plus selected `iproute2` outputs
- compare two snapshots deterministically
- generate a Markdown diff report for added, removed, and changed state
- keep the workflow local-file-based and reviewable

## Included in v0.2.0

- support for `ss` text input
- support for `ip -j addr show`
- support for `ip -j link show`
- support for `ip -j neigh show`
- optional support for `ip -s -s link show`
- one normalized snapshot artifact with `sockets`, `interfaces`, `addresses`, and `neighbors`
- CLI workflow for `snapshot` and `diff`
- golden regression coverage for baseline and changed snapshots
- malformed input coverage for `ss` parsing and `ip -j link show` parsing

## Validation Snapshot

- `python -m pytest -q` currently passes in `projects/linux-socket-observe`
- current tests cover parser basics for `ss` text and iproute2 JSON inputs
- current tests cover golden snapshot regression for both baseline and changed fixtures
- current tests cover snapshot diff basics for added, removed, and changed state
- current tests cover CLI smoke behavior and bounded error reporting for malformed inputs

## Not in Scope

- `/proc/net/tcp`
- pcap parsing
- live monitoring
- raw sockets or packet sockets
- network namespaces
- `ip monitor`

## Notes

- The snapshot schema remains intentionally small and currently centers on `sockets`, `interfaces`, `addresses`, and `neighbors`
- `interfaces[].stats` is only populated when `ip -s -s link show` input is provided
- The current diff report is meant for state comparison, not traffic inspection or packet forensics
