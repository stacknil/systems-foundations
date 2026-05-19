# linux-socket-observe

`linux-socket-observe` is a deterministic mini-lab for normalizing local Linux networking state snapshots and comparing them over time.

## Supported Inputs

- `ss` text output
- `ip -j addr show`
- `ip -j link show`
- `ip -j neigh show`
- optional `ip -s -s link show`

## Commands

## Workflow

The intended flow is:

1. Build a normalized snapshot from one set of local command-output files.
2. Build a second normalized snapshot from a later set of files.
3. Run `diff` to generate the Markdown report that summarizes added, removed, and changed state.

```bash
python -m linux_socket_observe snapshot \
  --ss tests/fixtures/baseline/ss.txt \
  --ip-addr tests/fixtures/baseline/ip_addr.json \
  --ip-link tests/fixtures/baseline/ip_link.json \
  --ip-neigh tests/fixtures/baseline/ip_neigh.json \
  --ip-link-stats tests/fixtures/baseline/ip_link_stats.txt \
  --output output/baseline.json

python -m linux_socket_observe snapshot \
  --ss tests/fixtures/changed/ss.txt \
  --ip-addr tests/fixtures/changed/ip_addr.json \
  --ip-link tests/fixtures/changed/ip_link.json \
  --ip-neigh tests/fixtures/changed/ip_neigh.json \
  --ip-link-stats tests/fixtures/changed/ip_link_stats.txt \
  --output output/changed.json

python -m linux_socket_observe diff \
  --before output/baseline.json \
  --after output/changed.json \
  --output output/diff.md
```

## Snapshot Schema

Each snapshot is one JSON object with four normalized sections:

- `sockets`
- `interfaces`
- `addresses`
- `neighbors`

Interface statistics are attached to `interfaces[].stats` only when `--ip-link-stats` is provided.

## Non-Goals

- `/proc/net/tcp`
- pcap parsing
- live capture
- raw sockets or packet sockets
- databases or storage backends

## Validation Status

- parser coverage for `ss` text and iproute2 JSON inputs
- snapshot diff coverage for added, removed, and changed state
- CLI smoke coverage for `snapshot` and `diff`
