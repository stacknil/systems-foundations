# network snapshot schema

## Top-level artifact

Each normalized snapshot is one JSON object with this shape:

- `schema_version`
- `sockets`
- `interfaces`
- `addresses`
- `neighbors`

## Sockets

Each socket record captures:

- `netid`
- `state`
- `family`
- `recv_q`
- `send_q`
- `local_address`
- `local_port`
- `peer_address`
- `peer_port`
- `processes`
- `pids`

## Interfaces

Each interface record captures:

- `ifindex`
- `ifname`
- `flags`
- `mtu`
- `operstate`
- `link_type`
- `address`
- `broadcast`
- optional `stats`

`stats` is only populated when `ip -s -s link show` input is provided.

## Addresses

Each address record captures:

- `ifindex`
- `ifname`
- `family`
- `local`
- `prefixlen`
- `scope`
- `label`
- `broadcast`

## Neighbors

Each neighbor record captures:

- `dev`
- `dst`
- `lladdr`
- `state`

## Diff intent

The Markdown diff report focuses on:

- added and removed sockets
- added, removed, and changed interfaces
- added and removed addresses
- added, removed, and changed neighbors
