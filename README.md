# systems-foundations

`systems-foundations` is a training repository for small, reviewable labs around Linux and systems fundamentals.

The goal is to keep each lab narrow, deterministic, and easy to inspect end to end: input evidence, normalization, filtering, reporting, and notes that explain the basics without pretending to be a full platform.

## Current Mini-Labs

- [`projects/linux-auth-observe`](projects/linux-auth-observe/README.md): Linux auth evidence mini-lab for exported journald JSON lines and distro auth syslog files. This was the first stable mini-lab in `v0.1.0`.
- [`projects/linux-socket-observe`](projects/linux-socket-observe/README.md): local Linux networking state mini-lab for `ss` plus selected `iproute2` snapshots. It builds one normalized snapshot artifact and generates a Markdown diff between two snapshots.

Latest stable release: [v0.2.0](https://github.com/stacknil/systems-foundations/releases/latest)
Latest release notes: [v0.2.0](docs/release-v0.2.0.md)
Reviewer brief: [docs/reviewer-brief.md](docs/reviewer-brief.md)

## Linux Notes

- [Linux notes index](notes/linux/README.md)
- [Public note policy](notes/linux/public-note-policy.md)
- [Text processing pipelines](notes/linux/text-processing-pipelines.md)
- [System information and disk triage](notes/linux/system-information-and-disk-triage.md)

## Repository Shape

- `projects/`: focused mini-labs
- `notes/`: short learning notes and schemas that support the labs
- `.codex/`: local assistant configuration for this repository
