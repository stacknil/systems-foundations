# systems-foundations

`systems-foundations` is a training repository for small, reviewable labs around Linux and systems fundamentals.

The goal is to keep each lab narrow, deterministic, and easy to inspect end to end: input evidence, normalization, filtering, reporting, and notes that explain the basics without pretending to be a full platform.

## Current Mini-Labs

- `projects/linux-auth-observe`
- `projects/linux-socket-observe`

`linux-auth-observe` focuses on Linux auth evidence from exported journald JSON lines plus distro auth syslog files, normalizes them into JSONL, supports simple filtering, and produces a Markdown summary report.

`linux-socket-observe` focuses on local Linux networking state snapshots from `ss` and selected `iproute2` outputs, normalizes them into a single snapshot artifact, and produces a Markdown diff between two snapshots.

Latest stable release: [v0.1.0](https://github.com/stacknil/systems-foundations/releases/latest)

## Linux Notes

- [Linux notes index](notes/linux/README.md)
- [Public note policy](notes/linux/public-note-policy.md)
- [Text processing pipelines](notes/linux/text-processing-pipelines.md)
- [System information and disk triage](notes/linux/system-information-and-disk-triage.md)

## Repository Shape

- `projects/`: focused mini-labs
- `notes/`: short learning notes and schemas that support the labs
- `.codex/`: local assistant configuration for this repository
