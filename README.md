# systems-foundations

`systems-foundations` is a training repository for small, reviewable labs around Linux and systems fundamentals.

The goal is to keep each lab narrow, deterministic, and easy to inspect end to end: input evidence, normalization, filtering, reporting, and notes that explain the basics without pretending to be a full platform.

## Current Mini-Lab

- `projects/linux-auth-observe`

`linux-auth-observe` is the first mini-lab in the repository. It focuses on Linux auth evidence from exported journald JSON lines plus distro auth syslog files, normalizes them into JSONL, supports simple filtering, and produces a Markdown summary report.

Latest stable release: [v0.1.0](https://github.com/stacknil/systems-foundations/releases/latest)

## Repository Shape

- `projects/`: focused mini-labs
- `notes/`: short learning notes and schemas that support the labs
- `.codex/`: local assistant configuration for this repository
