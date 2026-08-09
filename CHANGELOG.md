# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

### Changed

### Fixed

## [v0.3.0] - 2026-08-09

408-to-Security Bridge

### Added

- Introduced `projects/linux-permission-observe` for deterministic file mode/ownership, group, and sudoers drift evidence.
- Added `notes/408-to-linux-security.md` to map operating-system concepts to security evidence.
- Introduced `projects/linux-process-observe` for saved procfs identity, process/socket linking, normalized diffs, and Markdown reports.
- Added the `stacknil.system-evidence.v1` envelope contract for process evidence artifacts.
- Added a process-diff adapter that emits telemetry-lab-compatible JSONL with stable evidence metadata.
- Added `stacknil.system-evidence.telemetry.v1` to identify the adapter mapping contract separately from the source evidence contract.
- Added adapter golden regression, malformed input, PID fallback, and CLI coverage.

### Documentation

- Added `notes/process-evidence-schema.md` and the v0.3.0 release notes.
- Updated repository navigation and reviewer guidance for four stable mini-labs.
- Documented the process diff -> telemetry-lab JSONL bridge without adding a fifth mini-lab.

## [v0.2.0] - 2026-05-20

Second Credible Mini-Lab

### Added

- Introduced `projects/linux-socket-observe` as the second systems training mini-lab
- Added deterministic snapshot normalization for `ss` text plus selected `iproute2` command outputs
- Added CLI workflow for `snapshot` and `diff`
- Added Markdown diff reporting for added, removed, and changed network state
- Added notes for `ss`/iproute2 basics and the network snapshot schema
- Added golden regression, malformed input, parser, diff, and CLI coverage in pytest

### Documentation

- Added release notes in `docs/release-v0.2.0.md`
- Updated the root README to present the repository as a two-mini-lab training repo

## [v0.1.0] - 2026-04-10

First Credible Mini-Lab

### Added

- Introduced `projects/linux-auth-observe` as the first systems training mini-lab
- Added deterministic normalization for exported journald JSON lines, Ubuntu or Debian `auth.log`, and RHEL or CentOS `secure`
- Added CLI workflow for `normalize`, `filter`, and `summary`
- Added optional structured parse-error JSONL output during normalization
- Added notes for journald/syslog basics and the auth event schema
- Added parser, CLI, golden regression, and rollover coverage in pytest

### Documentation

- Added release notes in `docs/release-v0.1.0.md`
- Added root README release entry and latest release link

[Unreleased]: https://github.com/stacknil/systems-foundations/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/stacknil/systems-foundations/releases/tag/v0.3.0
[v0.2.0]: https://github.com/stacknil/systems-foundations/releases/tag/v0.2.0
[v0.1.0]: https://github.com/stacknil/systems-foundations/releases/tag/v0.1.0
