# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Added `docs/reviewer-brief.md` as a short external-review entry point.
- Added repository-level docs and notes index pages.
- Added related-notes links from each mini-lab README to its supporting notes.
- Added `.gitignore` rules for local Python test artifacts and generated mini-lab output files.

### Changed

- Added changelog and docs-directory links to the root README and docs index.
- Updated the root README with a reviewer brief link.
- Updated repository agent guidance to reflect the current two-mini-lab scope and boundaries.

### Fixed

- Tightened reviewer brief wording to avoid implying CI coverage where only local pytest coverage is currently documented.
- Made the reviewer brief quick-run path separator platform-neutral.

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

[Unreleased]: https://github.com/stacknil/systems-foundations/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/stacknil/systems-foundations/releases/tag/v0.2.0
[v0.1.0]: https://github.com/stacknil/systems-foundations/releases/tag/v0.1.0
