# Changelog

All notable changes to this repository will be documented in this file.

## v0.1.0 - 2026-04-10

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
