# Reviewer brief

## Problem

Systems learning is often broad but hard to review. Reviewers need small labs that show concrete Linux evidence handling instead of vague “I studied systems” claims.

## What it does

`systems-foundations` is a repository of small, reviewable Linux mini-labs.

Current stable labs:

- `projects/linux-auth-observe` for normalizing Linux auth evidence, filtering it, and generating short Markdown summaries
- `projects/linux-socket-observe` for turning saved `ss` and `iproute2` snapshots into normalized JSON and Markdown diffs
- `projects/linux-permission-observe` for turning saved file, group, and sudoers records into normalized permission drift artifacts
- `projects/linux-process-observe` for saved procfs identity, process/socket links, normalized diffs, and a telemetry-lab JSONL adapter

## Reviewer Evidence

- Reproducible command: `python -m linux_auth_observe normalize --input tests/fixtures/ubuntu_auth.log --source auto --year 2026 --timezone Asia/Shanghai --output output/events.jsonl`
- Deterministic outputs: normalized auth JSONL, parse-error JSONL, auth summaries, socket snapshot JSON, socket diff Markdown reports, permission drift artifacts, process evidence envelopes, and telemetry-lab-compatible JSONL.
- Tests: local pytest coverage for parsers, filtering, summaries, CLI workflows, golden regression artifacts, malformed input handling, process/socket diffs, and adapter mapping.
- Release evidence: versioned mini-lab release notes for `v0.1.0`, `v0.2.0`, and `v0.3.0`.
- Non-goals: live monitoring, packet capture, `/proc/net/tcp` parsing, `audit.log` support, databases, or offensive functionality.

## Quick run

```bash
cd projects/linux-auth-observe
python -m pip install -e ".[dev]"
python -m linux_auth_observe normalize --input tests/fixtures/ubuntu_auth.log --source auto --year 2026 --timezone Asia/Shanghai --output output/events.jsonl
python -m linux_auth_observe summary --input output/events.jsonl --output output/summary.md

cd ../linux-socket-observe
python -m pip install -e ".[dev]"
python -m linux_socket_observe snapshot --ss tests/fixtures/baseline/ss.txt --ip-addr tests/fixtures/baseline/ip_addr.json --ip-link tests/fixtures/baseline/ip_link.json --ip-neigh tests/fixtures/baseline/ip_neigh.json --ip-link-stats tests/fixtures/baseline/ip_link_stats.txt --output output/baseline.json

cd ../linux-process-observe
python -m pip install -e ".[dev]"
python -m linux_process_observe adapt --input tests/golden/diff/process_diff.json --output output/telemetry_events.jsonl
```

## Sample output

`linux-auth-observe` emits:

- normalized `events.jsonl`
- optional structured parse-error output
- a short reviewer-friendly `summary.md`

`linux-socket-observe` emits:

- normalized snapshot JSON artifacts such as `baseline.json`
- a Markdown diff report such as `diff.md` when comparing two snapshots

## What this proves

- Linux evidence normalization and schema discipline
- CLI workflows that are deterministic and reviewer-friendly
- the ability to turn low-level system state into stable artifacts
- a bounded evidence bridge into the existing telemetry-lab event contract

## Safety / boundaries

- local file inputs only
- no live monitoring, pcap capture, or offensive functionality
- narrow, bounded evidence handling instead of platform claims

## Limitations

- supported input families are intentionally selective
- `linux-auth-observe` does not cover `audit.log`
- `linux-socket-observe` does not do live capture or traffic analysis
- labs are separate mini-projects; the process adapter is a file-format bridge, not a unified runtime

## Next milestone

Keep hardening the four existing labs and their evidence contracts without adding a fifth mini-lab by default.
