# AGENTS.md

## Project scope

This repository is a training ground for small, deterministic Linux/systems foundations mini-labs.

Current mini-labs:

- `projects/linux-auth-observe`: normalize saved Linux auth evidence, filter normalized JSONL, and generate Markdown summaries.
- `projects/linux-socket-observe`: normalize saved Linux networking state snapshots and generate Markdown diffs.
- `projects/linux-permission-observe`: normalize saved Linux permission state and report permission drift.
- `projects/linux-process-observe`: normalize saved procfs process identity, link saved socket context, and report diffs.

Keep each lab narrow, local-file-based, reviewable, and easy to validate with sanitized fixtures and pytest.

## Hard boundaries

- Keep changes scoped to the active mini-lab and directly related docs:
  - `projects/linux-auth-observe/**`
  - `projects/linux-socket-observe/**`
  - `projects/linux-permission-observe/**`
  - `projects/linux-process-observe/**`
  - `notes/**`
  - `docs/**`
  - `.codex/**`
  - root `README.md`, `CHANGELOG.md`, `.gitignore`, and `AGENTS.md` when needed for repository coordination
- Do not create unrelated projects.
- Do not introduce network services, web UI, cloud dependencies, databases, or storage backends.
- Do not add real-time monitoring unless a future task explicitly scopes it.
- Keep samples sanitized and obviously non-sensitive.

## Lab-specific boundaries

### linux-auth-observe

- Supported inputs: exported journald JSON lines, Ubuntu/Debian `auth.log`, and RHEL/CentOS `secure`.
- Do not parse `audit.log`.
- Preserve raw line/message in normalized output for evidence traceability.
- Keep syslog timestamp year/timezone assumptions explicit and tested.

### linux-socket-observe

- Supported inputs: `ss` text, `ip -j addr show`, `ip -j link show`, `ip -j neigh show`, and optional `ip -s -s link show`.
- Do not parse `/proc/net/tcp`.
- Do not add pcap parsing, live capture, raw sockets, packet sockets, network namespaces, or `ip monitor`.
- Treat snapshots as saved command-output artifacts, not live telemetry.

### linux-permission-observe

- Supported inputs: saved file inventory TSV, sanitized group records, and sanitized sudoers rules.
- Do not crawl the live filesystem or parse sudoers include trees.
- Treat snapshots as permission evidence, not policy or privilege-escalation verdicts.

### linux-process-observe

- Supported inputs: saved procfs PID directories (`status`, `stat`, `cmdline`, `exe`) and saved TCP/UDP `ss -H -a -n -t -u -p` text.
- Do not add live procfs crawling, `/proc/net/tcp` parsing, eBPF, netlink subscriptions, process control, or EDR agent behavior.
- Treat executable paths and `ss` process context as contextual evidence, not authoritative integrity or attribution proof.
- Keep the `stacknil.system-evidence.v1` envelope deterministic and backward compatible.

## Engineering style

- Prefer Python stdlib where reasonable.
- Use simple, reviewable code.
- Keep output schemas stable once documented.
- Fail closed on malformed records where appropriate, while keeping batch processing resilient when the CLI contract says so.
- Add focused pytest coverage for parsers, filters, diffs, summaries, CLI workflows, golden outputs, and malformed inputs.
- Keep fixtures deterministic and sanitized.

## Documentation style

- Keep README files practical: scope, workflow, schema, assumptions, non-goals, and validation status.
- Keep notes beginner-friendly but precise.
- Keep release notes and reviewer-facing docs aligned with tested behavior only.

## Current release state

- Latest stable release: `v0.3.0`
- `v0.1.0`: first credible mini-lab, centered on `linux-auth-observe`
- `v0.2.0`: second credible mini-lab, adding `linux-socket-observe`
- `v0.3.0`: 408-to-security bridge, `linux-permission-observe`, `linux-process-observe`, and the process-diff to telemetry-lab JSONL adapter
- Unreleased: follow-up hardening only; do not infer a fifth mini-lab from this release
