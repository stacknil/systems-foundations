# AGENTS.md

## Project scope
This repository is a training ground for Linux/systems foundations.
Current task: build `projects/linux-auth-observe` as a small, deterministic mini-lab.

## Hard boundaries
- Keep changes limited to:
  - `projects/linux-auth-observe/**`
  - `notes/**`
  - `.codex/**`
  - root `README.md` only if needed for a short index entry
- Do not create unrelated projects.
- Do not introduce network services, web UI, or cloud dependencies.
- Do not parse `audit.log` in v0.1.

## Engineering style
- Prefer Python stdlib for v0.1.
- Use simple, reviewable code.
- Fail closed on malformed records when appropriate, but keep batch processing resilient.
- Preserve raw line/message in normalized output for evidence traceability.
- Add pytest coverage for parsing, filtering, and summary generation.
- Keep sample logs sanitized and obviously non-sensitive.

## Deliverables
- JSONL normalization
- CLI filters by user / IP / service / time window
- Markdown summary report
- Notes:
  - `notes/journald-syslog-basics.md`
  - `notes/auth-event-schema.md`

## Non-goals for v0.1
- No real-time tailing
- No auditd parser
- No database
- No LLM features
- No packaging/publishing workflow yet
