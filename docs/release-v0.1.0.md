# v0.1.0 Release Notes

## Title

First Credible Mini-Lab

## Summary

`systems-foundations` now has its first focused mini-lab: `projects/linux-auth-observe`.

This release packages a narrow, tested workflow for Linux auth evidence review:

- normalize supported journald and auth syslog fixtures into JSONL
- filter normalized rows by `user`, `IP`, and `service`
- generate a Markdown summary report
- optionally emit structured parse failures as JSONL during normalization

## Included in v0.1.0

- support for exported journald JSON lines
- support for Ubuntu or Debian `auth.log`
- support for RHEL or CentOS `secure`
- normalized JSONL output with preserved raw evidence
- CLI workflow for `normalize`, `filter`, and `summary`
- pytest coverage for parsing, CLI behavior, summary generation, golden regression, and syslog year rollover

## Validation Snapshot

- `pytest -q` passes in the current repository state
- current tests cover all three supported fixture families
- current tests cover `Dec 31 -> Jan 1` syslog rollover behavior
- current tests cover optional `--error-output` generation for malformed lines

## Not in Scope

- `audit.log`
- real-time monitoring or tailing
- databases or storage backends
- packaging or publishing workflows

## Notes

- Syslog timestamps are yearless and timezone-less in the source files, so v0.1.0 documents and tests the current year inference and rollover rules explicitly
- `_PID` is preserved as contextual metadata when present, not as a standalone identity guarantee
