# linux-permission-observe

`linux-permission-observe` is a deterministic mini-lab for reviewing Linux permission state from saved local command-output files.

It focuses on file mode and ownership drift, group membership drift, and sudoers rule drift. It does not inspect the live system.

## Supported Inputs

- file inventory TSV with `path`, `mode`, `owner`, `group`, and `type`
- sanitized `getent group` style lines
- sanitized sudoers rule lines

## Commands

- `snapshot`: build one normalized permission snapshot JSON file
- `diff`: compare two snapshots and write a Markdown drift report

## Workflow

```bash
python -m linux_permission_observe snapshot \
  --files tests/fixtures/baseline/files.tsv \
  --groups tests/fixtures/baseline/groups.txt \
  --sudoers tests/fixtures/baseline/sudoers.txt \
  --output output/baseline.json

python -m linux_permission_observe snapshot \
  --files tests/fixtures/changed/files.tsv \
  --groups tests/fixtures/changed/groups.txt \
  --sudoers tests/fixtures/changed/sudoers.txt \
  --output output/changed.json

python -m linux_permission_observe diff \
  --before output/baseline.json \
  --after output/changed.json \
  --output output/diff.md
```

## Drift Covered

- `chmod`: file mode changes
- `chown`: owner or group changes
- `groups`: group membership changes
- `sudoers`: added or removed sudoers rules
- file permission drift: added, removed, or changed file records

## Non-Goals

- no live filesystem crawling
- no parsing real `/etc/sudoers` includes
- no privilege escalation checks
- no policy engine
- no database or storage backend

## Related Note

- [408 to Linux security](../../notes/408-to-linux-security.md)

