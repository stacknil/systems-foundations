# Log, Configuration, and Diff Troubleshooting

This note collects small shell patterns for inspecting logs, comparing configuration files, and narrowing failures.

## Start with Recent Evidence

```bash
tail -n 100 service.log
grep -n "ERROR" service.log | tail -n 20
grep -n "WARN" service.log | tail -n 20
```

This gives a quick view of recent activity and the latest error locations.

## Extract a Context Window

When a line number matters:

```bash
nl -ba service.log | sed -n '240,280p'
```

When a pattern matters:

```bash
grep -n -C 3 "connection refused" service.log
```

Use `-C` for surrounding context, `-A` for lines after a match, and `-B` for lines before a match.

## Compare Configuration Files

```bash
diff -u app.conf app.conf.new
```

Look for:

- changed ports or addresses
- changed file paths
- changed feature flags
- missing comments that documented assumptions
- whitespace-only changes in sensitive formats

For directory comparisons:

```bash
diff -ru config.before config.after
```

## Confirm File Type and Permissions

```bash
ls -l app.conf
stat app.conf
file app.conf
```

This catches simple problems:

- wrong owner
- unexpected permissions
- symlink surprises
- binary or encoded content where plain text was expected

## Build a Small Report

```bash
{
  date
  hostname
  echo "Recent errors:"
  grep -n "ERROR" service.log | tail -n 20
  echo
  echo "Config diff:"
  diff -u app.conf app.conf.new
} > troubleshooting-report.txt
```

The useful habit is to keep evidence, commands, and conclusions close together.

## Safety Notes

- Inspect before editing.
- Copy or version-control important config before changing it.
- Prefer `diff -u` over memory when reviewing changes.
- Avoid pasting private hostnames, IPs, tokens, or logs into public notes.
