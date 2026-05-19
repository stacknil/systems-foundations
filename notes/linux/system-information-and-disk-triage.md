# System Information and Disk Triage

This note summarizes first-pass Linux system inspection with `top`, `free`, `df`, `du`, and `time`.

## Process Overview with `top`

Run:

```bash
top
```

Useful fields:

- `PID`: process ID
- `USER`: process owner
- `%CPU`: current CPU usage
- `%MEM`: memory share
- `TIME+`: accumulated CPU time
- `COMMAND`: command name or process command

Common interactive keys:

- `q`: quit
- `P`: sort by CPU
- `M`: sort by memory
- `k`: kill a process by PID after confirmation

Filter by user:

```bash
top -u username
```

For non-interactive snapshots, prefer:

```bash
ps aux --sort=-%cpu | head
ps aux --sort=-%mem | head
```

## Memory Overview with `free`

```bash
free -h
```

Important columns:

- `total`: installed memory
- `used`: memory in use
- `free`: currently unused memory
- `available`: a better estimate of memory available for new work
- `buff/cache`: memory used for buffers and page cache

In most troubleshooting, `available` is more useful than `free`.

## Filesystem Overview with `df`

```bash
df -h
df -hT
df -i
```

Use:

- `df -h` for readable capacity.
- `df -hT` to include filesystem type.
- `df -i` to detect inode exhaustion.

Low byte capacity and low inode capacity are different problems. A system can fail to create new files even when it still has free bytes.

## Directory Usage with `du`

Measure one directory:

```bash
du -sh /path/to/target
```

Rank direct children:

```bash
du -h --max-depth=1 /path/to/target | sort -hr
```

Find large files:

```bash
find /path/to/target -type f -exec du -h {} + | sort -hr | head -n 20
```

## Disk Triage Workflow

```bash
df -hT
df -i
du -h --max-depth=1 /path/to/mount | sort -hr
find /path/to/mount -type f -exec du -h {} + | sort -hr | head -n 20
```

The layers are:

- `df` finds the stressed filesystem.
- `df -i` checks whether inode count is the real problem.
- `du` finds the responsible subtree.
- `find` plus `du` identifies large individual files.

## Timing a Command

Use `time` to measure a command:

```bash
time grep -R "ERROR" logs/
```

Typical output includes:

- real elapsed time
- user CPU time
- system CPU time

This is useful when comparing two command forms, such as a broad recursive search versus a narrower targeted search.
