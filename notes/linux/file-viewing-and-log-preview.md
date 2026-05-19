# File Viewing and Log Preview

This note covers `cat`, `head`, `tail`, `nl`, and related patterns for quickly inspecting text files and logs.

## Choose the Right Viewer

Use `cat` for short files:

```bash
cat config.txt
```

Use `less` for longer files:

```bash
less application.log
```

Use `head` to inspect the beginning:

```bash
head application.log
head -n 20 application.log
```

Use `tail` to inspect the end:

```bash
tail application.log
tail -n 50 application.log
```

## Follow a Growing Log

Use `tail -f` for live append-only logs:

```bash
tail -f application.log
```

Use a line limit before following if the file is noisy:

```bash
tail -n 20 -f application.log
```

This gives immediate context without printing the entire file.

## Start from a Specific Line

Use `tail -n +N` to print from line `N` onward:

```bash
tail -n +100 application.log
```

This is useful when a previous command or editor has already identified an approximate line number.

## Add Line Numbers

Use `nl` when line numbers help with review:

```bash
nl -ba script.sh | less
```

Useful options:

- `-ba` numbers all lines, including blank lines.
- `-w1` reduces number-field width.
- `-s': '` changes the separator.

Example:

```bash
nl -ba -w1 -s': ' config.txt
```

## Compare Small Files

Use `diff -u` for reviewable text differences:

```bash
diff -u old.conf new.conf
```

Use recursive comparison for directory snapshots:

```bash
diff -ru old-dir new-dir
```

The unified format is usually easier to read and paste into reviews than the default diff format.

## Practical Log Triage Pattern

```bash
tail -n 100 application.log
grep -n "ERROR" application.log | tail -n 20
nl -ba application.log | sed -n '200,240p'
```

This pattern answers three different questions:

- What happened most recently?
- Where are the recent errors?
- What exact line range needs closer inspection?
