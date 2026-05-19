# PATH, Command Discovery, and `find`

This note explains how the shell locates commands and how to search the filesystem for files.

## Command Lookup

When you type a command name, the shell searches directories listed in `PATH`.

```bash
printf '%s\n' "$PATH" | tr ':' '\n'
```

The order matters. If two directories contain an executable with the same name, the first matching directory in `PATH` wins.

## `which`

Use `which` for a quick executable lookup:

```bash
which ls
which python3
```

This answers: which executable would this command name resolve to?

## `whereis`

Use `whereis` for a broader lookup of binaries, source, and manuals:

```bash
whereis ls
whereis bash
```

This is useful when you want to see related system locations, not only the executable selected by the shell.

## Shell Builtins

Some commands are built into the shell. Use `type` to inspect how a name resolves:

```bash
type cd
type echo
type ls
```

This helps explain why some commands do not have a normal executable path.

## Search Files with `find`

Find by name:

```bash
find /path/to/search -name '*.log'
```

Find by type:

```bash
find /path/to/search -type f
find /path/to/search -type d
```

Find by size:

```bash
find /path/to/search -type f -size +100M
```

Find recently modified files:

```bash
find /path/to/search -type f -mtime -7
```

## Safe Execution Pattern

Print matches before acting on them:

```bash
find /path/to/search -type f -name '*.tmp' -print
```

Then, after verifying the target set, use `-exec`:

```bash
find /path/to/search -type f -name '*.tmp' -exec rm -i {} \;
```

For many files, batching is more efficient:

```bash
find /path/to/search -type f -name '*.log' -exec wc -l {} +
```

The `+` form passes multiple paths to each command invocation where possible.

## Practical Habit

When command behavior is surprising, check both the command path and the shell lookup result:

```bash
type command-name
which command-name
printf '%s\n' "$PATH" | tr ':' '\n'
```
