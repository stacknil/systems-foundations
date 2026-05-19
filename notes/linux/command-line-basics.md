# Command-Line Basics

This note summarizes the first layer of Linux shell fluency: locating yourself, moving through directories, listing files, and reading small text files.

## Core Idea

Most command-line work starts with three questions:

- Where am I?
- What is here?
- What do I want to inspect or change?

The basic loop is:

```bash
pwd
ls
cd /path/to/directory
```

## Current Directory

Use `pwd` to print the current working directory.

```bash
pwd
```

This is useful before running commands that read or write relative paths.

## Moving Around

Common `cd` forms:

```bash
cd /absolute/path
cd relative/path
cd ..
cd ~
cd -
```

Notes:

- `/absolute/path` starts from the filesystem root.
- `relative/path` starts from the current directory.
- `..` moves to the parent directory.
- `~` expands to the current user's home directory.
- `-` returns to the previous directory.

## Listing Files

Common `ls` forms:

```bash
ls
ls -l
ls -a
ls -lh
ls -R
```

Useful reading:

- `-l` shows permissions, owner, group, size, and modification time.
- `-a` includes dotfiles.
- `-h` makes sizes human-readable when paired with `-l`.
- `-R` recursively lists subdirectories.

## Reading Text

Use `cat` for short files:

```bash
cat notes.txt
```

Use `less` for files that may be longer than the terminal:

```bash
less system.log
```

Inside `less`, `/pattern` searches forward and `q` quits.

Use `more` only when it is already available in a simple environment. `less` is usually the more practical pager.

## Practical Habit

Before changing files, run a quick context check:

```bash
pwd
ls -lah
```

This prevents many mistakes caused by assuming the wrong working directory.
