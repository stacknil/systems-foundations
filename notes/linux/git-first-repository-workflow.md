# Git First Repository Workflow

This note describes the smallest useful Git workflow: initialize a repository, track a file, commit it, inspect history, and understand working-tree state.

## Minimal Loop

```bash
mkdir demo-repo
cd demo-repo
git init
printf "first note\n" > notes.txt
git status
git add notes.txt
git commit -m "docs: add first note"
```

The loop is:

- create or edit files
- inspect state with `git status`
- stage selected changes with `git add`
- record a snapshot with `git commit`

## Inspect Repository State

```bash
git status
git status --short
```

Useful mental model:

- untracked files exist in the directory but are not yet part of Git history.
- modified files are tracked files with working-tree changes.
- staged files are selected for the next commit.

## Inspect History

```bash
git log --oneline
git show --stat
```

Use `git log --oneline` for a compact history and `git show --stat` to see what changed in the latest commit.

## Inspect Changes

Before staging:

```bash
git diff
```

After staging:

```bash
git diff --cached
```

This distinction matters because Git commits the staged snapshot, not every file currently changed in the working tree.

## Configure Identity

If Git asks for user identity:

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

Use repository-local configuration when you need a different identity for one repository:

```bash
git config user.name "Your Name"
git config user.email "you@example.com"
```

## Practical Habit

Before every commit:

```bash
git status --short
git diff --cached
```

This catches accidental files, missing files, and unrelated changes before they become part of history.
