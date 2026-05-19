# File Operations Patterns

This note covers common patterns for creating, copying, moving, renaming, organizing, and deleting files from the shell.

## Create Directories

Create one directory:

```bash
mkdir reports
```

Create nested directories:

```bash
mkdir -p project/{src,docs,tests}
mkdir -p project/logs/archive
```

Create a directory with a specific mode:

```bash
mkdir -m 700 private
```

Useful options:

- `-p` creates missing parent directories and does not fail if the directory already exists.
- `-m MODE` sets the directory permission mode at creation time.
- `-v` prints each directory created.

## Copy Files

Copy one file to a new file:

```bash
cp report.txt report.backup.txt
```

Copy files into a directory:

```bash
cp *.txt text-files/
```

Copy a directory tree:

```bash
cp -r site site.backup
```

Preserve basic metadata:

```bash
cp -p original.txt preserved-copy.txt
```

Prompt before overwriting:

```bash
cp -i draft.txt final.txt
```

## Move and Rename

Rename a file:

```bash
mv draft.txt final.txt
```

Move a file into a directory:

```bash
mv final.txt reports/
```

Move several files:

```bash
mv *.log logs/
```

Prompt before overwriting:

```bash
mv -i new.conf app.conf
```

## Delete Conservatively

Remove one file:

```bash
rm old-report.txt
```

Prompt before removal:

```bash
rm -i old-report.txt
```

Remove an empty directory:

```bash
rmdir empty-dir
```

Remove a directory tree only when you have verified the target:

```bash
pwd
ls -la old-build
rm -r old-build
```

Avoid using `rm -rf` as a default habit. It is useful in automation only when the target path is explicitly controlled and verified.

## Organizing a Small Project

One compact pattern:

```bash
mkdir -p project/{bin,docs,logs,src,tests}
touch project/README.md
```

Then inspect:

```bash
find project -maxdepth 2 -type d | sort
```

The useful lesson is the sequence: create structure, create minimal marker files, then inspect the result.
