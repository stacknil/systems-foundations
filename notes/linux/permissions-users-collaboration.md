# Permissions, Users, and Collaboration

This note summarizes Linux ownership, permissions, user identity, and a common shared-directory pattern.

## Identity Commands

```bash
whoami
id
groups
```

Use:

- `whoami` for the current username.
- `id` for UID, primary GID, and group memberships.
- `groups` for a compact group list.

## Read Permission Bits

```bash
ls -l file.txt
```

Example shape:

```text
-rw-r----- 1 alice developers 1200 May 19 10:00 file.txt
```

Breakdown:

- first character: file type
- next three: owner permissions
- next three: group permissions
- last three: other permissions

Common numeric modes:

- `600`: owner read/write only
- `644`: owner read/write, everyone else read
- `700`: owner full access only
- `755`: owner full access, others read/execute
- `770`: owner and group full access

## Change Permissions

Symbolic mode:

```bash
chmod u+rw,g+r,o-rwx file.txt
```

Numeric mode:

```bash
chmod 640 file.txt
```

Use symbolic mode when documenting intent. Use numeric mode when setting a known final state.

## Change Owner or Group

```bash
sudo chown alice file.txt
sudo chgrp developers file.txt
sudo chown alice:developers file.txt
```

Only privileged users can change file ownership on typical Linux systems.

## Shared Directory with setgid

A common collaboration pattern is a directory where new files inherit the directory group.

```bash
sudo mkdir -p /srv/shared/project
sudo chgrp developers /srv/shared/project
sudo chmod 2770 /srv/shared/project
```

The leading `2` sets the setgid bit on the directory. New files and subdirectories created inside typically inherit the `developers` group.

Verify:

```bash
ls -ld /srv/shared/project
```

Expected shape:

```text
drwxrws--- 2 root developers 4096 May 19 10:00 /srv/shared/project
```

The `s` in the group execute position indicates setgid.

## Practical Safety Notes

- Avoid granting world-writable access unless there is a specific reason.
- Use groups for collaboration instead of sharing one user account.
- Check both ownership and mode when access fails.
- Remember that directory execute permission controls traversal.
