# User Account Basics

This note summarizes common Linux user and group administration commands for a local practice machine.

## Inspect Current Identity

```bash
whoami
id
groups
```

These commands show the active user, numeric IDs, primary group, and supplementary groups.

## Inspect Accounts and Groups

```bash
getent passwd username
getent group groupname
```

`getent` respects the system name service configuration, so it is usually preferable to directly parsing `/etc/passwd` or `/etc/group`.

## Create a User

On many Linux systems:

```bash
sudo useradd -m username
```

Set or change a password:

```bash
sudo passwd username
```

Common options:

- `-m`: create a home directory.
- `-s /bin/bash`: set login shell.
- `-G group1,group2`: set supplementary groups at creation time.

## Create and Use Groups

```bash
sudo groupadd developers
sudo usermod -aG developers username
```

Use `-aG` together when adding supplementary groups. Omitting `-a` can replace existing supplementary group membership on many systems.

Verify:

```bash
id username
```

The user may need a new login session before new group membership is active.

## Lock or Remove Access

Lock an account password:

```bash
sudo passwd -l username
```

Remove a user only after preserving any needed data:

```bash
sudo userdel username
```

Remove the home directory only when that data is no longer needed:

```bash
sudo userdel -r username
```

## Practical Safety Notes

- Prefer groups over shared accounts.
- Verify existing group membership before modifying it.
- Be careful with `userdel -r`; it removes the home directory.
- Keep account-management examples generic in public notes.
