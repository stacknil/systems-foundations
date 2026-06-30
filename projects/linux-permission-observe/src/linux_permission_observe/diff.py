from __future__ import annotations

from dataclasses import dataclass

from .models import FileRecord, GroupRecord, PermissionSnapshot, SudoersRule


@dataclass(slots=True)
class PermissionDiff:
    files_added: list[str]
    files_removed: list[str]
    file_changes: list[str]
    groups_added: list[str]
    groups_removed: list[str]
    group_changes: list[str]
    sudoers_added: list[str]
    sudoers_removed: list[str]


def compare_snapshots(before: PermissionSnapshot, after: PermissionSnapshot) -> PermissionDiff:
    before_files = {item.path: item for item in before.files}
    after_files = {item.path: item for item in after.files}
    before_groups = {item.name: item for item in before.groups}
    after_groups = {item.name: item for item in after.groups}
    before_sudoers = {_sudoers_key(item): item for item in before.sudoers}
    after_sudoers = {_sudoers_key(item): item for item in after.sudoers}

    return PermissionDiff(
        files_added=sorted(after_files.keys() - before_files.keys()),
        files_removed=sorted(before_files.keys() - after_files.keys()),
        file_changes=_file_changes(before_files, after_files),
        groups_added=sorted(after_groups.keys() - before_groups.keys()),
        groups_removed=sorted(before_groups.keys() - after_groups.keys()),
        group_changes=_group_changes(before_groups, after_groups),
        sudoers_added=sorted(after_sudoers.keys() - before_sudoers.keys()),
        sudoers_removed=sorted(before_sudoers.keys() - after_sudoers.keys()),
    )


def _file_changes(before_items: dict[str, FileRecord], after_items: dict[str, FileRecord]) -> list[str]:
    changes: list[str] = []
    for path in sorted(before_items.keys() & after_items.keys()):
        before = before_items[path]
        after = after_items[path]
        if before.mode != after.mode:
            changes.append(f"{path}: mode {before.mode} -> {after.mode}")
        if before.owner != after.owner:
            changes.append(f"{path}: owner {before.owner} -> {after.owner}")
        if before.group != after.group:
            changes.append(f"{path}: group {before.group} -> {after.group}")
        if before.type != after.type:
            changes.append(f"{path}: type {before.type} -> {after.type}")
    return changes


def _group_changes(before_items: dict[str, GroupRecord], after_items: dict[str, GroupRecord]) -> list[str]:
    changes: list[str] = []
    for name in sorted(before_items.keys() & after_items.keys()):
        before = before_items[name]
        after = after_items[name]
        if before.gid != after.gid:
            changes.append(f"{name}: gid {before.gid} -> {after.gid}")
        added = sorted(set(after.members) - set(before.members))
        removed = sorted(set(before.members) - set(after.members))
        if added:
            changes.append(f"{name}: added members {','.join(added)}")
        if removed:
            changes.append(f"{name}: removed members {','.join(removed)}")
    return changes


def _sudoers_key(item: SudoersRule) -> str:
    tags = ":".join(item.tags) if item.tags else "none"
    commands = ", ".join(item.commands)
    hosts = ",".join(item.hosts)
    return f"{item.subject} {hosts}=({item.run_as}) tags={tags} commands={commands}"

