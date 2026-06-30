from __future__ import annotations

from .diff import PermissionDiff


def build_diff_report(diff: PermissionDiff) -> str:
    lines = ["# Linux Permission Observe Drift", ""]
    lines.append(f"- Files: +{len(diff.files_added)} / -{len(diff.files_removed)} / {len(diff.file_changes)} changed")
    lines.append(f"- Groups: +{len(diff.groups_added)} / -{len(diff.groups_removed)} / {len(diff.group_changes)} changed")
    lines.append(f"- Sudoers: +{len(diff.sudoers_added)} / -{len(diff.sudoers_removed)}")

    lines.extend(["", "## Files", ""])
    lines.extend(_render_lines("Added files", diff.files_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed files", diff.files_removed))
    lines.extend([""])
    lines.extend(_render_lines("Changed files", diff.file_changes))

    lines.extend(["", "## Groups", ""])
    lines.extend(_render_lines("Added groups", diff.groups_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed groups", diff.groups_removed))
    lines.extend([""])
    lines.extend(_render_lines("Changed groups", diff.group_changes))

    lines.extend(["", "## Sudoers", ""])
    lines.extend(_render_lines("Added sudoers rules", diff.sudoers_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed sudoers rules", diff.sudoers_removed))
    lines.append("")
    return "\n".join(lines)


def _render_lines(title: str, entries: list[str]) -> list[str]:
    lines = [f"### {title}", ""]
    if not entries:
        lines.append("- none")
        return lines
    for entry in entries:
        lines.append(f"- `{entry}`")
    return lines

