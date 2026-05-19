from __future__ import annotations

from .diff import SnapshotDiff


def build_diff_report(diff: SnapshotDiff) -> str:
    lines = ["# Linux Socket Observe Diff", ""]
    lines.append(f"- Sockets: +{len(diff.sockets_added)} / -{len(diff.sockets_removed)}")
    lines.append(
        f"- Interfaces: +{len(diff.interfaces_added)} / -{len(diff.interfaces_removed)} / {len(diff.interface_changes)} changed"
    )
    lines.append(f"- Addresses: +{len(diff.addresses_added)} / -{len(diff.addresses_removed)}")
    lines.append(
        f"- Neighbors: +{len(diff.neighbors_added)} / -{len(diff.neighbors_removed)} / {len(diff.neighbor_changes)} changed"
    )

    lines.extend(["", "## Sockets", ""])
    lines.extend(_render_lines("Added sockets", diff.sockets_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed sockets", diff.sockets_removed))

    lines.extend(["", "## Interfaces", ""])
    lines.extend(_render_lines("Added interfaces", diff.interfaces_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed interfaces", diff.interfaces_removed))
    lines.extend([""])
    lines.extend(_render_lines("Changed interfaces", diff.interface_changes))

    lines.extend(["", "## Addresses", ""])
    lines.extend(_render_lines("Added addresses", diff.addresses_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed addresses", diff.addresses_removed))

    lines.extend(["", "## Neighbors", ""])
    lines.extend(_render_lines("Added neighbors", diff.neighbors_added))
    lines.extend([""])
    lines.extend(_render_lines("Removed neighbors", diff.neighbors_removed))
    lines.extend([""])
    lines.extend(_render_lines("Changed neighbors", diff.neighbor_changes))
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
