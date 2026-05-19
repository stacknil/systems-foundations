from __future__ import annotations

import re

HEADER_RE = re.compile(r"^\d+:\s+(?P<ifname>[^:]+):")


def parse_link_stats_text(text: str) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    current_ifname: str | None = None
    expecting: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        header_match = HEADER_RE.match(line)
        if header_match is not None:
            current_ifname = header_match.group("ifname")
            stats.setdefault(current_ifname, {})
            expecting = None
            continue

        stripped = line.strip()
        if stripped.startswith("RX:"):
            expecting = "rx"
            continue
        if stripped.startswith("TX:"):
            expecting = "tx"
            continue
        if stripped.startswith("RX errors:") or stripped.startswith("TX errors:"):
            expecting = None
            continue
        if current_ifname is None or expecting is None:
            continue

        parts = stripped.split()
        if len(parts) < 2:
            raise ValueError(f"malformed ip link stats row for {current_ifname}")
        try:
            bytes_value = int(parts[0])
            packets_value = int(parts[1])
        except ValueError as exc:
            raise ValueError(f"malformed ip link stats row for {current_ifname}") from exc

        stats[current_ifname][f"{expecting}_bytes"] = bytes_value
        stats[current_ifname][f"{expecting}_packets"] = packets_value
        expecting = None

    return stats
