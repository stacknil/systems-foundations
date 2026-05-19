from __future__ import annotations

import json

from ..models import AddressRecord, InterfaceRecord, NeighborRecord


def parse_link_json(text: str) -> list[InterfaceRecord]:
    payload = _load_list(text, label="ip link")
    interfaces = [
        InterfaceRecord(
            ifindex=int(item["ifindex"]),
            ifname=str(item["ifname"]),
            flags=sorted(str(flag) for flag in item.get("flags", [])),
            mtu=int(item["mtu"]),
            operstate=_optional_text(item.get("operstate")),
            link_type=_optional_text(item.get("link_type")),
            address=_optional_text(item.get("address")),
            broadcast=_optional_text(item.get("broadcast")),
            stats=None,
        )
        for item in payload
    ]
    return sorted(interfaces, key=lambda item: (item.ifindex, item.ifname))


def parse_addr_json(text: str) -> list[AddressRecord]:
    payload = _load_list(text, label="ip addr")
    addresses: list[AddressRecord] = []
    for item in payload:
        ifindex = int(item["ifindex"])
        ifname = str(item["ifname"])
        for address in item.get("addr_info", []):
            addresses.append(
                AddressRecord(
                    ifindex=ifindex,
                    ifname=ifname,
                    family=str(address["family"]),
                    local=str(address["local"]),
                    prefixlen=int(address["prefixlen"]),
                    scope=_optional_text(address.get("scope")),
                    label=_optional_text(address.get("label")),
                    broadcast=_optional_text(address.get("broadcast")),
                )
            )
    return sorted(
        addresses,
        key=lambda item: (item.ifname, item.family, item.local, item.prefixlen),
    )


def parse_neigh_json(text: str) -> list[NeighborRecord]:
    payload = _load_list(text, label="ip neigh")
    neighbors = [
        NeighborRecord(
            dev=str(item["dev"]),
            dst=str(item["dst"]),
            lladdr=_optional_text(item.get("lladdr")),
            state=_optional_text(item.get("nud") or item.get("state")),
        )
        for item in payload
    ]
    return sorted(neighbors, key=lambda item: (item.dev, item.dst))


def _load_list(text: str, *, label: str) -> list[dict[str, object]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid {label} JSON") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{label} JSON must decode to a list")
    return payload


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
