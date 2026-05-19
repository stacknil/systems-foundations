from __future__ import annotations

from dataclasses import dataclass

from .models import NetworkSnapshot


@dataclass(slots=True)
class SnapshotDiff:
    sockets_added: list[str]
    sockets_removed: list[str]
    interfaces_added: list[str]
    interfaces_removed: list[str]
    interface_changes: list[str]
    addresses_added: list[str]
    addresses_removed: list[str]
    neighbors_added: list[str]
    neighbors_removed: list[str]
    neighbor_changes: list[str]


def compare_snapshots(before: NetworkSnapshot, after: NetworkSnapshot) -> SnapshotDiff:
    before_sockets = {_socket_key(item): item for item in before.sockets}
    after_sockets = {_socket_key(item): item for item in after.sockets}

    before_interfaces = {item.ifname: item for item in before.interfaces}
    after_interfaces = {item.ifname: item for item in after.interfaces}

    before_addresses = {_address_key(item) for item in before.addresses}
    after_addresses = {_address_key(item) for item in after.addresses}

    before_neighbors = {_neighbor_key(item): item for item in before.neighbors}
    after_neighbors = {_neighbor_key(item): item for item in after.neighbors}

    return SnapshotDiff(
        sockets_added=sorted(after_sockets.keys() - before_sockets.keys()),
        sockets_removed=sorted(before_sockets.keys() - after_sockets.keys()),
        interfaces_added=sorted(after_interfaces.keys() - before_interfaces.keys()),
        interfaces_removed=sorted(before_interfaces.keys() - after_interfaces.keys()),
        interface_changes=_interface_changes(before_interfaces, after_interfaces),
        addresses_added=sorted(after_addresses - before_addresses),
        addresses_removed=sorted(before_addresses - after_addresses),
        neighbors_added=sorted(_neighbor_display(after_neighbors[key]) for key in after_neighbors.keys() - before_neighbors.keys()),
        neighbors_removed=sorted(_neighbor_display(before_neighbors[key]) for key in before_neighbors.keys() - after_neighbors.keys()),
        neighbor_changes=_neighbor_changes(before_neighbors, after_neighbors),
    )


def _socket_key(item) -> str:
    processes = ",".join(item.processes) if item.processes else "(none)"
    return f"{item.netid} {item.state} {item.local_address}:{item.local_port} -> {item.peer_address}:{item.peer_port} [{processes}]"


def _address_key(item) -> str:
    return f"{item.ifname} {item.family} {item.local}/{item.prefixlen}"


def _neighbor_key(item) -> tuple[str, str]:
    return item.dev, item.dst


def _neighbor_display(item) -> str:
    state = item.state or "(none)"
    lladdr = item.lladdr or "(none)"
    return f"{item.dev} {item.dst} lladdr={lladdr} state={state}"


def _interface_changes(before_items: dict[str, object], after_items: dict[str, object]) -> list[str]:
    changes: list[str] = []
    for ifname in sorted(before_items.keys() & after_items.keys()):
        before = before_items[ifname]
        after = after_items[ifname]
        if before.operstate != after.operstate:
            changes.append(f"{ifname}: operstate {before.operstate} -> {after.operstate}")
        if before.mtu != after.mtu:
            changes.append(f"{ifname}: mtu {before.mtu} -> {after.mtu}")
        if before.address != after.address:
            changes.append(f"{ifname}: mac {before.address} -> {after.address}")
    return changes


def _neighbor_changes(before_items: dict[tuple[str, str], object], after_items: dict[tuple[str, str], object]) -> list[str]:
    changes: list[str] = []
    for key in sorted(before_items.keys() & after_items.keys()):
        before = before_items[key]
        after = after_items[key]
        if before.state != after.state:
            changes.append(f"{after.dev} {after.dst}: state {before.state} -> {after.state}")
        elif before.lladdr != after.lladdr:
            changes.append(f"{after.dev} {after.dst}: lladdr {before.lladdr} -> {after.lladdr}")
    return changes
