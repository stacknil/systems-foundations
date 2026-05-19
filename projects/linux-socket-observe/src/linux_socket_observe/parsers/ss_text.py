from __future__ import annotations

import re

from ..models import SocketRecord

PROCESS_RE = re.compile(r'"(?P<name>[^"]+)",pid=(?P<pid>\d+)')


def parse_ss_text(text: str) -> list[SocketRecord]:
    sockets: list[SocketRecord] = []
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        return sockets

    start_index = 1 if lines[0].startswith("Netid") else 0
    for line_number, line in enumerate(lines[start_index:], start=start_index + 1):
        parts = line.split(maxsplit=6)
        if len(parts) < 6:
            raise ValueError(f"malformed ss line {line_number}")

        netid, state, recv_q, send_q, local_token, peer_token = parts[:6]
        process_token = parts[6] if len(parts) == 7 else ""
        local_address, local_port = _parse_endpoint(local_token, line_number)
        peer_address, peer_port = _parse_endpoint(peer_token, line_number)
        processes, pids = _parse_processes(process_token)

        sockets.append(
            SocketRecord(
                netid=netid,
                state=state,
                family=_infer_family(local_address, peer_address),
                recv_q=int(recv_q),
                send_q=int(send_q),
                local_address=local_address,
                local_port=local_port,
                peer_address=peer_address,
                peer_port=peer_port,
                processes=processes,
                pids=pids,
            )
        )

    return sorted(
        sockets,
        key=lambda item: (
            item.netid,
            item.state,
            item.local_address,
            str(item.local_port),
            item.peer_address,
            str(item.peer_port),
            tuple(item.processes),
        ),
    )


def _parse_endpoint(token: str, line_number: int) -> tuple[str, str | int]:
    if token.startswith("["):
        closing_index = token.find("]")
        if closing_index == -1 or closing_index + 1 >= len(token) or token[closing_index + 1] != ":":
            raise ValueError(f"malformed ss endpoint on line {line_number}")
        address = token[1:closing_index]
        port_token = token[closing_index + 2 :]
    else:
        if ":" not in token:
            raise ValueError(f"malformed ss endpoint on line {line_number}")
        address, port_token = token.rsplit(":", maxsplit=1)

    return _normalize_address(address), _normalize_port(port_token)


def _parse_processes(token: str) -> tuple[list[str], list[int]]:
    names: list[str] = []
    pids: list[int] = []
    for match in PROCESS_RE.finditer(token):
        names.append(match.group("name"))
        pids.append(int(match.group("pid")))
    return sorted(dict.fromkeys(names)), sorted(dict.fromkeys(pids))


def _normalize_address(value: str) -> str:
    cleaned = value.strip()
    return "*" if cleaned == "" else cleaned


def _normalize_port(value: str) -> str | int:
    cleaned = value.strip()
    if cleaned == "*":
        return cleaned
    return int(cleaned)


def _infer_family(local_address: str, peer_address: str) -> str:
    address = local_address if local_address != "*" else peer_address
    return "inet6" if ":" in address and "." not in address else "inet"
