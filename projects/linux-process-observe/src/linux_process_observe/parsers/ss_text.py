from __future__ import annotations

import re

from ..models import ProcessRef, SocketObservation


PROCESS_RE = re.compile(r'"(?P<name>[^"]+)",pid=(?P<pid>\d+)')


def parse_ss_text(text: str) -> list[SocketObservation]:
    observations: list[SocketObservation] = []
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    start_index = 1 if lines and lines[0].startswith("Netid") else 0

    for line_number, line in enumerate(lines[start_index:], start=start_index + 1):
        parts = line.split(maxsplit=6)
        if len(parts) < 6:
            raise ValueError(f"malformed ss line {line_number}")
        protocol, state, recv_q_text, send_q_text, local_token, remote_token = parts[:6]
        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"unsupported ss protocol on line {line_number}: {protocol}")
        process_token = parts[6] if len(parts) == 7 else ""
        try:
            recv_q = int(recv_q_text)
            send_q = int(send_q_text)
        except ValueError as exc:
            raise ValueError(f"malformed ss queue on line {line_number}") from exc

        local_address, local_port = _parse_endpoint(local_token, line_number)
        remote_address, remote_port = _parse_endpoint(remote_token, line_number)
        refs = _parse_process_refs(process_token, line_number)
        observations.append(
            SocketObservation(
                protocol=protocol,
                state=state,
                recv_q=recv_q,
                send_q=send_q,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                process_refs=refs,
            )
        )

    return sorted(
        observations,
        key=lambda item: (
            item.protocol,
            item.state,
            item.local_address,
            str(item.local_port),
            item.remote_address,
            str(item.remote_port),
            tuple((ref.pid, ref.name) for ref in item.process_refs),
        ),
    )


def _parse_endpoint(token: str, line_number: int) -> tuple[str, str | int]:
    if token.startswith("["):
        closing = token.find("]")
        if closing == -1 or token[closing + 1 : closing + 2] != ":":
            raise ValueError(f"malformed ss endpoint on line {line_number}")
        address = token[1:closing]
        port = token[closing + 2 :]
    else:
        if ":" not in token:
            raise ValueError(f"malformed ss endpoint on line {line_number}")
        address, port = token.rsplit(":", maxsplit=1)
    if not port:
        raise ValueError(f"malformed ss endpoint on line {line_number}")
    try:
        normalized_port: str | int = port if port == "*" else int(port)
    except ValueError as exc:
        raise ValueError(f"malformed ss endpoint on line {line_number}") from exc
    return address or "*", normalized_port


def _parse_process_refs(token: str, line_number: int) -> list[ProcessRef]:
    matches = [ProcessRef(name=match.group("name"), pid=int(match.group("pid"))) for match in PROCESS_RE.finditer(token)]
    if "users:" in token and not matches:
        raise ValueError(f"malformed ss process field on line {line_number}")
    unique = {(item.pid, item.name): item for item in matches}
    return [unique[key] for key in sorted(unique)]
