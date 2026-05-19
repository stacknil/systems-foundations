from __future__ import annotations

from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_socket_observe.parsers import ip_json, link_stats, ss_text


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def test_ss_text_parsing_basics() -> None:
    text = (FIXTURES / "baseline" / "ss.txt").read_text(encoding="utf-8")
    sockets = ss_text.parse_ss_text(text)

    assert len(sockets) == 4
    ssh_socket = next(item for item in sockets if item.state == "ESTAB")
    listen_v6 = next(item for item in sockets if item.family == "inet6")
    assert ssh_socket.local_address == "192.0.2.10"
    assert ssh_socket.local_port == 22
    assert ssh_socket.peer_address == "198.51.100.24"
    assert ssh_socket.processes == ["sshd"]
    assert listen_v6.local_address == "2001:db8::10"
    assert listen_v6.peer_port == "*"


def test_ip_json_normalization_and_optional_stats() -> None:
    interfaces = ip_json.parse_link_json((FIXTURES / "baseline" / "ip_link.json").read_text(encoding="utf-8"))
    addresses = ip_json.parse_addr_json((FIXTURES / "baseline" / "ip_addr.json").read_text(encoding="utf-8"))
    neighbors = ip_json.parse_neigh_json((FIXTURES / "baseline" / "ip_neigh.json").read_text(encoding="utf-8"))
    stats = link_stats.parse_link_stats_text((FIXTURES / "baseline" / "ip_link_stats.txt").read_text(encoding="utf-8"))

    assert [item.ifname for item in interfaces] == ["lo", "eth0", "cni0"]
    assert any(item.local == "192.0.2.10" and item.ifname == "eth0" for item in addresses)
    assert any(item.dst == "192.0.2.1" and item.dev == "eth0" for item in neighbors)
    assert stats["eth0"]["rx_bytes"] == 123456
    assert stats["eth0"]["tx_packets"] == 1200


def test_malformed_ss_and_ip_inputs_raise_clear_errors() -> None:
    bad_ss = (FIXTURES / "malformed" / "ss_bad.txt").read_text(encoding="utf-8")
    bad_ip_link = (FIXTURES / "malformed" / "ip_link_bad.json").read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="malformed ss endpoint on line 2"):
        ss_text.parse_ss_text(bad_ss)

    with pytest.raises(ValueError, match="ip link JSON must decode to a list"):
        ip_json.parse_link_json(bad_ip_link)
