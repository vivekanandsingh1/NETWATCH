import ipaddress
import json

from netwatch import Tracker, mask, parse

FIREWALL = "[NETWATCH] IN=eth0 OUT= MAC=00:00 SRC=45.83.12.7 DST=203.0.113.10 LEN=44 TTL=242 PROTO=TCP SPT=40000 DPT={port} WINDOW=1024 SYN URGP=0"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def tracker():
    clock = Clock()
    return Tracker(lambda ip: None, [0, 0], clock), clock


def test_parse_firewall_line():
    event = parse(FIREWALL.format(port=3389))
    assert event == {"ip": ipaddress.ip_address("45.83.12.7"), "kind": "blocked", "proto": "TCP", "port": 3389}


def test_only_new_tcp_connections_count():
    late_reply = FIREWALL.format(port=51563).replace(" SYN ", " ACK RST ")
    syn_ack = FIREWALL.format(port=51563).replace(" SYN ", " ACK SYN ")
    assert parse(late_reply) is None
    assert parse(syn_ack) is None
    assert parse("[NETWATCH] IN=eth0 SRC=45.83.12.7 DST=203.0.113.10 PROTO=UDP SPT=5353 DPT=1900 LEN=20")["port"] == 1900


def test_parse_icmp_without_port():
    event = parse("[NETWATCH] IN=eth0 SRC=45.83.12.7 DST=203.0.113.10 PROTO=ICMP TYPE=8 CODE=0")
    assert event["proto"] == "ICMP" and event["port"] is None


def test_parse_ssh_lines():
    for line in [
        "Invalid user oracle from 45.83.12.7 port 51234",
        "Invalid user  from 45.83.12.7 port 51234",
        "Failed password for root from 45.83.12.7 port 51234 ssh2",
        "Connection closed by authenticating user root 45.83.12.7 port 51234 [preauth]",
    ]:
        assert parse(line)["kind"] == "ssh", line


def test_ignores_duplicates_noise_and_private_sources():
    assert parse("Failed password for invalid user oracle from 45.83.12.7 port 51234 ssh2") is None
    assert parse("Accepted publickey for me from 45.83.12.7 port 51234 ssh2") is None
    assert parse(FIREWALL.replace("45.83.12.7", "192.168.1.5").format(port=22)) is None
    assert parse("[UFW BLOCK] IN=eth0 SRC=45.83.12.7 PROTO=TCP DPT=22") is None


def test_mask_hides_host_part():
    assert mask(ipaddress.ip_address("45.83.12.7")) == "45.83.x.x"
    assert mask(ipaddress.ip_address("2a01:4f8::1")) == "2a01:04f8:x::"


def test_port_scan_alerts_once():
    t, clock = tracker()
    for port in range(1, 30):
        t.record(parse(FIREWALL.format(port=port)))
        clock.t += 0.2
    assert [a["kind"] for a in t.alerts] == ["Port scan"]


def test_slow_probing_is_not_a_scan():
    t, clock = tracker()
    for port in range(1, 30):
        t.record(parse(FIREWALL.format(port=port)))
        clock.t += 2
    assert not t.alerts


def test_ssh_brute_force_alert():
    t, clock = tracker()
    line = "Invalid user admin from 45.83.12.7 port 51234"
    for _ in range(4):
        t.record(parse(line))
        clock.t += 10
    assert not t.alerts
    t.record(parse(line))
    assert t.alerts[0]["kind"] == "SSH brute force"


def test_snapshot_never_contains_full_ip():
    t, clock = tracker()
    for port in range(1, 30):
        t.record(parse(FIREWALL.format(port=port)))
    body = t.snapshot().decode()
    assert "45.83.12.7" not in body
    assert json.loads(body)["total"] == 29


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
