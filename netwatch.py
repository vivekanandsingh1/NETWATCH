import argparse
import ipaddress
import json
import random
import re
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import maxminddb

FIREWALL_RE = re.compile(r"\[NETWATCH\].*?\bSRC=(?P<ip>\S+).*?\bPROTO=(?P<proto>\w+)(?:.*?\bDPT=(?P<port>\d+))?")
SSH_RE = re.compile(
    r"(?:Invalid user \S* from|Failed \S+ for \S+ from|Connection closed by authenticating user \S+)"
    r" (?P<ip>[0-9a-fA-F:.]+) port"
)

SCAN_WINDOW, SCAN_PORTS = 10, 10
BRUTE_WINDOW, BRUTE_TRIES = 300, 5
ALERT_COOLDOWN = 600

WEB = Path(__file__).with_name("web")
ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


def parse(line):
    if m := FIREWALL_RE.search(line):
        kind, proto, port = "blocked", m["proto"].upper(), m["port"]
        if proto == "TCP" and (" SYN " not in line or " ACK " in line):
            return None
    elif m := SSH_RE.search(line):
        kind, proto, port = "ssh", "SSH", None
    else:
        return None
    try:
        ip = ipaddress.ip_address(m["ip"])
    except ValueError:
        return None
    if not ip.is_global:
        return None
    return {"ip": ip, "kind": kind, "proto": proto, "port": int(port) if port else None}


def mask(ip):
    if ip.version == 4:
        a, b, _, _ = str(ip).split(".")
        return f"{a}.{b}.x.x"
    return ":".join(ip.exploded.split(":")[:2]) + ":x::"


def make_locator(path):
    db = maxminddb.open_database(path) if Path(path).is_file() else None

    @lru_cache(maxsize=8192)
    def locate(ip):
        record = db.get(ip) if db else None
        location = (record or {}).get("location") or {}
        if "latitude" not in location:
            return None
        country = record.get("country") or {}
        return {
            "cc": country.get("iso_code", "??"),
            "country": country.get("names", {}).get("en", "Unknown"),
            "lat": round(location["latitude"], 1),
            "lon": round(location["longitude"], 1),
        }

    return locate


def trim(hits, oldest):
    while hits and hits[0][0] < oldest:
        hits.popleft()


class Tracker:
    def __init__(self, locate, home, clock=time.time):
        self.locate = locate
        self.home = home
        self.clock = clock
        self.lock = threading.Lock()
        self.started = clock()
        self.last_id = 0
        self.kinds = Counter()
        self.countries = Counter()
        self.country_names = {}
        self.ports = Counter()
        self.sources = set()
        self.per_second = Counter()
        self.events = deque(maxlen=80)
        self.alerts = deque(maxlen=8)
        self.scan_hits = defaultdict(deque)
        self.ssh_hits = defaultdict(deque)
        self.alerted = {}
        self.cached = (None, b"")

    def record(self, event):
        now = self.clock()
        ip = event["ip"]
        geo = self.locate(ip)
        masked = mask(ip)
        with self.lock:
            self.last_id += 1
            self.kinds[event["kind"]] += 1
            self.sources.add(masked)
            self.per_second[int(now)] += 1
            if event["port"] is not None:
                self.ports[event["port"]] += 1
            if geo:
                self.countries[geo["cc"]] += 1
                self.country_names[geo["cc"]] = geo["country"]
            self.events.append({
                "id": self.last_id,
                "t": round(now),
                "ip": masked,
                "kind": event["kind"],
                "proto": event["proto"],
                "port": event["port"],
                **(geo or {}),
            })
            self.detect(ip, masked, geo, event, now)

    def detect(self, ip, masked, geo, event, now):
        if event["kind"] == "blocked" and event["port"] is not None:
            hits = self.scan_hits[ip]
            hits.append((now, event["port"]))
            trim(hits, now - SCAN_WINDOW)
            ports = {port for _, port in hits}
            if len(ports) >= SCAN_PORTS:
                self.alert("Port scan", ip, masked, geo, f"{len(ports)} ports in {SCAN_WINDOW}s", now)
        elif event["kind"] == "ssh":
            hits = self.ssh_hits[ip]
            hits.append((now, None))
            trim(hits, now - BRUTE_WINDOW)
            if len(hits) >= BRUTE_TRIES:
                self.alert("SSH brute force", ip, masked, geo, f"{len(hits)} failed logins in 5 min", now)

    def alert(self, kind, ip, masked, geo, detail, now):
        key = (kind, ip)
        if key in self.alerted and now - self.alerted[key] < ALERT_COOLDOWN:
            return
        self.alerted[key] = now
        self.alerts.appendleft({
            "t": round(now),
            "kind": kind,
            "ip": masked,
            "cc": geo["cc"] if geo else "??",
            "detail": detail,
        })

    def prune(self, now):
        for hits, window in ((self.scan_hits, SCAN_WINDOW), (self.ssh_hits, BRUTE_WINDOW)):
            for ip in [ip for ip, h in hits.items() if not h or h[-1][0] < now - window]:
                del hits[ip]
        for key in [k for k, t in self.alerted.items() if now - t >= ALERT_COOLDOWN]:
            del self.alerted[key]
        for second in [s for s in self.per_second if s <= now - 60]:
            del self.per_second[second]

    def snapshot(self):
        now = int(self.clock())
        with self.lock:
            if self.cached[0] == now:
                return self.cached[1]
            self.prune(now)
            rate = [self.per_second.get(s, 0) for s in range(now - 59, now + 1)]
            body = json.dumps({
                "home": self.home,
                "started": round(self.started),
                "now": now,
                "total": self.last_id,
                "ssh": self.kinds["ssh"],
                "blocked": self.kinds["blocked"],
                "sources": len(self.sources),
                "country_count": len(self.countries),
                "countries": [[cc, self.country_names[cc], n] for cc, n in self.countries.most_common(6)],
                "ports": self.ports.most_common(6),
                "rate": rate,
                "events": list(self.events),
                "alerts": list(self.alerts),
            }).encode()
            self.cached = (now, body)
            return body


def make_handler(tracker):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NetWatch"
        sys_version = ""

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/api/state":
                self.reply(200, tracker.snapshot(), "application/json", "no-store")
            elif path in ROUTES:
                name, content_type = ROUTES[path]
                self.reply(200, (WEB / name).read_bytes(), content_type, "no-cache")
            else:
                self.reply(404, b"not found", "text/plain", "no-store")

        def reply(self, status, body, content_type, cache):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


def journal():
    command = [
        "journalctl", "--follow", "--lines=0", "--output=cat",
        "_TRANSPORT=kernel", "+", "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session",
    ]
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, errors="replace") as process:
        yield from process.stdout


def random_public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.getrandbits(32))
        if ip.is_global:
            return ip


def firewall_line(ip, port, proto="TCP"):
    return f"[NETWATCH] IN=eth0 OUT= SRC={ip} DST=203.0.113.10 LEN=44 PROTO={proto} SPT={random.randint(1024, 65535)} DPT={port} RES=0x00 SYN URGP=0"


def demo():
    common = [22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
    while True:
        ip, roll = random_public_ip(), random.random()
        if roll < 0.06:
            lines = [firewall_line(ip, port) for port in random.sample(range(1, 10000), 14)]
        elif roll < 0.12:
            lines = [f"Invalid user admin from {ip} port {random.randint(1024, 65535)}" for _ in range(6)]
        elif roll < 0.4:
            lines = [f"Connection closed by authenticating user root {ip} port {random.randint(1024, 65535)} [preauth]"]
        else:
            lines = [firewall_line(ip, random.choice(common), random.choice(["TCP"] * 8 + ["UDP"]))]
        for line in lines:
            yield line
            time.sleep(random.uniform(0.02, 0.15))
        time.sleep(random.uniform(0.1, 0.9))


def main():
    parser = argparse.ArgumentParser(description="Live map of unsolicited traffic hitting a Linux server.")
    parser.add_argument("--demo", action="store_true", help="generate synthetic traffic instead of reading the journal")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--geoip", default="dbip-city-lite.mmdb", help="path to a DB-IP or MaxMind city .mmdb file")
    parser.add_argument("--home", default="49.45,11.08", help="server location as latitude,longitude")
    args = parser.parse_args()

    tracker = Tracker(make_locator(args.geoip), [float(v) for v in args.home.split(",")])
    server = ThreadingHTTPServer((args.host, args.port), make_handler(tracker))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"NetWatch listening on http://{args.host}:{args.port}", flush=True)

    for line in demo() if args.demo else journal():
        if event := parse(line):
            tracker.record(event)
    raise SystemExit("log source closed")


if __name__ == "__main__":
    main()
