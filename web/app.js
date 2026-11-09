const POLL_MS = 2000;
const MAX_FLIGHTS = 30;
const COLORS = { blocked: "#22d3ee", ssh: "#f472b6" };
const PORT_NAMES = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
  135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
  1900: "UPnP", 2375: "Docker", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "Postgres", 5555: "ADB",
  5900: "VNC", 6379: "Redis", 8080: "HTTP alt", 8443: "HTTPS alt", 9200: "Elastic", 11211: "Memcached", 27017: "MongoDB",
};

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  node.append(...children);
  return node;
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

const projection = d3.geoNaturalEarth1().fitExtent([[8, 8], [952, 462]], { type: "Sphere" });
const geoPath = d3.geoPath(projection);
let homePoint = null;
let lastId = 0;

async function drawLand() {
  const world = await d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json");
  const land = topojson.feature(world, world.objects.countries).features.filter((f) => f.id !== "010");
  for (const feature of land) $("land").append(svg("path", { d: geoPath(feature), class: "land" }));
  const [[x0, y0], [x1, y1]] = geoPath.bounds({ type: "FeatureCollection", features: land });
  $("map").setAttribute("viewBox", `${x0 - 6} ${y0 - 6} ${x1 - x0 + 12} ${y1 - y0 + 12}`);
}

function drawHome(home) {
  homePoint = projection([home[1], home[0]]);
  const [x, y] = homePoint;
  $("home").replaceChildren(
    svg("circle", { cx: x, cy: y, r: 4, class: "pulse" }),
    svg("circle", { cx: x, cy: y, r: 4.5, class: "home" }),
    Object.assign(svg("text", { x: x + 10, y: y + 16, class: "home-label" }), { textContent: "my server" }),
  );
}

function fly(event) {
  const from = projection([event.lon, event.lat]);
  if (!from || !homePoint) return;
  const [x0, y0] = from;
  const [x1, y1] = homePoint;
  const lift = Math.hypot(x1 - x0, y1 - y0) * 0.35;
  const color = COLORS[event.kind];
  const arc = svg("path", { d: `M${x0},${y0} Q${(x0 + x1) / 2},${(y0 + y1) / 2 - lift} ${x1},${y1}`, class: "arc", stroke: color });
  $("arcs").append(arc);
  const length = arc.getTotalLength() || 1;
  arc.style.strokeDasharray = length;
  arc.animate(
    [{ strokeDashoffset: length, opacity: 1 }, { strokeDashoffset: 0, opacity: 1, offset: 0.7 }, { strokeDashoffset: 0, opacity: 0 }],
    { duration: 2400, easing: "ease-in-out" },
  ).onfinish = () => arc.remove();

  const ring = svg("circle", { cx: x0, cy: y0, r: 3, fill: "none", stroke: color });
  $("arcs").append(ring);
  ring.animate([{ r: 2, opacity: 1 }, { r: 14, opacity: 0 }], { duration: 1400, easing: "ease-out" }).onfinish = () => ring.remove();
}

function drawSources(events) {
  const seen = new Set();
  const dots = [];
  for (const event of events) {
    const key = `${event.lat},${event.lon}`;
    if (event.lat === undefined || seen.has(key)) continue;
    seen.add(key);
    const [x, y] = projection([event.lon, event.lat]);
    dots.push(svg("circle", { cx: x, cy: y, r: 2.6, fill: COLORS[event.kind], class: "source" }));
  }
  $("sources").replaceChildren(...dots);
}

function clock(t) {
  return new Date(t * 1000).toLocaleTimeString([], { hour12: false });
}

function duration(seconds) {
  const m = Math.floor(seconds / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d) return `${d}d ${h % 24}h`;
  if (h) return `${h}h ${m % 60}m`;
  return `${m}m`;
}

function portLabel(port) {
  return PORT_NAMES[port] ? `${port} · ${PORT_NAMES[port]}` : String(port);
}

function drawStats(state) {
  const perMinute = state.rate.reduce((a, b) => a + b, 0);
  $("s-total").textContent = state.total.toLocaleString();
  $("s-sources").textContent = state.sources.toLocaleString();
  $("s-countries").textContent = state.country_count;
  $("s-ssh").textContent = state.ssh.toLocaleString();
  $("s-rate").textContent = perMinute.toLocaleString();
  $("s-uptime").textContent = duration(state.now - state.started);
}

function drawSpark(rate) {
  const peak = Math.max(4, ...rate);
  const points = rate.map((v, i) => `${i},${40 - (v / peak) * 36}`).join(" ");
  $("spark").querySelector("polyline").setAttribute("points", points);
  $("spark").querySelector("polygon").setAttribute("points", `0,40 ${points} 59,40`);
  $("s-peak").textContent = `peak ${Math.max(...rate)}/s`;
}

function drawFeed(events, previousId) {
  const rows = events.slice(-12).reverse().map((event) => {
    const target = event.kind === "ssh" ? "ssh login" : event.port ? portLabel(event.port) : event.proto;
    const tag = el("span", { className: "tag", textContent: event.kind === "ssh" ? "SSH" : event.proto });
    tag.style.background = COLORS[event.kind];
    return el("tr", { className: event.id > previousId ? "fresh" : "" },
      el("td", {}, clock(event.t)),
      el("td", {}, event.ip),
      el("td", { className: "dim" }, event.country || "Unknown"),
      el("td", {}, "→ ", target),
      el("td", {}, tag),
    );
  });
  $("feed").replaceChildren(...rows);
}

function drawBars(id, items) {
  const top = items[0]?.at(-1) || 1;
  $(id).replaceChildren(...items.map(([label, count]) => {
    const bar = el("span", { className: "bar" });
    bar.style.width = `${(count / top) * 100}%`;
    return el("li", {}, el("span", {}, label), el("b", {}, count.toLocaleString()), bar);
  }));
}

function drawAlerts(alerts) {
  $("s-alerts").textContent = alerts.length;
  if (!alerts.length) return $("alerts").replaceChildren(el("li", { className: "empty" }, "Quiet so far"));
  $("alerts").replaceChildren(...alerts.map((alert) =>
    el("li", { className: alert.kind === "Port scan" ? "scan" : "" },
      `▲ ${alert.kind}`,
      el("small", {}, `${alert.ip} (${alert.cc}) · ${alert.detail} · ${clock(alert.t)}`),
    ),
  ));
}

function render(state) {
  if (!homePoint) drawHome(state.home);
  const fresh = state.events.filter((event) => event.id > lastId).slice(-MAX_FLIGHTS);
  fresh.forEach((event, i) => setTimeout(() => fly(event), (i / fresh.length) * POLL_MS));
  drawStats(state);
  drawSpark(state.rate);
  drawFeed(state.events, lastId);
  drawSources(state.events);
  drawBars("countries", state.countries.map(([, name, n]) => [name, n]));
  drawBars("ports", state.ports.map(([port, n]) => [portLabel(port), n]));
  drawAlerts(state.alerts);
  lastId = state.total;
}

async function poll() {
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(response.status);
    render(await response.json());
    $("live").className = "live";
    $("live").textContent = "LIVE";
  } catch {
    $("live").className = "live off";
    $("live").textContent = "OFFLINE";
  }
  setTimeout(poll, POLL_MS);
}

drawLand().catch(() => {});
poll();
