# path-engine

Answers "which way does this traffic actually go?" for a multi-site MikroTik
network, using only data that is already in Prometheus.

Given a source and a destination (IP address or DNS name), it computes
the forward and the reverse path hop by hop: routers, switches, ingress and
egress interfaces, VLANs, tunnels, firewall and NAT decisions. It can do this
for any moment in the past that Prometheus still remembers, and it keeps
auditing the routing for non-optimal or unsafe decisions.

It is read-only: it never connects to network devices and never changes them.

## Why

It was written after backup traffic was found taking a path nobody intended.
`traceroute` shows one direction, from one host, right now. This tool shows
both directions, for any pair, at any point in time, and explains each hop.

## How it works

```
 RouterOS API ──► route-exporter ────────┐
 RouterOS, SNMP ► bridge-host-exporter ──┴─► Prometheus ─► path-engine ─► Grafana (JSON API)
 NetFlow v9 ────► OpenSearch ──────────────────────────────────┘       └► /metrics ─► alerts
```

path-engine has no storage of its own. Every request loads a snapshot of the
network state from Prometheus at the requested time, so the history of paths
is the history of the metrics. The exporters it reads live in
[noc-exporters](https://github.com/gurevsergey/noc-exporters).

Tracing a pair:

1. **Endpoints.** A DNS name is resolved to an address; the MAC of an address
   comes from router ARP tables.
2. **First router.** The gateway from `subnet_gateways` in the config, or the
   only router that has an address in the source subnet.
3. **Layer 2.** From the router to the host MAC through switch FDBs, crossing
   switches along LLDP/MNDP links. Same-subnet traffic is traced on L2 only.
4. **Layer 3.** On every router: routing table selection by mangle rules
   (connection marks, address lists, interface lists) and routing rules, then
   longest prefix match, recursive gateways, ECMP, tunnels.
5. **Firewall and NAT.** `filter`, `srcnat` and `dstnat` are evaluated for the
   packet, so the trace shows where it is translated or dropped.
6. **NetFlow.** If flow records are available, hops are checked against the
   interfaces the flow was really seen on.

### Confidence model

Every hop carries a status and the evidence behind it.

| Status | Meaning |
|---|---|
| **Observed** | The flow was seen in NetFlow on this router through these interfaces |
| **Inferred** | Computed from routing tables, policy routing, FDB, LLDP links or inventory |
| **Unknown** | Not enough data: device is not polled, MAC not found, no data for that time |
| **Conflicting** | Sources disagree, or the choice is ambiguous (ECMP, several gateways, a mangle condition that cannot be evaluated) |

Routing tables and FDBs never produce Observed. The two directions are
computed independently and symmetry is never assumed. Missing NetFlow records
are not treated as missing traffic.

### Routing audit

A background loop checks the whole network every `REFRESH_INTERVAL` seconds.

| Check | Severity | Finding |
|---|---|---|
| `sensitive_route_down` | warning | Static route to a protected network is inactive |
| `unencrypted_sensitive` | warning | Route to a protected network goes through a tunnel without IPsec |
| `transit_site` | warning | A watched pair passes through a third site |
| `asymmetric` | warning | Forward and reverse directions use different routers |
| `observed_differs` | warning | NetFlow shows other interfaces than the routing tables imply |
| `static_over_dynamic` | warning | A static route shadows an OSPF route through another interface |
| `backup_route_active` | warning | The primary route is inactive, traffic uses the backup |
| `tunnel_down` | warning | An active route points into a tunnel that is not running |
| `dead_route` | info | A static route is inactive and nothing replaces it |
| `policy_without_lan` | info | `mark-routing` without a destination limit leads to a table with no local routes |

Findings can be accepted with a reason and a review date in `config.yml`.

## Run

```sh
docker build -t path-engine .
docker run --rm -p 49105:49105 \
  -e PROMETHEUS_URL=http://prometheus:9090 \
  -v "$PWD/config.yml:/config.yml:ro" path-engine
```

| Variable | Default | Purpose |
|---|---|---|
| `PROMETHEUS_URL` | `http://prometheus:9090` | Source of network state |
| `CONFIG_PATH` | `/config.yml` | Sites, protected networks, watched pairs |
| `NETMAP_PATH` | `/netmap-config.json` | Optional manual L2 links for devices without LLDP |
| `LISTEN_PORT` | `49105` | HTTP port |
| `REFRESH_INTERVAL` | `120` | Audit period, seconds |
| `WATCH_WINDOW` | `900` | Window for path change detection, seconds |
| `NETFLOW_OS_URL`, `NETFLOW_OS_USER`, `NETFLOW_OS_PASSWORD` | unset | OpenSearch with NetFlow records; NetFlow is off without them |
| `NETFLOW_INDEX` | `netflow_*` | Index pattern |

[config.yml](config.yml) is a commented example for a fictional network.

## API

Designed for the Grafana Infinity data source; every endpoint accepts `time`.

| Endpoint | Returns |
|---|---|
| `GET /api/summary?src=&dst=` | Status, coverage and symmetry of both directions |
| `GET /api/path?src=&dst=&mode=both\|forward\|reverse[&proto=&dport=]` | Hops with evidence |
| `GET /api/graph/nodes`, `/api/graph/edges` | Frames for the Node Graph panel |
| `GET /api/audit` | Audit findings |
| `GET /api/watch` | Watched pairs and their route history |
| `GET /api/flows/top\|conversations\|timeline?host=` | NetFlow per host |
| `GET /api/flows/pair?src=&dst=` | NetFlow per pair, by exporter and interface |
| `GET /metrics`, `/healthz` | `path_audit_*`, `path_watch_*`, `path_engine_*`; liveness |

## Tests

```sh
go test -race ./...
```

Tests need neither Prometheus nor devices. `testdata/golden.json` holds
synthetic network snapshots with the expected traces, audit findings, API
responses and metrics; results are compared in full, including evidence
strings.

## Limitations

- Observed is only possible on routers that export NetFlow.
- BGP routes are not collected; hops on BGP routers carry a warning.
- Mangle `accept`/`jump`/`return` are not evaluated.
- The physical member link inside a LAG is not determined.
- The underlay path of a tunnel is not traced.
- IPv4 only.

Code comments and user-facing messages are in Russian.

## License

MIT
