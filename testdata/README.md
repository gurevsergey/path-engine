# Regression fixtures

`golden.json` holds synthetic network snapshots and the results expected from
them: traces, audit findings, NetFlow annotation, path comparison, API
responses and metrics. The scenarios cover unknown endpoints, missing routes,
ECMP, loops, policy routing conditions, dead routes and failed tunnels.
OpenSearch fixtures record both the outgoing query and the returned rows for
pair, top peers, conversations and timeline.

Snapshots are deduplicated and referenced by `snapshot_index`. Composite map
keys use U+001F between their components. Addresses retain their host bits;
route prefixes are network addresses. All IPs, devices, flows and credentials
are synthetic. No production telemetry or secrets are stored.

The tests compare full results, including evidence strings. Finding order,
metric label order and the order of policy match conditions are insignificant
and normalized for comparison. `integration_test.go` additionally checks HTTP
requests, loading the actual YAML config, unavailable backends and concurrent
refreshes/requests under the race detector.
