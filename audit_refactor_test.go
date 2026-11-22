package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAcceptedFindingsAndExpiry(t *testing.T) {
	at := float64(time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC).Unix())
	f := Finding{Check: "backup_route_active", Device: "H1_TENANT_CHR", Object: "192.168.44.0/22 [main]"}
	rules := []Accepted{{Check: "backup_route_active", Device: "H1_TENANT_CHR", Object: "192.168.44.0/22", Reason: "Gamma выведен", Until: "2026-12-31"}}
	if got := acceptedReason(rules, f, at); got != "Gamma выведен (до 2026-12-31)" {
		t.Fatalf("accepted: %q", got)
	}
	rules[0].Until = "2026-11-11"
	if got := acceptedReason(rules, f, at); got != "" {
		t.Fatalf("expired rule still applied: %q", got)
	}
	rules[0].Until, rules[0].Device = "", "OTHER"
	if got := acceptedReason(rules, f, at); got != "" {
		t.Fatalf("other device matched: %q", got)
	}
}

func TestGroupFindingsMergesObjects(t *testing.T) {
	in := []Finding{
		{Check: "tunnel_down", Severity: "warning", Device: "GAMMA", Object: "tun1", Detail: "same"},
		{Check: "tunnel_down", Severity: "warning", Device: "GAMMA", Object: "tun2", Detail: "same"},
		{Check: "dead_route", Severity: "info", Device: "R", Object: "10.0.0.0/8", Detail: "other"},
	}
	out := groupFindings(in)
	if len(out) != 2 || out[0].Object != "2 объектов: tun1, tun2" || out[1].Object != "10.0.0.0/8" {
		t.Fatalf("grouped: %+v", out)
	}
}

func TestDeadRouteEvidenceExplainsReason(t *testing.T) {
	s := newSnapshot(0, nil)
	s.Tunnels[key("R", "gre1")] = Tunnel{Type: "gre", Running: false}
	s.Routes["R"] = []Route{
		{Table: "main", Dst: netip.MustParsePrefix("10.1.0.0/24"), Gateway: "10.9.9.1", OutIf: "gre1", Distance: 1, Protocol: "static", Comment: "-"},
		{Table: "pbr", Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: "-", OutIf: "-", Distance: 1, Protocol: "static", Comment: "-"},
	}
	got := map[string]Finding{}
	for _, f := range routeChecks(s, nil) {
		got[f.Object] = f
	}
	if f := got["10.1.0.0/24 [main]"]; !strings.Contains(f.Evidence, "туннель gre1 не running") {
		t.Fatalf("tunnel reason missing: %+v", f)
	}
	if f := got["0.0.0.0/0 [pbr]"]; !strings.Contains(f.Detail, "via без шлюза") || !strings.Contains(f.Evidence, "таблица политики") {
		t.Fatalf("pbr dead route: %+v", f)
	}
}

func TestL3StatusIgnoresL2Gaps(t *testing.T) {
	p := &Path{Hops: []*Hop{
		{Kind: "host", Status: "Inferred"},
		{Kind: "unknown", Device: "L2 ?", Status: "Unknown"},
		{Kind: "router", Device: "R1", Status: "Inferred"},
		{Kind: "host", Status: "Inferred"},
	}}
	if l3Status(p) != "Inferred" || l2Gaps(p) != 1 {
		t.Fatalf("l3 %s gaps %d", l3Status(p), l2Gaps(p))
	}
	p.Hops[2].Status = "Conflicting"
	if l3Status(p) != "Conflicting" {
		t.Fatal("router conflict must stay")
	}
}

func TestSensitiveRouteDownShowsWhereTrafficGoes(t *testing.T) {
	s := newSnapshot(0, nil)
	s.Routes["GR"] = []Route{
		{Table: "main", Dst: netip.MustParsePrefix("192.168.31.16/28"), Gateway: "10.200.164.18", OutIf: "-", Distance: 1, Protocol: "static", Comment: "-"},
		{Table: "main", Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: "198.18.85.1", OutIf: "wan", Distance: 1, Protocol: "static", Active: true, Comment: "-"},
		{Table: "main", Dst: netip.MustParsePrefix("10.5.0.0/24"), Gateway: "10.9.9.9", OutIf: "-", Distance: 1, Protocol: "static", Comment: "-"},
	}
	sens := []Sensitive{{Prefix: netip.MustParsePrefix("192.168.31.16/28"), Name: "Backup"}}
	got := map[string]Finding{}
	for _, f := range routeChecks(s, sens) {
		got[f.Object] = f
	}
	f := got["192.168.31.16/28 [main]"]
	if f.Check != "sensitive_route_down" || f.Severity != "warning" || !strings.Contains(f.Detail, "шлюз провайдера") {
		t.Fatalf("sensitive: %+v", f)
	}
	if f := got["10.5.0.0/24 [main]"]; f.Check != "dead_route" || !strings.Contains(f.Evidence, "вместо него трафик идёт по 0.0.0.0/0") {
		t.Fatalf("dead route fallback: %+v", f)
	}
}

func TestQuietDevicesHideOnlyInfo(t *testing.T) {
	s := newSnapshot(0, nil)
	s.Routes["GR"] = []Route{
		{Table: "main", Dst: netip.MustParsePrefix("10.5.0.0/24"), Gateway: "10.9.9.9", OutIf: "-", Distance: 1, Protocol: "static", Comment: "-"},
		{Table: "main", Dst: netip.MustParsePrefix("192.168.31.16/28"), Gateway: "10.9.9.8", OutIf: "-", Distance: 1, Protocol: "static", Comment: "-"},
	}
	cfg := Config{QuietDevices: []string{"GR"}, Sensitive: []Sensitive{{Prefix: netip.MustParsePrefix("192.168.31.16/28")}}}
	findings, _ := runAudit(s, cfg)
	if len(findings) != 1 || findings[0].Check != "sensitive_route_down" {
		t.Fatalf("quiet device: %+v", findings)
	}
}
