package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestDNSAddressListPolicyAndIncompleteData(t *testing.T) {
	// Model the exporter snapshot: RouterOS resolves the hostname itself;
	// Path Explorer must use that dynamic member, not perform its own DNS lookup.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rows := []any{}
		add := func(list, address, value string) {
			rows = append(rows, object{"metric": object{"routerboard_name": "CCR", "list": list, "address": address}, "value": []any{123, value}})
		}
		switch r.Form.Get("query") {
		case "address_list_entry_info":
			add("via-isp-a", "mail.example.com", "1")
			add("via-isp-a", "203.0.113.50", "1")
			add("truncated", "203.0.113.50", "1")
			add("legacy-truncated", "203.0.113.50", "1")
			add("range", "192.0.2.1-192.0.2.20", "1")
		case "address_list_truncated":
			add("legacy-truncated", "", "1")
		case "address_list_complete":
			add("via-isp-a", "", "1")
			add("empty", "", "1")
			add("truncated", "", "0")
			add("range", "", "1")
		}
		_ = json.NewEncoder(w).Encode(object{"status": "success", "data": object{"result": rows}})
	}))
	defer srv.Close()
	s, err := loadSnapshot(context.Background(), &Prom{URL: srv.URL}, 123, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		list, dst string
		want      match
	}{
		{"via-isp-a", "203.0.113.50", hit},
		{"via-isp-a", "192.168.31.21", no},
		{"!via-isp-a", "192.168.31.21", hit},
		{"empty", "192.168.31.21", no},
		{"!empty", "192.168.31.21", hit},
		{"missing", "192.168.31.21", unknown},
		{"!missing", "192.168.31.21", unknown},
		{"truncated", "192.168.31.21", unknown},
		{"!truncated", "192.168.31.21", unknown},
		{"legacy-truncated", "192.168.31.21", unknown},
		{"truncated", "203.0.113.50", hit},
		{"!truncated", "203.0.113.50", no},
		{"range", "192.0.2.10", unknown},
	} {
		r := Mangle{Match: map[string]string{"dst-address-list": tc.list}}
		if got := ruleMatches(s, "CCR", r, Packet{Dst: parseIP(tc.dst)}, nil); got != tc.want {
			t.Errorf("%s destination %s: got %v, want %v", tc.list, tc.dst, got, tc.want)
		}
	}
	// An unknown connection-state must not poison later connection-mark rules
	// when the destination definitely does not match the first rule.
	s.Mangle["CCR"] = []Mangle{
		{Position: 35, Chain: "prerouting", Action: "mark-connection", NewMark: "isp-a", Passthrough: true,
			Match: map[string]string{"connection-state": "new", "dst-address-list": "via-isp-a"}},
		{Position: 36, Chain: "prerouting", Action: "mark-routing", NewMark: "via-isp-a",
			Match: map[string]string{"connection-mark": "isp-a"}},
		{Position: 40, Chain: "prerouting", Action: "mark-routing", NewMark: "via-fournet",
			Match: map[string]string{"connection-mark": "fournet"}},
	}
	for _, dst := range []string{"192.168.31.21", "10.20.0.231", "192.168.44.10"} {
		table, _, unsure := selectTable(s, "CCR", Packet{Src: parseIP("192.168.31.21"), Dst: parseIP(dst)})
		if table != "main" || len(unsure) != 0 {
			t.Errorf("internal destination %s: table %s, unexpected ambiguity %v", dst, table, unsure)
		}
	}
}

// mark-connection по connection-state=new и списку адресов решает путь
// соединения: следующее правило по connection-mark выбирает таблицу.
func TestConnectionMarkOnNewConnectionSelectsTable(t *testing.T) {
	s := &Snapshot{
		Mangle: map[string][]Mangle{"CCR": {
			{Position: 59, Chain: "prerouting", Action: "mark-connection", NewMark: "eu", Passthrough: true,
				Match: map[string]string{"connection-state": "new", "dst-address-list": "to-eu"}},
			{Position: 60, Chain: "prerouting", Action: "mark-routing", NewMark: "via-eu",
				Match: map[string]string{"connection-mark": "eu", "in-interface-list": "!TUNNELS"}},
		}},
		AddrLists:    map[string][]netip.Prefix{key("CCR", "to-eu"): {netip.MustParsePrefix("1.1.1.1/32")}},
		PartialLists: map[string]bool{},
		IfaceLists:   map[string]map[string]bool{key("CCR", "TUNNELS"): {"gre1": true}},
	}
	table, _, unsure := selectTable(s, "CCR", Packet{Src: parseIP("10.20.0.23"), Dst: parseIP("1.1.1.1"), InIf: "lan"})
	if table != "via-eu" || len(unsure) != 0 {
		t.Fatalf("listed destination: table %s, unsure %v", table, unsure)
	}
	table, _, unsure = selectTable(s, "CCR", Packet{Src: parseIP("10.20.0.23"), Dst: parseIP("8.8.8.8"), InIf: "lan"})
	if table != "main" || len(unsure) != 0 {
		t.Fatalf("other destination: table %s, unsure %v", table, unsure)
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{"1.1.1.1": true, "10.0.0.1": false, "192.168.1.1": false, "100.64.1.1": false, "127.0.0.1": false} {
		if isPublic(parseIP(ip)) != want {
			t.Errorf("isPublic(%s) != %v", ip, want)
		}
	}
}

func TestDomainDestinationResolvesViaDNS(t *testing.T) {
	old := lookupNetIP
	defer func() { lookupNetIP = old }()
	lookupNetIP = func(ctx context.Context, name string) ([]netip.Addr, error) {
		if name == "example.org" {
			return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name}
	}
	s := newSnapshot(0, nil)
	ep := resolveEndpoint(s, "Example.ORG.")
	if ep == nil || ep.IP.String() != "93.184.215.14" || ep.Name != "example.org" {
		t.Fatalf("resolved %+v", ep)
	}
	if h := endpointHop(ep, "destination"); h.Device != "example.org" || h.IP != "93.184.215.14" {
		t.Fatalf("hop %+v", h)
	}
	for _, bad := range []string{"missing.example", "no-dot", "a b.c"} {
		if resolveEndpoint(s, bad) != nil {
			t.Errorf("%q must not resolve", bad)
		}
	}
}

func TestPublicToPublicDoesNotRecurse(t *testing.T) {
	s := newSnapshot(0, nil)
	p := trace(s, "1.1.1.1", "8.8.8.8", "", "")
	if p == nil || len(p.Hops) == 0 {
		t.Fatalf("no path returned")
	}
}

func TestRecursiveGatewayUsesImmediateGW(t *testing.T) {
	s := newSnapshot(0, nil)
	s.Owner[netip.MustParseAddr("10.201.164.1")] = Port{"RB5009", "VL.0555"}
	r := Route{Gateway: "1.0.0.1", OutIf: "VL.0555", ImmediateGW: "10.201.164.1%VL.0555"}
	if next, _ := nextDevice(s, "Helix", r); next.Device != "RB5009" || next.Iface != "VL.0555" {
		t.Fatalf("next %+v", next)
	}
	r.ImmediateGW = ""
	if next, _ := nextDevice(s, "Helix", r); next.Device != "" {
		t.Fatalf("without immediate-gw must stay unknown, got %+v", next)
	}
}
