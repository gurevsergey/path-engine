package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := loadConfig("config.yml", "testdata/no-netmap.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sites) != 9 || len(cfg.Watch) != 3 || cfg.Gateways[0].Gateway.String() != "10.20.0.1" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.External) != 1 || cfg.External[0].Prefix.String() != "192.168.34.0/23" {
		t.Fatalf("unexpected external networks: %+v", cfg.External)
	}
	s := newSnapshot(0, cfg.Sites)
	if s.site("Gamma-router") != "Gamma" {
		t.Fatal("case-insensitive site regex lost")
	}
	p := filepath.Join(t.TempDir(), "invalid.yml")
	if err = os.WriteFile(p, []byte("sites: [{match: '[', site: invalid}]"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadConfig(p, "missing"); err == nil {
		t.Fatal("invalid site expression accepted")
	}
	if err = os.WriteFile(p, []byte("external_networks: [{prefix: 192.168.34.0/23}]"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadConfig(p, "missing"); err == nil {
		t.Fatal("external network without a name accepted")
	}
}

func TestPromSnapshot(t *testing.T) {
	metrics := map[string][]map[string]string{
		"route_collect_up == 1":  {{"routerboard_name": "R1"}},
		"route_info":             {{"routerboard_name": "R1", "dst": "10.1.0.9/24", "gateway": "10.2.0.1", "out_interface": "gre1", "active": "1", "distance": "10", "protocol": "static"}, {"dst": "bad"}},
		"route_ip_address_info":  {{"routerboard_name": "R1", "address": "10.1.0.1/24", "interface": "lan"}},
		"interface_address_info": {{"routerboard_name": "R1", "address": "10.1.0.1/24,10.2.0.2/30,invalid", "name": "lan"}},
		"tunnel_info":            {{"routerboard_name": "R1", "interface": "gre1", "type": "gre", "local_address": "1.1.1.1", "remote_address": "2.2.2.2", "ipsec": "0", "running": "1"}},
		`mktxp_ipsec_peer_state_info{state="established"}`: {{"routerboard_name": "R1", "local_address": "1.1.1.1", "remote_address": "2.2.2.2"}},
		`mangle_rule_info{disabled="0"}`:                   {{"routerboard_name": "R1", "position": "9", "chain": "prerouting", "action": "mark-routing", "new_mark": "via-b", "match": "src-address=10.1.0.2;protocol=tcp"}, {"routerboard_name": "R1", "position": "1", "chain": "prerouting", "action": "mark-connection", "passthrough": "1", "match": "-"}},
		"address_list_entry_info":                          {{"routerboard_name": "R1", "list": "LAN", "address": "10.1.0.0/24"}},
		"address_list_truncated":                           nil,
		"address_list_complete":                            {{"routerboard_name": "R1", "list": "LAN"}, {"routerboard_name": "R1", "list": "empty"}},
		"interface_list_member_info":                       {{"routerboard_name": "R1", "list": "LAN", "interface": "lan"}},
		`routing_rule_info{disabled="0"}`:                  {{"routerboard_name": "R1", "position": "4", "src": "10.1.0.0/24", "table": "via-b", "action": "lookup"}},
		`mktxp_routes_protocol_count{protocol="bgp"}`:      {{"routerboard_name": "R1"}},
		"bridge_host_info":                                 {{"routerboard_name": "R1", "mac_address": "aa:bb", "on_interface": "ether1", "vid": "10", "identity": "SW1"}},
		"network_link_info":                                {{"source": "R1", "port": "ether1", "target": "SW1", "peer_port": "ether2"}},
		"arp_entry_info":                                   {{"address": "10.1.0.2", "mac_address": "aa:bb"}},
		"firewall_rule_info":                               {{"routerboard_name": "R1", "table": "filter", "position": "3", "chain": "forward", "action": "drop", "target": "-", "match": "in-interface-list=WAN", "comment": "-"}},
		`route_collect_section_up{section="filter"} == 1`:  {{"routerboard_name": "R1"}},
	}
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.Method != "POST" || r.URL.Path != "/api/v1/query" {
			t.Error("incorrect Prometheus endpoint")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("time") != "123.456" {
			t.Errorf("historical time missing: %v", r.Form)
		}
		expr := r.Form.Get("query")
		rows, ok := metrics[expr]
		if !ok {
			t.Errorf("unexpected query: %s", expr)
		}
		samples := []any{}
		for _, m := range rows {
			samples = append(samples, object{"metric": m, "value": []any{123.456, "1"}})
		}
		_ = json.NewEncoder(w).Encode(object{"status": "success", "data": object{"result": samples}})
	}))
	defer srv.Close()
	cfg := Config{Sites: []Site{{Match: "^R", Site: "SITE-A"}}, Links: []Link{{A: "R1", APort: "ether1", B: "wrong", BPort: "p"}, {A: "SW1", APort: "ether3", B: "SW2", BPort: "ether4", Note: "manual"}}, Gateways: []Gateway{{netip.MustParsePrefix("10.1.0.0/24"), parseIP("10.1.0.1")}}}
	if err := compileSites(cfg.Sites); err != nil {
		t.Fatal(err)
	}
	s, err := loadSnapshot(context.Background(), &Prom{URL: srv.URL}, 123.456, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if count != 18 {
		t.Errorf("queries: %d", count)
	}
	if fw := s.Firewall[key("R1", "filter")]; len(fw) != 1 || fw[0].Position != 3 || fw[0].Match["in-interface-list"] != "WAN" || !s.FwCollected["R1"] {
		t.Errorf("firewall rules not loaded: %+v", s.Firewall)
	}
	if len(s.Addresses["R1"]) != 2 || s.Owner[parseIP("10.1.0.1")].Iface != "lan" {
		t.Error("addresses, ownership or fallback changed")
	}
	if s.Routes["R1"][0].Dst.String() != "10.1.0.0/24" {
		t.Error("route prefix not masked")
	}
	if s.Mangle["R1"][0].Position != 1 || s.Mangle["R1"][1].Match["protocol"] != "tcp" {
		t.Error("mangle parsing/sorting changed")
	}
	if !s.IfaceLists[key("R1", "LAN")]["lan"] || len(s.AddrLists[key("R1", "LAN")]) != 1 || len(s.Rules["R1"]) != 1 {
		t.Error("policy data missing")
	}
	if entries, ok := s.AddrLists[key("R1", "empty")]; !ok || len(entries) != 0 {
		t.Error("successfully collected empty list treated as missing")
	}
	if !s.Collected["R1"] || !s.BGPDevices["R1"] {
		t.Error("collection flags missing")
	}
	if !s.PortNeighbors[key("R1", "ether1")]["SW1"] || s.PortMACs[key("R1", "ether1")] != 1 || s.ARP[parseIP("10.1.0.2")] != "AA:BB" {
		t.Error("L2 state missing")
	}
	if s.Links[key("R1", "ether1")].Device != "SW1" || !strings.Contains(s.LinkSource[key("SW2", "ether4")], "manual") {
		t.Error("manual links must preserve LLDP")
	}
	if tun := tunnelOf(s, "R1", "gre1"); tun == nil || !tun.Encrypted {
		t.Error("established IPsec peer missing")
	}
	if len(s.Warnings) != 0 {
		t.Error("unexpected warning")
	}
}

func TestNetFlowQueryCompatibility(t *testing.T) {
	data, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Queries []struct {
			Name   string
			Params struct {
				Src, Dst, Proto, Dport string
				IPS                    []string
				Size                   int
			}
			Responses []object
			Queries   []object
			Expected  any
		} `json:"netflow_queries"`
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases.Queries {
		t.Run(c.Name, func(t *testing.T) {
			index := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, pass, ok := r.BasicAuth()
				if !ok || user != "test-user" || pass != "test-pass" {
					t.Error("missing Basic auth")
				}
				if r.URL.Path != "/netflow_*/_search" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("incorrect OpenSearch endpoint")
				}
				var body object
				if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
					t.Error(e)
				}
				if index >= len(c.Queries) {
					t.Error("extra search request")
					http.Error(w, "unexpected", 500)
					return
				}
				equalJSON(t, c.Queries[index], body)
				_ = json.NewEncoder(w).Encode(c.Responses[index])
				index++
			}))
			defer srv.Close()
			n := &NetFlow{URL: srv.URL, User: "test-user", Password: "test-pass"}
			var got any
			var err error
			switch c.Name {
			case "pair":
				got, err = n.pair(context.Background(), parseIP(c.Params.Src), parseIP(c.Params.Dst), 1000, 4600, c.Params.Proto, c.Params.Dport)
			case "top":
				got, err = n.topPeers(context.Background(), c.Params.IPS, 1000, 4600, c.Params.Size)
			case "conversations":
				got, err = n.conversations(context.Background(), c.Params.IPS, 1000, 4600, c.Params.Size)
			case "timeline":
				got, err = n.timeline(context.Background(), c.Params.IPS, 1000, 4600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if index != len(c.Queries) {
				t.Errorf("queries sent: %d", index)
			}
			equalJSON(t, c.Expected, got)
		})
	}
}

func TestHTTPRoutes(t *testing.T) {
	cases := loadGolden(t)
	s := fixtureState(&cases.Snapshots[0])
	for _, path := range []string{"/healthz", "/metrics", "/api/path?src=10.99.10.11&dst=10.99.30.50&time=0", "/api/summary?src=10.99.10.11&dst=10.99.30.50&time=now", "/api/graph/nodes?src=10.99.10.11&dst=10.99.30.50&time=0", "/api/graph/edges?src=10.99.10.11&dst=10.99.30.50&time=0", "/api/audit", "/api/audit?time=0", "/api/flows/top", "/api/flows/conversations", "/api/flows/timeline", "/api/flows/pair", "/missing", "/api/path?time=NaN"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			code := 200
			if strings.Contains(path, "/api/flows/") || strings.Contains(path, "NaN") {
				code = 500
			} else if path == "/missing" {
				code = 404
			}
			if w.Code != code {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			if strings.HasPrefix(path, "/api/") && code == 200 {
				var body any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if _, ok := body.([]any); !ok {
					t.Fatalf("API must return array: %s", w.Body)
				}
			}
		})
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("POST", "/healthz", nil))
	if w.Code != 405 {
		t.Error("POST accepted")
	}
}

func TestConcurrentRefreshAndRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(object{"status": "success", "data": object{"result": []any{}}})
	}))
	defer srv.Close()
	s := &State{cfg: Config{}, prom: &Prom{URL: srv.URL}, nf: &NetFlow{}, cache: map[int64]*Snapshot{}, watchWindow: 900}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 8; j++ {
				s.refresh(context.Background())
				_ = s.metrics()
				_, err := s.api(context.Background(), "/api/path", map[string]string{"src": "10.0.0.1", "dst": "10.0.1.1"})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.cache) != 1 || s.lastError != "" || s.lastRefresh == 0 {
		t.Fatal("refresh/cache failure")
	}
}

func TestUnavailableBackends(t *testing.T) {
	for _, body := range []string{`{"status":"error","error":"query failed"}`, `bad JSON`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, body) }))
		_, err := loadSnapshot(context.Background(), &Prom{URL: srv.URL}, 123, Config{})
		srv.Close()
		if err == nil {
			t.Fatal("Prometheus error ignored")
		}
	}
	cases := loadGolden(t)
	p := trace(&cases.Snapshots[0], "10.99.10.11", "10.99.30.50", "", "")
	before := p.Status
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	defer srv.Close()
	n := &NetFlow{URL: srv.URL, User: "test", Password: "test"}
	n.annotate(context.Background(), p, &cases.Snapshots[0], 0, 1, "", "")
	if p.Status != before || len(p.Warnings) == 0 || !strings.Contains(p.Warnings[len(p.Warnings)-1], "NetFlow недоступен") {
		t.Fatal("NetFlow failure must preserve inferred path")
	}
}

func TestExporterCache(t *testing.T) {
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		_ = json.NewEncoder(w).Encode(object{"aggregations": object{"o": object{"buckets": []any{object{"key": "10.99.10.1", "n": object{"buckets": []any{object{"key": "R-A"}}}}}}}})
	}))
	defer srv.Close()
	n := &NetFlow{URL: srv.URL}
	a, err := n.exporters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.exporters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !reflect.DeepEqual(a, b) || a["10.99.10.1"] != "R-A" {
		t.Fatal("exporter cache changed")
	}
}
