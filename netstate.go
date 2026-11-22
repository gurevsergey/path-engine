package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Sample struct {
	Metric map[string]string `json:"metric"`
	Value  []json.RawMessage `json:"value"`
}
type Prom struct {
	URL    string
	Client *http.Client
}

func (p *Prom) query(ctx context.Context, expr string, at float64) ([]Sample, error) {
	form := url.Values{"query": {expr}, "time": {strconv.FormatFloat(at, 'f', 3, 64)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.URL, "/")+"/api/v1/query", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []Sample `json:"result"`
		} `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&body); err != nil {
		return nil, err
	}
	if body.Status != "success" {
		return nil, fmt.Errorf("prometheus: %s", body.Error)
	}
	return body.Data.Result, nil
}
func (s Sample) number() float64 {
	if len(s.Value) < 2 {
		return 0
	}
	var str string
	if json.Unmarshal(s.Value[1], &str) != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(str, 64)
	return v
}
func parseMatch(text string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(text, ";") {
		k, v, ok := strings.Cut(p, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}
func integer(s string) int { v, _ := strconv.Atoi(s); return v }
func addMember(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}
func (s *Snapshot) addAddress(dev, iface, text string) {
	p, err := netip.ParsePrefix(text)
	if err != nil {
		return
	}
	a := Address{p, iface}
	for _, old := range s.Addresses[dev] {
		if old == a {
			return
		}
	}
	s.Addresses[dev] = append(s.Addresses[dev], a)
	if _, ok := s.Owner[p.Addr()]; !ok {
		s.Owner[p.Addr()] = Port{dev, iface}
	}
}
func loadSnapshot(ctx context.Context, p *Prom, at float64, cfg Config) (*Snapshot, error) {
	s := newSnapshot(at, cfg.Sites)
	s.Gateways = cfg.Gateways
	s.External = cfg.External
	queries := []string{"route_collect_up == 1", "route_info", "route_ip_address_info", "interface_address_info", "tunnel_info", `mktxp_ipsec_peer_state_info{state="established"}`, `mangle_rule_info{disabled="0"}`, "address_list_entry_info", "interface_list_member_info", `routing_rule_info{disabled="0"}`, `mktxp_routes_protocol_count{protocol="bgp"}`, "bridge_host_info", "network_link_info", "arp_entry_info", "address_list_complete", "address_list_truncated", "firewall_rule_info", `route_collect_section_up{section="filter"} == 1`}
	for i, expr := range queries {
		rows, err := p.query(ctx, expr, at)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", expr, err)
		}
		for _, row := range rows {
			m := row.Metric
			dev := m["routerboard_name"]
			switch i {
			case 0:
				s.Collected[dev] = true
			case 1:
				dst := parseNet(m["dst"])
				if !dst.IsValid() {
					continue
				}
				s.Routes[dev] = append(s.Routes[dev], Route{Table: or(m["routing_table"], "main"), Dst: dst, Gateway: or(m["gateway"], "-"), OutIf: or(m["out_interface"], "-"), Distance: integer(m["distance"]), Protocol: or(m["protocol"], "-"), Active: m["active"] == "1", ECMP: m["ecmp"] == "1", Comment: or(m["comment"], "-"), Count: int(row.number()), ImmediateGW: m["immediate_gw"]})
			case 2:
				s.addAddress(dev, or(m["interface"], "-"), m["address"])
			case 3:
				for _, part := range strings.Split(m["address"], ",") {
					s.addAddress(dev, or(m["name"], "-"), strings.TrimSpace(part))
				}
			case 4:
				s.Tunnels[key(dev, m["interface"])] = Tunnel{m["type"], m["local_address"], m["remote_address"], m["ipsec"] == "1", m["running"] == "1"}
			case 5:
				s.IPsecPeers[key(dev, m["local_address"], m["remote_address"])] = true
			case 6:
				s.Mangle[dev] = append(s.Mangle[dev], Mangle{integer(m["position"]), m["id"], m["chain"], m["action"], m["new_mark"], m["passthrough"] == "1", parseMatch(m["match"]), or(m["comment"], "-")})
			case 7:
				n := parseNet(strings.SplitN(m["address"], "-", 2)[0])
				if n.IsValid() {
					s.AddrLists[key(dev, m["list"])] = append(s.AddrLists[key(dev, m["list"])], n)
					// A range's first address is a known member, but does not
					// establish that other addresses are absent from the list.
					if strings.Contains(m["address"], "-") {
						s.PartialLists[key(dev, m["list"])] = true
					}
				}
			case 8:
				addMember(s.IfaceLists, key(dev, m["list"]), m["interface"])
			case 9:
				s.Rules[dev] = append(s.Rules[dev], RoutingRule{integer(m["position"]), m["src"], m["dst"], m["interface"], m["routing_mark"], m["table"], m["action"]})
			case 10:
				if row.number() > 0 {
					s.BGPDevices[dev] = true
				}
			case 11:
				mac := strings.ToUpper(m["mac_address"])
				port := or(m["on_interface"], "-")
				s.FDB[key(dev, mac)] = append(s.FDB[key(dev, mac)], FDBEntry{port, or(m["vid"], "-")})
				s.PortMACs[key(dev, port)]++
				if present(m["identity"]) {
					addMember(s.PortNeighbors, key(dev, port), m["identity"])
				}
				s.FDBDevices[dev] = true
			case 12:
				a, b := Port{m["source"], m["port"]}, Port{m["target"], m["peer_port"]}
				if a.Device == "" || a.Iface == "" || b.Device == "" || b.Iface == "" {
					continue
				}
				s.Links[key(a.Device, a.Iface)] = b
				s.Links[key(b.Device, b.Iface)] = a
			case 13:
				a := parseIP(m["address"])
				if a.IsValid() {
					if _, ok := s.ARP[a]; !ok {
						s.ARP[a] = strings.ToUpper(m["mac_address"])
					}
				}
			case 14:
				k := key(dev, m["list"])
				if row.number() == 1 {
					// An explicitly collected empty list is different from a
					// missing list (failed collection or old historical data).
					if _, ok := s.AddrLists[k]; !ok {
						s.AddrLists[k] = []netip.Prefix{}
					}
				} else {
					s.PartialLists[k] = true
				}
			case 15:
				// Older snapshots already expose truncation, even without
				// the new completeness metric. Preserve that uncertainty.
				if row.number() > 0 {
					s.PartialLists[key(dev, m["list"])] = true
				}
			case 16:
				s.Firewall[key(dev, m["table"])] = append(s.Firewall[key(dev, m["table"])], FwRule{integer(m["position"]), m["chain"], m["action"], or(m["target"], "-"), parseMatch(m["match"]), or(m["comment"], "-")})
			case 17:
				s.FwCollected[dev] = true
			}
		}
	}
	if len(s.Collected) == 0 {
		s.Warnings = append(s.Warnings, "На этот момент нет данных route-exporter: L3-участки неизвестны.")
	}
	for d := range s.Mangle {
		sort.SliceStable(s.Mangle[d], func(i, j int) bool { return s.Mangle[d][i].Position < s.Mangle[d][j].Position })
	}
	sortFirewall(s)
	for d := range s.Rules {
		sort.SliceStable(s.Rules[d], func(i, j int) bool { return s.Rules[d][i].Position < s.Rules[d][j].Position })
	}
	for _, l := range cfg.Links {
		a, b := key(l.A, l.APort), key(l.B, l.BPort)
		if l.A == "" || l.APort == "" || l.B == "" || l.BPort == "" {
			continue
		}
		if _, ok := s.Links[a]; ok {
			continue
		}
		note := "ручная связь из netmap-config.json"
		if l.Note != "" {
			note += " (" + l.Note + ")"
		}
		s.Links[a] = Port{l.B, l.BPort}
		s.Links[b] = Port{l.A, l.APort}
		s.LinkSource[a] = note
		s.LinkSource[b] = note
	}
	return s, nil
}
