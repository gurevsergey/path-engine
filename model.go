package main

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Snapshots are immutable after loading and may be shared by concurrent requests.
type Route struct {
	Table    string       `json:"table"`
	Dst      netip.Prefix `json:"dst"`
	Gateway  string       `json:"gateway"`
	OutIf    string       `json:"out_if"`
	Distance int          `json:"distance"`
	Protocol string       `json:"protocol"`
	Active   bool         `json:"active"`
	ECMP     bool         `json:"ecmp"`
	Comment  string       `json:"comment"`
	Count    int          `json:"count"`
	// ImmediateGW — сосед, в который RouterOS разрешил рекурсивный шлюз
	// (gateway 1.0.0.1 → immediate-gw 10.201.164.1%VL.0555).
	ImmediateGW string `json:"immediate_gw,omitempty"`
}
type Address struct {
	Prefix netip.Prefix `json:"prefix"`
	Iface  string       `json:"iface"`
}
type Port struct {
	Device string `json:"device"`
	Iface  string `json:"iface"`
}
type FDBEntry struct {
	Port string `json:"port"`
	VLAN string `json:"vlan"`
}
type Tunnel struct {
	Type    string `json:"type"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	IPsec   bool   `json:"ipsec"`
	Running bool   `json:"running"`
}
type TunnelView struct {
	Name, Type, Local, Remote, Why string
	Encrypted, Running             bool
}
type Mangle struct {
	Position    int               `json:"position"`
	ID          string            `json:"id"`
	Chain       string            `json:"chain"`
	Action      string            `json:"action"`
	NewMark     string            `json:"new_mark"`
	Passthrough bool              `json:"passthrough"`
	Match       map[string]string `json:"match"`
	Comment     string            `json:"comment"`
}
type RoutingRule struct {
	Position    int    `json:"position"`
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Interface   string `json:"interface"`
	RoutingMark string `json:"routing_mark"`
	Table       string `json:"table"`
	Action      string `json:"action"`
}
type Site struct {
	Match string `yaml:"match" json:"match"`
	Site  string `yaml:"site" json:"site"`
	rx    *regexp.Regexp
}
type Gateway struct {
	Subnet  netip.Prefix `yaml:"subnet" json:"subnet"`
	Gateway netip.Addr   `yaml:"gateway" json:"gateway"`
}
type Link struct {
	A     string `json:"a"`
	APort string `json:"a_port"`
	B     string `json:"b"`
	BPort string `json:"b_port"`
	Note  string `json:"note"`
}
type Sensitive struct {
	Prefix netip.Prefix `yaml:"prefix" json:"prefix"`
	Name   string       `yaml:"name" json:"name"`
}

// External — сеть за неопрашиваемым устройством (партнёр, чужая площадка):
// путь к ней заканчивается на последнем нашем роутере, обратный начинается
// там же.
type External struct {
	Prefix netip.Prefix `yaml:"prefix" json:"prefix"`
	Name   string       `yaml:"name" json:"name"`
}
type Watch struct {
	Name string `yaml:"name" json:"name"`
	Src  string `yaml:"src" json:"src"`
	Dst  string `yaml:"dst" json:"dst"`
}
type Config struct {
	Sites     []Site      `yaml:"sites" json:"sites"`
	CoreSites []string    `yaml:"core_sites" json:"core_sites"`
	Gateways  []Gateway   `yaml:"subnet_gateways" json:"subnet_gateways"`
	Sensitive []Sensitive `yaml:"sensitive" json:"sensitive"`
	External  []External  `yaml:"external_networks" json:"external_networks,omitempty"`
	Watch     []Watch     `yaml:"watch" json:"watch"`
	// Принятые находки: известные и осознанно оставленные. Находка остаётся
	// в реестре с пометкой и причиной, но не считается в предупреждениях.
	Accepted []Accepted `yaml:"accepted" json:"accepted,omitempty"`
	// Устройства, которые опрашиваются только ради расчёта путей (выведены
	// из мониторинга): их информационные находки не показываются,
	// предупреждения — показываются.
	QuietDevices []string `yaml:"quiet_devices" json:"quiet_devices,omitempty"`
	Links        []Link   `yaml:"-" json:"-"`
}
type Snapshot struct {
	At            float64                    `json:"at"`
	Sites         []Site                     `json:"sites"`
	Warnings      []string                   `json:"warnings"`
	Routes        map[string][]Route         `json:"routes"`
	Addresses     map[string][]Address       `json:"addresses"`
	Owner         map[netip.Addr]Port        `json:"owner"`
	Tunnels       map[string]Tunnel          `json:"tunnels"`
	IPsecPeers    map[string]bool            `json:"ipsec_peers"`
	Mangle        map[string][]Mangle        `json:"mangle"`
	Firewall      map[string][]FwRule        `json:"firewall,omitempty"` // key(dev, table)
	FwCollected   map[string]bool            `json:"fw_collected,omitempty"`
	AddrLists     map[string][]netip.Prefix  `json:"addr_lists"`
	PartialLists  map[string]bool            `json:"partial_addr_lists,omitempty"`
	IfaceLists    map[string]map[string]bool `json:"iface_lists"`
	Rules         map[string][]RoutingRule   `json:"rules"`
	Collected     map[string]bool            `json:"collected"`
	BGPDevices    map[string]bool            `json:"bgp_devices"`
	FDB           map[string][]FDBEntry      `json:"fdb"`
	PortMACs      map[string]int             `json:"port_macs"`
	PortNeighbors map[string]map[string]bool `json:"port_neighbors"`
	Links         map[string]Port            `json:"links"`
	LinkSource    map[string]string          `json:"link_source"`
	Gateways      []Gateway                  `json:"subnet_gateways"`
	External      []External                 `json:"external_networks,omitempty"`
	ARP           map[netip.Addr]string      `json:"arp"`
	FDBDevices    map[string]bool            `json:"fdb_devices"`
}

func newSnapshot(at float64, sites []Site) *Snapshot {
	return &Snapshot{At: at, Sites: sites, Warnings: []string{}, Routes: map[string][]Route{}, Addresses: map[string][]Address{}, Owner: map[netip.Addr]Port{}, Tunnels: map[string]Tunnel{}, IPsecPeers: map[string]bool{}, Mangle: map[string][]Mangle{}, Firewall: map[string][]FwRule{}, FwCollected: map[string]bool{}, AddrLists: map[string][]netip.Prefix{}, PartialLists: map[string]bool{}, IfaceLists: map[string]map[string]bool{}, Rules: map[string][]RoutingRule{}, Collected: map[string]bool{}, BGPDevices: map[string]bool{}, FDB: map[string][]FDBEntry{}, PortMACs: map[string]int{}, PortNeighbors: map[string]map[string]bool{}, Links: map[string]Port{}, LinkSource: map[string]string{}, ARP: map[netip.Addr]string{}, FDBDevices: map[string]bool{}}
}
func key(parts ...string) string { return strings.Join(parts, "\x1f") }
func splitKey(k string) []string { return strings.Split(k, "\x1f") }
func (s *Snapshot) site(dev string) string {
	for _, v := range s.Sites {
		if v.rx != nil && v.rx.MatchString(dev) {
			return v.Site
		}
	}
	return "?"
}
func compileSites(sites []Site) error {
	for i := range sites {
		r, e := regexp.Compile(sites[i].Match)
		if e != nil {
			return e
		}
		sites[i].rx = r
	}
	return nil
}
func parseIP(s string) netip.Addr { a, _ := netip.ParseAddr(strings.SplitN(s, "%", 2)[0]); return a }
func parseNet(s string) netip.Prefix {
	if !strings.Contains(s, "/") {
		a := parseIP(s)
		if a.IsValid() {
			return netip.PrefixFrom(a, a.BitLen())
		}
		return netip.Prefix{}
	}
	p, _ := netip.ParsePrefix(s)
	return p.Masked()
}
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
func present(s string) bool { return s != "" && s != "-" }
func yes(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

type Endpoint struct {
	IP   netip.Addr
	MAC  string
	Name string // доменное имя, если адрес получен через DNS
}
type Hop struct {
	Device      string   `json:"device"`
	Kind        string   `json:"kind"`
	Role        string   `json:"role,omitempty"`
	IP          string   `json:"ip,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	InIf        string   `json:"in_if,omitempty"`
	OutIf       string   `json:"out_if,omitempty"`
	VLAN        string   `json:"vlan,omitempty"`
	Table       string   `json:"table,omitempty"`
	Route       string   `json:"route,omitempty"`
	Tunnel      string   `json:"tunnel,omitempty"`
	Encrypted   string   `json:"encrypted,omitempty"`
	Site        string   `json:"site,omitempty"`
	Status      string   `json:"status"`
	Evidence    []string `json:"evidence"`
	Attach      string   `json:"attach,omitempty"`
	ObservedAlt string   `json:"observed_alt,omitempty"`
	// Прохождение firewall на этом роутере; пусто, если правила не собраны.
	Flow    []FlowStep `json:"flow,omitempty"`
	Verdict string     `json:"verdict,omitempty"`
}
type Path struct {
	Src      string       `json:"src"`
	Dst      string       `json:"dst"`
	Hops     []*Hop       `json:"hops"`
	Warnings []string     `json:"warnings"`
	Status   string       `json:"status"`
	NetFlow  *FlowSummary `json:"netflow,omitempty"`
}
type FlowSummary struct {
	Flows     int64    `json:"flows"`
	Bytes     int64    `json:"bytes"`
	Exporters []string `json:"exporters_on_path"`
}
type Comparison struct {
	Symmetric string `json:"symmetric"`
	Detail    string `json:"detail"`
}
type Finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Device   string `json:"device"`
	Object   string `json:"object"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	Accepted string `json:"accepted,omitempty"` // причина, если находка принята
}

// Accepted — правило принятия находки: check и device совпадают точно
// (пустой device — любое устройство), object — подстрока (пусто — любой).
// Until (ГГГГ-ММ-ДД, МСК) — по какую дату включительно действует.
type Accepted struct {
	Check  string `yaml:"check" json:"check"`
	Device string `yaml:"device" json:"device"`
	Object string `yaml:"object" json:"object"`
	Reason string `yaml:"reason" json:"reason"`
	Until  string `yaml:"until" json:"until"`
}
type PairResult struct {
	Pair    string     `json:"pair"`
	Forward *Path      `json:"forward"`
	Reverse *Path      `json:"reverse"`
	Compare Comparison `json:"compare"`
}

var statusRank = map[string]int{"Observed": 0, "Inferred": 1, "Unknown": 2, "Conflicting": 3}

func worst(statuses ...string) string {
	result := "Unknown"
	rank := -1
	for _, s := range statuses {
		r, ok := statusRank[s]
		if !ok {
			r = 2
		}
		if r > rank {
			result = s
			rank = r
		}
	}
	return result
}
func restatus(p *Path) {
	st := []string{}
	for _, h := range p.Hops {
		st = append(st, h.Status)
	}
	if p.Status == "Conflicting" {
		for _, w := range p.Warnings {
			if strings.Contains(w, "расходятся") {
				st = append(st, "Conflicting")
			}
		}
	}
	p.Status = worst(st...)
}
