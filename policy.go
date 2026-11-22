package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// Three-valued matches keep unknown conditions from becoming asserted routes.
type match int

const (
	unknown match = iota
	no
	hit
)

func truth(b bool) match {
	if b {
		return hit
	}
	return no
}
func addrMatch(value string, ip netip.Addr) match {
	neg := strings.HasPrefix(value, "!")
	v := strings.TrimLeft(value, "!")
	if lo, hi, ok := strings.Cut(v, "-"); ok {
		a, b := parseIP(lo), parseIP(hi)
		inside := a.IsValid() && b.IsValid() && a.Compare(ip) <= 0 && ip.Compare(b) <= 0
		return truth(inside != neg)
	}
	n := parseNet(v)
	if !n.IsValid() {
		return unknown
	}
	return truth(n.Contains(ip) != neg)
}

type Packet struct {
	Src, Dst           netip.Addr
	InIf, Proto, DPort string
	// Для firewall: выходной интерфейс, состояние соединения (new —
	// первый пакет, established — ответ) и NAT-состояние. Пустой State —
	// старый режим выбора таблицы, где эти условия не вычисляются.
	OutIf, State, NatState string
	ConnMark               string // метка соединения из mangle (если известна)
	ConnKnown              bool
}

// connMarkOf — connection-mark, которую mangle prerouting ставит соединению.
func connMarkOf(s *Snapshot, dev string, p Packet) (string, bool) {
	mark := ""
	for _, r := range s.Mangle[dev] {
		if r.Chain != "prerouting" || r.Action != "mark-connection" {
			continue
		}
		switch ruleMatches(s, dev, r, p, &mark) {
		case hit:
			mark = r.NewMark
			if !r.Passthrough {
				return mark, true
			}
		case unknown:
			return "", false
		}
	}
	return mark, true
}

func ruleMatches(s *Snapshot, dev string, r Mangle, p Packet, conn *string) match {
	result := hit
	for k, v := range r.Match {
		neg := strings.HasPrefix(v, "!")
		name := strings.TrimLeft(v, "!")
		m := unknown
		switch k {
		case "src-address":
			m = addrMatch(v, p.Src)
		case "dst-address":
			m = addrMatch(v, p.Dst)
		case "src-address-list", "dst-address-list":
			entries, ok := s.AddrLists[key(dev, name)]
			if ok {
				ip := p.Src
				if k == "dst-address-list" {
					ip = p.Dst
				}
				found := false
				for _, n := range entries {
					found = found || n.Contains(ip)
				}
				// A known member is decisive even in a truncated list.
				// Absence is only decisive when the list is complete.
				if found || !s.PartialLists[key(dev, name)] {
					m = truth(found != neg)
				}
			}
		case "in-interface", "in-interface-list":
			if p.InIf != "" {
				found := p.InIf == name
				if k == "in-interface-list" {
					found = s.IfaceLists[key(dev, name)][p.InIf]
				}
				m = truth(found != neg)
			}
		case "connection-mark":
			if conn != nil {
				m = truth((*conn == name) != neg)
			}
		case "connection-state":
			// mark-connection с connection-state=new метит всё соединение по его
			// первому пакету, поэтому для пути соединения условие решено.
			// У mark-routing метка легла бы только на первый пакет — остаётся unknown.
			if p.State != "" {
				found := false
				for _, st := range strings.Split(name, ",") {
					found = found || st == p.State
				}
				m = truth(found != neg)
			} else if r.Action == "mark-connection" {
				found := false
				for _, st := range strings.Split(name, ",") {
					found = found || st == "new"
				}
				m = truth(found != neg)
			}
		case "connection-nat-state":
			if p.State != "" {
				found := false
				for _, st := range strings.Split(name, ",") {
					found = found || (st != "" && st == p.NatState)
				}
				m = truth(found != neg)
			}
		case "out-interface", "out-interface-list":
			if p.OutIf != "" {
				found := p.OutIf == name
				if k == "out-interface-list" {
					found = s.IfaceLists[key(dev, name)][p.OutIf]
				}
				m = truth(found != neg)
			}
		case "dst-address-type", "src-address-type":
			ip := p.Dst
			if k == "src-address-type" {
				ip = p.Src
			}
			if p.State != "" && (name == "local" || name == "unicast") {
				found := s.Owner[ip].Device == dev
				if name == "unicast" {
					found = ip.IsGlobalUnicast() || ip.IsPrivate()
				}
				m = truth(found != neg)
			}
		case "port":
			// port = src или dst; известен только dst-порт.
			if p.State != "" && p.DPort != "" {
				for _, port := range strings.Split(name, ",") {
					if port == p.DPort && !neg {
						m = hit
					}
				}
			}
		case "routing-mark":
			m = no
		case "protocol":
			if p.Proto != "" {
				m = truth((p.Proto == name) != neg)
			}
		case "dst-port", "src-port":
			if k == "dst-port" && p.DPort != "" {
				found := false
				for _, port := range strings.Split(name, ",") {
					if a, b, ok := strings.Cut(port, "-"); ok {
						if integer(a) <= integer(p.DPort) && integer(p.DPort) <= integer(b) {
							found = true
						}
					} else {
						found = found || port == p.DPort
					}
				}
				m = truth(found != neg)
			}
		}
		if m == no {
			return no
		}
		if m == unknown {
			result = unknown
		}
	}
	return result
}
func selectTable(s *Snapshot, dev string, p Packet) (string, []string, []string) {
	table, evidence, unsure, _ := selectTableSteps(s, dev, p)
	return table, evidence, unsure
}

// selectTableSteps — то же, плюс сработавшие и возможные правила mangle и
// /routing/rule в виде этапов прохождения пакета (stage mangle / routing-rule;
// To — новая метка или таблица).
func selectTableSteps(s *Snapshot, dev string, p Packet) (string, []string, []string, []FlowStep) {
	evidence, unsure := []string{}, []string{}
	steps := []FlowStep{}
	mark := ""
	conn := &mark
	table := ""
	for _, r := range s.Mangle[dev] {
		if r.Chain != "prerouting" {
			continue
		}
		m := ruleMatches(s, dev, r, p, conn)
		if m == no {
			continue
		}
		label := fmt.Sprintf("mangle #%d %s → %s", r.Position, r.Action, r.NewMark)
		if present(r.Comment) {
			label += " («" + r.Comment + "»)"
		}
		steps = append(steps, FlowStep{Stage: "mangle", Chain: r.Chain, Position: r.Position, Action: r.Action, Comment: fwComment(r.Comment), Certain: m == hit, To: r.NewMark})
		if m == unknown {
			unsure = append(unsure, label)
			if r.Action == "mark-connection" {
				conn = nil
			}
			continue
		}
		if r.Action == "mark-connection" {
			v := r.NewMark
			conn = &v
			evidence = append(evidence, label)
		} else if r.Action == "mark-routing" {
			table = r.NewMark
			evidence = append(evidence, label)
		}
		if !r.Passthrough {
			break
		}
	}
	if table == "" {
		for _, r := range s.Rules[dev] {
			ok := true
			if present(r.Src) {
				ok = ok && addrMatch(r.Src, p.Src) == hit
			}
			if present(r.Dst) {
				ok = ok && addrMatch(r.Dst, p.Dst) == hit
			}
			if present(r.Interface) {
				ok = ok && r.Interface == p.InIf
			}
			if present(r.RoutingMark) {
				ok = false
			}
			if ok && (r.Action == "lookup" || r.Action == "lookup-only-in-table") {
				table = r.Table
				evidence = append(evidence, fmt.Sprintf("routing rule #%d → %s", r.Position, table))
				steps = append(steps, FlowStep{Stage: "routing-rule", Chain: "routing", Position: r.Position, Action: r.Action, Certain: true, To: table})
				break
			}
		}
	}
	return or(table, "main"), evidence, unsure, steps
}
func lookup(s *Snapshot, dev, table string, dst netip.Addr) ([]Route, int) {
	best := []Route{}
	plen := -1
	for _, r := range s.Routes[dev] {
		if !r.Active || r.Table != table || !r.Dst.Contains(dst) {
			continue
		}
		if r.Dst.Bits() > plen {
			best = []Route{r}
			plen = r.Dst.Bits()
		} else if r.Dst.Bits() == plen {
			best = append(best, r)
		}
	}
	return best, plen
}
func ifaceNet(s *Snapshot, dev, iface string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, a := range s.Addresses[dev] {
		if a.Iface == iface {
			out = append(out, a.Prefix)
		}
	}
	return out
}
func ifaceIP(s *Snapshot, dev, iface string, near netip.Addr) netip.Addr {
	for _, a := range ifaceNet(s, dev, iface) {
		if !near.IsValid() || a.Contains(near) {
			return a.Addr()
		}
	}
	return netip.Addr{}
}
func nextDevice(s *Snapshot, dev string, r Route) (Port, string) {
	gw := parseIP(r.Gateway)
	if gw.IsValid() {
		if o, ok := s.Owner[gw]; ok {
			return o, fmt.Sprintf("шлюз %s — адрес %s:%s", gw, o.Device, o.Iface)
		}
		// Рекурсивный шлюз (проверка канала через 1.0.0.1 и т. п.): RouterOS
		// сам разрешил его в соседа — immediate-gw.
		ig, _, _ := strings.Cut(r.ImmediateGW, "%")
		if a := parseIP(ig); a.IsValid() && a != gw {
			if o, ok := s.Owner[a]; ok {
				return o, fmt.Sprintf("рекурсивный шлюз %s → immediate-gw %s — адрес %s:%s", gw, a, o.Device, o.Iface)
			}
			return Port{}, fmt.Sprintf("рекурсивный шлюз %s → immediate-gw %s не принадлежит ни одному опрашиваемому устройству", gw, a)
		}
		return Port{}, fmt.Sprintf("шлюз %s не принадлежит ни одному опрашиваемому устройству", gw)
	}
	for _, addr := range ifaceNet(s, dev, r.OutIf) {
		for _, other := range sortedKeys(s.Addresses) {
			if other == dev {
				continue
			}
			for _, a := range s.Addresses[other] {
				if addr.Contains(a.Prefix.Addr()) && a.Prefix.Addr() != addr.Addr() && addr.Bits() >= 29 {
					return Port{other, a.Iface}, fmt.Sprintf("сосед по %s (%s)", addr.Masked(), r.OutIf)
				}
			}
		}
	}
	return Port{}, fmt.Sprintf("за интерфейсом %s нет опрашиваемого устройства", r.OutIf)
}
func tunnelOf(s *Snapshot, dev, iface string) *TunnelView {
	t, ok := s.Tunnels[key(dev, iface)]
	if !ok {
		return nil
	}
	why := ""
	if t.Type == "wireguard" {
		why = "WireGuard"
	} else if t.IPsec {
		why = "ipsec-secret на туннеле"
	} else if s.IPsecPeers[key(dev, t.Local, t.Remote)] {
		why = fmt.Sprintf("IPsec-пир %s → %s established на %s", t.Local, t.Remote, dev)
	} else {
		for _, k := range sortedKeys(s.IPsecPeers) {
			p := splitKey(k)
			if len(p) == 3 && p[1] == t.Remote && p[2] == t.Local {
				why = "IPsec-пир established на " + p[0]
				break
			}
		}
	}
	return &TunnelView{iface, t.Type, t.Local, t.Remote, or(why, "ни ipsec-secret, ни установленного IPsec-пира"), why != "", t.Running}
}
