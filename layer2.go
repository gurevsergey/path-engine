package main

import (
	"fmt"
	"net/netip"
	"strings"
)

const maxHops = 20
const uplinkMACs = 300

func isUplink(s *Snapshot, dev, port, itself string) bool {
	for n := range s.PortNeighbors[key(dev, port)] {
		if itself == "" || !strings.HasPrefix(strings.ToLower(n), strings.ToLower(itself)) {
			return true
		}
	}
	return s.PortMACs[key(dev, port)] >= uplinkMACs
}

type attachment struct {
	Device, Port, VLAN string
	SamePort           bool
}

func (a *attachment) text() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s VLAN %s", a.Device, a.Port, a.VLAN)
}

type l2hop struct {
	Device, InIf, OutIf, VLAN string
	Notes                     []string
}
type l2result struct {
	Hops         []l2hop
	Attach       *attachment
	Status, Note string
}

func routerAttach(s *Snapshot, router string, ip netip.Addr) (Port, string) {
	mac := s.ARP[ip]
	if mac == "" {
		return Port{}, ""
	}
	points := []Port{}
	for _, k := range sortedKeys(s.FDB) {
		parts := splitKey(k)
		entries := s.FDB[k]
		if len(parts) != 2 || parts[1] != mac || len(entries) == 0 {
			continue
		}
		dev, port := parts[0], entries[0].Port
		if _, ok := s.Links[key(dev, port)]; !ok && !isUplink(s, dev, port, router) {
			points = append(points, Port{dev, port})
		}
	}
	if len(points) == 1 {
		return points[0], mac
	}
	return Port{}, ""
}
func fdbPorts(entries []FDBEntry) []string {
	m := map[string]bool{}
	for _, e := range entries {
		m[e.Port] = true
	}
	return sortedKeys(m)
}
func quotedList(v []string) string {
	q := make([]string, len(v))
	for i, s := range v {
		q[i] = "'" + s + "'"
	}
	return "[" + strings.Join(q, ", ") + "]"
}
func l2From(s *Snapshot, dev, inPort, mac string) l2result {
	result := l2result{Hops: []l2hop{}, Status: "Unknown"}
	seen := map[Port]bool{}
	for range maxHops {
		entries := s.FDB[key(dev, mac)]
		if len(entries) == 0 {
			result.Note = fmt.Sprintf("%s: MAC %s нет в FDB", dev, or(mac, "None"))
			return result
		}
		ports := fdbPorts(entries)
		if len(ports) > 1 {
			result.Status = "Conflicting"
			result.Note = fmt.Sprintf("%s: MAC %s сразу на портах %s", dev, mac, quotedList(ports))
			return result
		}
		port, vid := entries[0].Port, entries[0].VLAN
		if port == inPort {
			result.Attach = &attachment{dev, port, vid, true}
			result.Status = "Inferred"
			return result
		}
		result.Hops = append(result.Hops, l2hop{dev, inPort, port, vid, []string{}})
		peer, ok := s.Links[key(dev, port)]
		if !ok {
			if isUplink(s, dev, port, "") {
				result.Note = fmt.Sprintf("%s:%s — аплинк без известной связи", dev, port)
				return result
			}
			result.Attach = &attachment{dev, port, vid, false}
			result.Status = "Inferred"
			return result
		}
		if seen[peer] {
			result.Status = "Conflicting"
			result.Note = fmt.Sprintf("петля в FDB на ('%s', '%s')", peer.Device, peer.Iface)
			return result
		}
		seen[peer] = true
		dev, inPort = peer.Device, peer.Iface
	}
	result.Note = "слишком длинная L2-цепочка"
	return result
}
func l2Walk(s *Snapshot, router, mac string, routerIP netip.Addr) l2result {
	result := l2result{Hops: []l2hop{}, Status: "Unknown"}
	if mac == "" {
		result.Note = "MAC хоста неизвестен"
		return result
	}
	dev, inPort := router, ""
	seen := map[Port]bool{}
	startNotes := []string{}
	if len(s.FDB[key(router, mac)]) == 0 && !s.FDBDevices[router] {
		start, rmac := routerAttach(s, router, routerIP)
		if start.Device != "" {
			dev, inPort = start.Device, start.Iface
			startNotes = append(startNotes, fmt.Sprintf("%s подключён к %s:%s (его MAC %s по ARP и FDB)", router, dev, inPort, rmac))
			router = ""
		}
	}
	for range maxHops {
		entries := s.FDB[key(dev, mac)]
		if len(entries) == 0 {
			if dev == router {
				result.Note = fmt.Sprintf("%s: MAC %s нет в FDB (устройство без FDB или чужая сеть)", router, mac)
			} else {
				result.Note = fmt.Sprintf("%s: MAC %s нет в FDB (запись устарела или не собрана)", dev, mac)
			}
			return result
		}
		port, vid := entries[0].Port, entries[0].VLAN
		ports := fdbPorts(entries)
		if len(ports) > 1 {
			result.Status = "Conflicting"
			result.Note = fmt.Sprintf("%s: MAC %s сразу на портах %s", dev, mac, quotedList(ports))
			return result
		}
		if dev != router {
			result.Hops = append(result.Hops, l2hop{dev, inPort, port, vid, startNotes})
			startNotes = nil
		}
		peer, ok := s.Links[key(dev, port)]
		if ok && s.LinkSource[key(dev, port)] != "" && len(result.Hops) > 0 {
			i := len(result.Hops) - 1
			result.Hops[i].Notes = append(result.Hops[i].Notes, fmt.Sprintf("связь %s:%s ↔ %s:%s — %s", dev, port, peer.Device, peer.Iface, s.LinkSource[key(dev, port)]))
		}
		if !ok {
			if isUplink(s, dev, port, "") {
				nb := sortedKeys(s.PortNeighbors[key(dev, port)])
				extra := fmt.Sprintf(" (%d MAC)", s.PortMACs[key(dev, port)])
				if len(nb) > 0 {
					extra = " (за ним видны " + strings.Join(nb[:min(3, len(nb))], ", ") + ")"
				}
				result.Note = fmt.Sprintf("%s:%s — аплинк без LLDP-связи и без записи в netmap-config.json%s: куда дальше — неизвестно", dev, port, extra)
				return result
			}
			result.Attach = &attachment{dev, port, vid, false}
			result.Status = "Inferred"
			return result
		}
		if seen[peer] {
			result.Status = "Conflicting"
			result.Note = fmt.Sprintf("петля в FDB на ('%s', '%s')", peer.Device, peer.Iface)
			return result
		}
		seen[peer] = true
		dev, inPort = peer.Device, peer.Iface
	}
	result.Note = "слишком длинная L2-цепочка"
	return result
}
