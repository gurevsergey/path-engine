package main

import (
	"net/netip"
	"strings"
	"testing"
)

// R1 (шлюз хоста 10.0.0.5) → R2 → туннель к неопрашиваемому роутеру, за
// которым внешняя сеть 192.168.34.0/23.
func externalSnapshot() *Snapshot {
	s := newSnapshot(0, nil)
	addr := func(dev, iface, cidr string) {
		p := netip.MustParsePrefix(cidr)
		s.Addresses[dev] = append(s.Addresses[dev], Address{p, iface})
		s.Owner[p.Addr()] = Port{dev, iface}
	}
	route := func(dev, dst, gw, out, proto string) {
		s.Routes[dev] = append(s.Routes[dev], Route{Table: "main", Dst: netip.MustParsePrefix(dst), Gateway: gw, OutIf: out, Protocol: proto, Active: true})
	}
	s.Collected["R1"], s.Collected["R2"] = true, true
	addr("R1", "lan", "10.0.0.1/24")
	addr("R1", "core", "10.1.0.1/30")
	addr("R2", "core", "10.1.0.2/30")
	addr("R2", "tun-ext", "10.9.0.2/30")
	route("R1", "10.0.0.0/24", "lan", "lan", "connect")
	route("R1", "192.168.34.0/23", "10.1.0.2", "core", "static")
	route("R2", "192.168.34.0/23", "tun-ext", "tun-ext", "static")
	route("R2", "10.0.0.0/24", "10.1.0.1", "core", "static")
	s.External = []External{{netip.MustParsePrefix("192.168.34.0/23"), "Partner"}}
	return s
}

func TestExternalNetworkEndsForwardAndStartsReverse(t *testing.T) {
	s := externalSnapshot()
	f := trace(s, "10.0.0.5", "192.168.35.206", "", "")
	last := f.Hops[len(f.Hops)-1]
	if got := strings.Join(l3Devices(f), ","); got != "R1,R2" || !l3Complete(f) {
		t.Fatalf("forward routers %q, complete %v", got, l3Complete(f))
	}
	if last.Role != "destination" || last.Status != "Inferred" || !strings.Contains(last.Evidence[0], "внешняя сеть «Partner»") || !strings.Contains(last.Evidence[0], "R2:tun-ext") {
		t.Fatalf("forward last hop %+v", last)
	}
	r := traceDir(s, "192.168.35.206", "10.0.0.5", "", "", true)
	if got := strings.Join(l3Devices(r), ","); got != "R2,R1" || !l3Complete(r) {
		t.Fatalf("reverse routers %q, complete %v", got, l3Complete(r))
	}
	if r.Hops[1].Device != "R2" || r.Hops[1].InIf != "tun-ext" || !strings.Contains(r.Hops[1].Evidence[0], "внешней сети") {
		t.Fatalf("reverse entry hop %+v", r.Hops[1])
	}
	if !strings.Contains(strings.Join(r.Hops[0].Evidence, "|"), "внешняя сеть «Partner»") {
		t.Fatalf("reverse source hop %+v", r.Hops[0])
	}
	if c := compare(f, r); c.Symmetric != "да" {
		t.Fatalf("compare %+v", c)
	}
}

func TestExternalNetworkNeedsDeclarationAndRoute(t *testing.T) {
	s := externalSnapshot()
	s.External = nil
	f := trace(s, "10.0.0.5", "192.168.35.206", "", "")
	if last := f.Hops[len(f.Hops)-1]; last.Kind != "unknown" || l3Complete(f) {
		t.Fatalf("undeclared network must stay unknown: %+v", last)
	}
	if r := trace(s, "192.168.35.206", "10.0.0.5", "", ""); len(l3Devices(r)) != 0 {
		t.Fatalf("undeclared source must have no entry: %v", l3Devices(r))
	}
	// Объявлена, но маршрута нет: обрыв остаётся обрывом.
	s = externalSnapshot()
	s.Routes["R2"] = s.Routes["R2"][1:]
	f = trace(s, "10.0.0.5", "192.168.35.206", "", "")
	if l3Complete(f) || f.Hops[len(f.Hops)-1].Status != "Unknown" {
		t.Fatalf("missing route must stay unknown: %+v", f.Hops[len(f.Hops)-1])
	}
	if r := trace(s, "192.168.35.206", "10.0.0.5", "", ""); len(l3Devices(r)) != 0 {
		t.Fatalf("no forward exit, so no reverse entry: %v", l3Devices(r))
	}
}

func TestExternalPairsDoNotRecurse(t *testing.T) {
	s := externalSnapshot()
	for _, pair := range [][2]string{{"192.168.34.1", "192.168.35.1"}, {"192.168.35.1", "8.8.8.8"}, {"8.8.8.8", "192.168.35.1"}} {
		if p := trace(s, pair[0], pair[1], "", ""); p == nil || len(p.Hops) == 0 {
			t.Fatalf("%v: no path returned", pair)
		}
	}
}

func TestPolledSubnetIsNotExternal(t *testing.T) {
	s := externalSnapshot()
	p := netip.MustParsePrefix("192.168.35.1/24")
	s.Addresses["R2"] = append(s.Addresses["R2"], Address{p, "lan75"})
	if externalNet(s, netip.MustParseAddr("192.168.35.206")) != nil {
		t.Fatal("subnet with a polled router must not be external")
	}
	if externalNet(s, netip.MustParseAddr("192.168.34.5")) == nil {
		t.Fatal("the rest of the prefix stays external")
	}
}
