package main

import (
	"net/netip"
	"testing"
)

func fwSnapshot() *Snapshot {
	s := newSnapshot(0, nil)
	s.FwCollected["R"] = true
	s.IfaceLists[key("R", "WAN")] = map[string]bool{"ether1": true}
	s.AddrLists[key("R", "admins")] = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	s.Addresses["R"] = []Address{{netip.MustParsePrefix("198.51.100.10/30"), "ether1"}, {netip.MustParsePrefix("10.0.0.1/24"), "lan"}}
	s.Owner[netip.MustParseAddr("198.51.100.10")] = Port{"R", "ether1"}
	s.Firewall[key("R", "filter")] = []FwRule{
		{Position: 0, Chain: "forward", Action: "accept", Match: map[string]string{"connection-state": "established,related"}, Comment: "est"},
		{Position: 1, Chain: "forward", Action: "jump", Target: "ADM", Match: map[string]string{"src-address-list": "admins"}},
		{Position: 2, Chain: "forward", Action: "drop", Match: map[string]string{"protocol": "tcp", "dst-port": "25"}, Comment: "smtp"},
		{Position: 3, Chain: "forward", Action: "drop", Match: map[string]string{"in-interface-list": "WAN", "connection-nat-state": "!dstnat"}, Comment: "wan"},
		{Position: 4, Chain: "ADM", Action: "return", Match: map[string]string{"dst-address": "10.9.9.9"}},
		{Position: 5, Chain: "ADM", Action: "accept", Match: map[string]string{}, Comment: "admins"},
	}
	s.Firewall[key("R", "nat")] = []FwRule{
		{Position: 0, Chain: "dstnat", Action: "dst-nat", Target: "10.0.0.50:443", Match: map[string]string{"dst-address": "198.51.100.10", "protocol": "tcp", "dst-port": "443"}},
		{Position: 1, Chain: "srcnat", Action: "masquerade", Target: "-", Match: map[string]string{"out-interface-list": "WAN"}},
	}
	return s
}

func fwRun(s *Snapshot, p Packet, local bool) (flowResult, netip.Addr, netip.Addr) {
	f := flowResult{}
	rawStage(s, "R", p, &f)
	nd := dstNat(s, "R", &p, &f)
	filterStage(s, "R", p, local, &f)
	ns := srcNat(s, "R", p, netip.MustParseAddr("198.51.100.9"), &f)
	f.verdict = verdictOf(f.steps)
	return f, nd, ns
}

func TestFirewallJumpAcceptAndMasquerade(t *testing.T) {
	s := fwSnapshot()
	p := Packet{Src: parseIP("10.0.0.5"), Dst: parseIP("1.1.1.1"), InIf: "lan", OutIf: "ether1", State: "new", Proto: "tcp", DPort: "443"}
	f, nd, ns := fwRun(s, p, false)
	if f.verdict != "accept" || nd.IsValid() || ns.String() != "198.51.100.10" {
		t.Fatalf("verdict %s dst %v src %v steps %+v", f.verdict, nd, ns, f.steps)
	}
	last := f.steps[len(f.steps)-1]
	if last.Stage != "srcnat" || last.From != "10.0.0.5" || last.To != "198.51.100.10" || !last.Certain {
		t.Fatalf("masquerade step %+v", last)
	}
}

func TestFirewallUnknownProtocolIsMaybeDrop(t *testing.T) {
	s := fwSnapshot()
	// Не админ, протокол «любой»: drop smtp может сработать, решения нет.
	p := Packet{Src: parseIP("10.0.1.5"), Dst: parseIP("1.1.1.1"), InIf: "lan", OutIf: "ether1", State: "new"}
	f, _, _ := fwRun(s, p, false)
	if f.verdict != "conditional" {
		t.Fatalf("verdict %s steps %+v", f.verdict, f.steps)
	}
}

func TestFirewallWanDropAndDstNat(t *testing.T) {
	s := fwSnapshot()
	p := Packet{Src: parseIP("8.8.8.8"), Dst: parseIP("198.51.100.10"), InIf: "ether1", OutIf: "lan", State: "new", Proto: "tcp", DPort: "443"}
	f, nd, _ := fwRun(s, p, false)
	if nd.String() != "10.0.0.50" || f.steps[0].Stage != "dstnat" || f.steps[0].To != "10.0.0.50" {
		t.Fatalf("dst-nat %v steps %+v", nd, f.steps)
	}
	if f.verdict != "accept" {
		t.Fatalf("dst-nat'ed connection must pass the !dstnat drop: %s %+v", f.verdict, f.steps)
	}
	p.DPort = "22"
	f, nd, _ = fwRun(s, p, false)
	if nd.IsValid() || f.verdict != "drop" {
		t.Fatalf("WAN ssh must be dropped: %s %+v", f.verdict, f.steps)
	}
}

func TestFirewallReplyIsEstablishedWithoutNat(t *testing.T) {
	s := fwSnapshot()
	p := Packet{Src: parseIP("8.8.8.8"), Dst: parseIP("10.0.1.5"), InIf: "ether1", OutIf: "lan", State: "established"}
	f, nd, ns := fwRun(s, p, false)
	if f.verdict != "accept" || nd.IsValid() || ns.IsValid() || f.steps[0].Comment != "est" {
		t.Fatalf("reply: %s %v %v %+v", f.verdict, nd, ns, f.steps)
	}
}

func TestMangleStepsReported(t *testing.T) {
	s := newSnapshot(0, nil)
	s.Mangle["R"] = []Mangle{
		{Position: 59, Chain: "prerouting", Action: "mark-connection", NewMark: "eu", Passthrough: true, Match: map[string]string{"connection-state": "new", "dst-address": "1.1.1.1"}, Comment: "To EU"},
		{Position: 60, Chain: "prerouting", Action: "mark-routing", NewMark: "via-eu", Match: map[string]string{"connection-mark": "eu"}},
	}
	table, _, _, steps := selectTableSteps(s, "R", Packet{Src: parseIP("10.0.0.5"), Dst: parseIP("1.1.1.1")})
	if table != "via-eu" || len(steps) != 2 || steps[0].To != "eu" || steps[1].To != "via-eu" || !steps[1].Certain || steps[0].Comment != "To EU" {
		t.Fatalf("table %s steps %+v", table, steps)
	}
}
