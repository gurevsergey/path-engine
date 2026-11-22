package main

import (
	"net/netip"
	"sort"
	"strings"
)

// Прохождение пакета через firewall маршрутизатора (RouterOS packet flow):
// raw prerouting → dstnat → [выбор маршрута] → filter forward/input → srcnat.
// Правила вычисляются в трёх состояниях, как mangle: неизвестное условие
// даёт «может сработать», но решение принимает только сработавшее правило.

// FwRule — включённое правило filter/nat/raw (метрика firewall_rule_info).
type FwRule struct {
	Position int               `json:"position"`
	Chain    string            `json:"chain"`
	Action   string            `json:"action"`
	Target   string            `json:"target"`
	Match    map[string]string `json:"match"`
	Comment  string            `json:"comment"`
}

// FlowStep — правило, которое решает (или может решить) судьбу пакета на этапе.
type FlowStep struct {
	Stage    string `json:"stage"` // raw, dstnat, filter, srcnat
	Chain    string `json:"chain"`
	Position int    `json:"position"`
	Action   string `json:"action"`
	Comment  string `json:"comment,omitempty"`
	Certain  bool   `json:"certain"`
	From     string `json:"from,omitempty"` // адрес до NAT
	To       string `json:"to,omitempty"`   // адрес после NAT
}

var (
	filterTerminal = map[string]bool{"accept": true, "drop": true, "reject": true, "tarpit": true}
	natTerminal    = map[string]bool{"accept": true, "src-nat": true, "masquerade": true, "dst-nat": true, "redirect": true, "netmap": true, "same": true, "endpoint-independent-nat": true}
	rawTerminal    = map[string]bool{"accept": true, "drop": true}
	blocking       = map[string]bool{"drop": true, "reject": true, "tarpit": true}
)

const maxFwDepth = 8

func (s *Snapshot) firewallKnown(dev string) bool {
	return s.FwCollected[dev]
}

// evalChain обходит цепочку. decided — найдено терминальное правило, которое
// точно сработало; steps — оно и все терминальные «может сработать» до него.
func evalChain(s *Snapshot, dev, table, chain string, p Packet, terminal map[string]bool, maybe bool, depth int, stage string, steps *[]FlowStep) (*FwRule, bool) {
	if depth > maxFwDepth {
		return nil, false
	}
	for i := range s.Firewall[key(dev, table)] {
		r := &s.Firewall[key(dev, table)][i]
		if r.Chain != chain {
			continue
		}
		var conn *string
		if p.ConnKnown {
			c := p.ConnMark
			conn = &c
		}
		m := ruleMatches(s, dev, Mangle{Chain: r.Chain, Action: r.Action, Match: r.Match}, p, conn)
		if m == no {
			continue
		}
		certain := m == hit && !maybe
		switch {
		case r.Action == "jump":
			if rule, ok := evalChain(s, dev, table, r.Target, p, terminal, !certain, depth+1, stage, steps); ok {
				return rule, true
			}
		case r.Action == "return":
			if certain {
				return nil, false
			}
		case terminal[r.Action]:
			// «Может сработать» показываем, только если правило может что-то
			// изменить: заблокировать (filter/raw) или преобразовать адрес (nat).
			if !certain && r.Action == "accept" {
				continue
			}
			*steps = append(*steps, FlowStep{Stage: stage, Chain: r.Chain, Position: r.Position, Action: r.Action, Comment: fwComment(r.Comment), Certain: certain})
			if certain {
				return r, true
			}
		}
	}
	return nil, false
}

func fwComment(c string) string {
	if c == "-" {
		return ""
	}
	return c
}

// natAddr — первый адрес из to-addresses («a.b.c.d», «a-b», «a/24», «a:port»).
func natAddr(target string) netip.Addr {
	t, _, _ := strings.Cut(target, ":")
	t, _, _ = strings.Cut(t, "-")
	t, _, _ = strings.Cut(t, "/")
	return parseIP(t)
}

// flowResult — итог по роутеру.
type flowResult struct {
	steps   []FlowStep
	verdict string // accept, drop, unknown
}

func (f *flowResult) add(steps []FlowStep) { f.steps = append(f.steps, steps...) }

// verdictOf: точный блок → drop; до разрешения есть правила, которые могут
// заблокировать (зависят от протокола, порта и т. п.) → conditional; иначе accept.
func verdictOf(steps []FlowStep) string {
	maybeBlock := false
	for _, st := range steps {
		if st.Stage != "filter" && st.Stage != "raw" {
			continue
		}
		if blocking[st.Action] {
			if st.Certain {
				return "drop"
			}
			maybeBlock = true
		}
	}
	if maybeBlock {
		return "conditional"
	}
	return "accept"
}

// rawStage — raw prerouting (до connection tracking и mangle).
func rawStage(s *Snapshot, dev string, p Packet, f *flowResult) {
	steps := []FlowStep{}
	evalChain(s, dev, "raw", "prerouting", p, rawTerminal, false, 0, "raw", &steps)
	f.add(steps)
}

// dstNat — dstnat (после mangle prerouting). Если dst-nat точно сработал,
// меняет p.Dst и возвращает новый адрес назначения.
func dstNat(s *Snapshot, dev string, p *Packet, f *flowResult) netip.Addr {
	if p.State != "new" {
		return netip.Addr{}
	}
	steps := []FlowStep{}
	rule, ok := evalChain(s, dev, "nat", "dstnat", *p, natTerminal, false, 0, "dstnat", &steps)
	newDst := netip.Addr{}
	if ok && rule.Action != "accept" {
		switch rule.Action {
		case "redirect":
			newDst = ifaceIP(s, dev, p.InIf, netip.Addr{})
		default:
			newDst = natAddr(rule.Target)
		}
		if newDst.IsValid() && newDst != p.Dst {
			steps[len(steps)-1].From, steps[len(steps)-1].To = p.Dst.String(), newDst.String()
			p.NatState = "dstnat"
		} else {
			newDst = netip.Addr{}
		}
	}
	for i := range steps {
		if steps[i].To != "" || steps[i].Action == "accept" {
			continue
		}
		to := natAddr(findRule(s, dev, "nat", steps[i].Position).Target)
		if steps[i].Action == "redirect" {
			to = ifaceIP(s, dev, p.InIf, netip.Addr{})
		}
		if to.IsValid() {
			steps[i].From, steps[i].To = p.Dst.String(), to.String()
		}
	}
	f.add(steps)
	if newDst.IsValid() {
		p.Dst = newDst
	}
	return newDst
}

func findRule(s *Snapshot, dev, table string, pos int) FwRule {
	for _, r := range s.Firewall[key(dev, table)] {
		if r.Position == pos {
			return r
		}
	}
	return FwRule{}
}

// filterStage — filter forward (или input, если пакет адресован роутеру).
func filterStage(s *Snapshot, dev string, p Packet, local bool, f *flowResult) {
	chain := "forward"
	if local {
		chain = "input"
	}
	steps := []FlowStep{}
	evalChain(s, dev, "filter", chain, p, filterTerminal, false, 0, "filter", &steps)
	f.add(steps)
}

// srcNat — srcnat по выходному интерфейсу. Возвращает новый адрес источника,
// если src-nat/masquerade точно сработал.
func srcNat(s *Snapshot, dev string, p Packet, gw netip.Addr, f *flowResult) netip.Addr {
	if p.State != "new" {
		return netip.Addr{}
	}
	steps := []FlowStep{}
	rule, ok := evalChain(s, dev, "nat", "srcnat", p, natTerminal, false, 0, "srcnat", &steps)
	translate := func(r FwRule) netip.Addr {
		if r.Action == "masquerade" {
			if a := ifaceIP(s, dev, p.OutIf, gw); a.IsValid() {
				return a
			}
			return ifaceIP(s, dev, p.OutIf, netip.Addr{})
		}
		return natAddr(r.Target)
	}
	for i := range steps {
		if steps[i].Action == "accept" {
			continue
		}
		if a := translate(findRule(s, dev, "nat", steps[i].Position)); a.IsValid() {
			steps[i].From, steps[i].To = p.Src.String(), a.String()
		}
	}
	f.add(steps)
	if ok && rule.Action != "accept" {
		if a := translate(*rule); a.IsValid() && a != p.Src {
			return a
		}
	}
	return netip.Addr{}
}

func sortFirewall(s *Snapshot) {
	for k := range s.Firewall {
		sort.SliceStable(s.Firewall[k], func(i, j int) bool { return s.Firewall[k][i].Position < s.Firewall[k][j].Position })
	}
}
