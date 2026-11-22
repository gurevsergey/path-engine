package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func metricQuote(s string) string {
	return `"` + strings.NewReplacer("\\", "\\\\", "\n", "\\n", `"`, `\"`).Replace(s) + `"`
}
func metricHeader(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}
func metric(b *strings.Builder, name string, value float64, labels ...string) {
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteByte('=')
			b.WriteString(metricQuote(labels[i+1]))
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	b.WriteByte('\n')
}
func (s *State) metrics() string {
	s.mu.RLock()
	findings, pairs, last, lastError := s.findings, s.pairs, s.lastRefresh, s.lastError
	s.mu.RUnlock()
	var b strings.Builder
	metricHeader(&b, "path_audit_finding", "Non-optimal path finding")
	for _, f := range findings {
		detail := []rune(f.Detail)
		metric(&b, "path_audit_finding", 1, "check", f.Check, "severity", f.Severity, "device", f.Device, "object", f.Object, "detail", string(detail[:min(200, len(detail))]))
	}
	metricHeader(&b, "path_audit_accepted", "Finding accepted in config (known, deliberately left as is)")
	for _, f := range findings {
		if f.Accepted != "" {
			metric(&b, "path_audit_accepted", 1, "check", f.Check, "device", f.Device, "object", f.Object, "reason", f.Accepted)
		}
	}
	metricHeader(&b, "path_watch_l3_status", "Watched pair L3 (router) status without L2 gaps (1 for current)")
	for _, p := range pairs {
		metric(&b, "path_watch_l3_status", 1, "pair", p.Pair, "direction", "forward", "status", l3Status(p.Forward))
		metric(&b, "path_watch_l3_status", 1, "pair", p.Pair, "direction", "reverse", "status", l3Status(p.Reverse))
	}
	metricHeader(&b, "path_watch_l2_gaps", "Unknown L2 segments on the watched pair path")
	for _, p := range pairs {
		metric(&b, "path_watch_l2_gaps", float64(l2Gaps(p.Forward)), "pair", p.Pair, "direction", "forward")
		metric(&b, "path_watch_l2_gaps", float64(l2Gaps(p.Reverse)), "pair", p.Pair, "direction", "reverse")
	}
	metricHeader(&b, "path_watch_status", "Watched pair path status (1 for current)")
	for _, p := range pairs {
		metric(&b, "path_watch_status", 1, "pair", p.Pair, "direction", "forward", "status", or(p.Forward.Status, "Unknown"))
		metric(&b, "path_watch_status", 1, "pair", p.Pair, "direction", "reverse", "status", or(p.Reverse.Status, "Unknown"))
	}
	metricHeader(&b, "path_watch_asymmetric", "1 if forward and reverse differ, -1 unknown")
	for _, p := range pairs {
		v := -1.
		if p.Compare.Symmetric == "нет" {
			v = 1
		} else if p.Compare.Symmetric == "да" {
			v = 0
		}
		metric(&b, "path_watch_asymmetric", v, "pair", p.Pair)
	}
	metricHeader(&b, "path_watch_signature", "Hash of the router sequence; changes when path changes")
	for _, p := range pairs {
		for i, path := range []*Path{p.Forward, p.Reverse} {
			if !l3Complete(path) {
				continue
			}
			routers := strings.Join(l3Devices(path), " → ")
			sum := sha1.Sum([]byte(routers))
			metric(&b, "path_watch_signature", float64(binary.BigEndian.Uint32(sum[:4])), "pair", p.Pair, "direction", []string{"forward", "reverse"}[i], "routers", or(routers, "-"))
		}
	}
	metricHeader(&b, "path_engine_last_refresh_timestamp", "Last successful audit refresh")
	metric(&b, "path_engine_last_refresh_timestamp", last)
	metricHeader(&b, "path_engine_refresh_ok", "1 if the last refresh succeeded")
	v := 1.
	if lastError != "" {
		v = 0
	}
	metric(&b, "path_engine_refresh_ok", v)
	return b.String()
}

// l3Status — достоверность пути по роутерам без учёта пробелов L2:
// пробел L2 не делает рассчитанный маршрут неизвестным.
func l3Status(p *Path) string {
	if p == nil || !l3Complete(p) {
		return "Unknown"
	}
	st := []string{}
	for _, h := range p.Hops {
		if h.Kind == "router" {
			st = append(st, h.Status)
		}
	}
	if len(st) == 0 {
		// Один сегмент без роутеров: путь известен, если дошли до назначения.
		if n := len(p.Hops); n > 1 && p.Hops[n-1].Kind == "host" {
			return "Inferred"
		}
		return "Unknown"
	}
	return worst(st...)
}

func l2Gaps(p *Path) int {
	n := 0
	if p == nil {
		return 0
	}
	for _, h := range p.Hops {
		if h.Kind == "unknown" && strings.HasPrefix(h.Device, "L2") {
			n++
		}
	}
	return n
}
