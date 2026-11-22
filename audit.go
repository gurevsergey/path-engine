package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var private = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

func finding(check, severity, dev, obj, detail, evidence string) Finding {
	return Finding{Check: check, Severity: severity, Device: dev, Object: obj, Detail: detail, Evidence: evidence}
}

// routeText — маршрут для людей: шлюз, интерфейс, distance, комментарий.
func routeText(r Route) string {
	gw := r.Gateway
	if !present(gw) {
		gw = "без шлюза"
	}
	out := "via " + gw
	if present(r.OutIf) && !strings.Contains(gw, r.OutIf) {
		out += " (" + r.OutIf + ")"
	}
	out += fmt.Sprintf(", d=%d", r.Distance)
	if present(r.Comment) {
		out += " «" + r.Comment + "»"
	}
	return out
}

// whyInactive — почему RouterOS не использует маршрут, насколько это видно
// по собранным данным.
func whyInactive(s *Snapshot, dev string, r Route) string {
	if t, ok := s.Tunnels[key(dev, r.OutIf)]; ok && !t.Running {
		return "туннель " + r.OutIf + " не running"
	}
	if !present(r.Gateway) {
		return "у маршрута нет шлюза или его интерфейс не активен"
	}
	return "шлюз недоступен: нет в подключённых сетях или не проходит check-gateway"
}
func routeChecks(s *Snapshot, sensitive []Sensitive) []Finding {
	out := []Finding{}
	for _, dev := range sortedKeys(s.Routes) {
		groups := map[string][]Route{}
		for _, r := range s.Routes[dev] {
			k := key(r.Table, r.Dst.String())
			groups[k] = append(groups[k], r)
		}
		for _, k := range sortedKeys(groups) {
			rs := groups[k]
			table, dst := rs[0].Table, rs[0].Dst
			active, inactive, statics := []Route{}, []Route{}, []Route{}
			var st, osp *Route
			for _, r := range rs {
				if r.Active {
					active = append(active, r)
					if st == nil && r.Protocol == "static" {
						v := r
						st = &v
					}
				} else {
					inactive = append(inactive, r)
					if osp == nil && r.Protocol == "ospf" {
						v := r
						osp = &v
					}
					if r.Protocol == "static" {
						statics = append(statics, r)
					}
				}
			}
			obj := fmt.Sprintf("%s [%s]", dst, table)
			if st != nil && osp != nil && st.OutIf != osp.OutIf {
				out = append(out, finding("static_over_dynamic", "warning", dev, obj, fmt.Sprintf("статика via %s (%s) перекрывает OSPF via %s (%s): трафик идёт не тем путём, который выбрал бы OSPF, и при отказе статика держится, пока шлюз отвечает", st.Gateway, st.OutIf, osp.Gateway, osp.OutIf), fmt.Sprintf("static d=%d %s; ospf d=%d", st.Distance, st.Comment, osp.Distance)))
			}
			if len(active) > 0 && len(statics) > 0 {
				a := active[0]
				for _, r := range active {
					if r.Distance < a.Distance {
						a = r
					}
				}
				var b *Route
				for _, r := range statics {
					if r.Distance < a.Distance && (b == nil || r.Distance < b.Distance) {
						v := r
						b = &v
					}
				}
				if b != nil && (a.Protocol == "static" || a.Protocol == "ospf") {
					out = append(out, finding("backup_route_active", "warning", dev, obj, fmt.Sprintf("работает via %s (d=%d), основной via %s (d=%d) неактивен", a.Gateway, a.Distance, b.Gateway, b.Distance), "основной: "+routeText(*b)+" — "+whyInactive(s, dev, *b)+"; работает: "+routeText(a)))
				}
			}
			if len(active) == 0 && len(statics) > 0 {
				r := statics[0]
				gw := r.Gateway
				if !present(gw) {
					gw = "без шлюза"
					if present(r.OutIf) {
						gw = r.OutIf
					}
				}
				ev := routeText(r) + " — " + whyInactive(s, dev, r)
				fallback := fallbackRoute(s, dev, table, dst)
				if fallback != "" {
					ev += "; вместо него трафик идёт по " + fallback
				} else if table != "main" {
					ev += "; это таблица политики маршрутизации: помеченный в неё трафик не найдёт маршрута"
				}
				if name := sensitiveName(sensitive, dst); name != "" {
					out = append(out, finding("sensitive_route_down", "warning", dev, obj, fmt.Sprintf("маршрут к защищаемой сети «%s» via %s неактивен: трафик к ней идёт %s", name, gw, or(fallback, "в никуда (других маршрутов нет)")), ev))
					continue
				}
				out = append(out, finding("dead_route", "info", dev, obj, fmt.Sprintf("статический маршрут via %s неактивен, других к этой сети нет", gw), ev))
			}
			for _, r := range active {
				if t, ok := s.Tunnels[key(dev, r.OutIf)]; ok && !t.Running {
					out = append(out, finding("tunnel_down", "warning", dev, obj, fmt.Sprintf("активный маршрут смотрит в туннель %s, он не running", r.OutIf), ""))
				}
			}
		}
	}
	for _, dev := range sortedKeys(s.Routes) {
		for _, sensitive := range sensitive {
			n := sensitive.Prefix.Masked()
			probe := n.Addr()
			if n.Bits() < probe.BitLen() {
				probe = probe.Next()
			}
			best, plen := lookup(s, dev, "main", probe)
			if len(best) == 0 || plen == 0 {
				continue
			}
			r := best[0]
			t := tunnelOf(s, dev, r.OutIf)
			if t != nil && !t.Encrypted {
				out = append(out, finding("unencrypted_sensitive", "warning", dev, fmt.Sprintf("%s → %s", n, r.OutIf), fmt.Sprintf("трафик к «%s» идёт по %s %s без шифрования", or(sensitive.Name, n.String()), t.Type, r.OutIf), fmt.Sprintf("route %s via %s; %s → %s", r.Dst, r.Gateway, t.Local, t.Remote)))
			}
		}
	}
	return out
}
func policyChecks(s *Snapshot) []Finding {
	out := []Finding{}
	for _, dev := range sortedKeys(s.Mangle) {
		for _, r := range s.Mangle[dev] {
			if r.Action != "mark-routing" || r.Chain != "prerouting" {
				continue
			}
			skip := false
			for _, k := range []string{"dst-address", "dst-address-list", "dst-address-type", "connection-mark"} {
				if _, ok := r.Match[k]; ok {
					skip = true
				}
			}
			if skip {
				continue
			}
			for _, rt := range s.Routes[dev] {
				if rt.Table != r.NewMark || rt.Dst.Bits() <= 0 {
					continue
				}
				for _, p := range private {
					if rt.Dst.Bits() >= p.Bits() && p.Contains(rt.Dst.Addr()) {
						skip = true
					}
				}
			}
			if skip {
				continue
			}
			ev := []string{}
			for _, k := range sortedKeys(r.Match) {
				ev = append(ev, k+"="+r.Match[k])
			}
			out = append(out, finding("policy_without_lan", "info", dev, fmt.Sprintf("mangle #%d → %s", r.Position, r.NewMark), "помеченный трафик во внутренние сети уйдёт по маршруту по умолчанию этой таблицы: в правиле нет ограничения по назначению, в таблице — маршрутов к локальным сетям", or(strings.Join(ev, ";"), "без условий")))
		}
	}
	return out
}
func attachments(s *Snapshot, mac string) []attachment {
	out := []attachment{}
	for _, k := range sortedKeys(s.FDB) {
		v := splitKey(k)
		e := s.FDB[k]
		if len(v) != 2 || v[1] != mac || len(e) == 0 {
			continue
		}
		if _, ok := s.Links[key(v[0], e[0].Port)]; !ok && !isUplink(s, v[0], e[0].Port, "") {
			out = append(out, attachment{v[0], e[0].Port, e[0].VLAN, false})
		}
	}
	return out
}

// fallbackRoute — каким активным маршрутом в той же таблице пойдёт трафик
// к сети, если её собственный маршрут неактивен ("" — никаким).
func fallbackRoute(s *Snapshot, dev, table string, dst netip.Prefix) string {
	probe := dst.Masked().Addr()
	if dst.Bits() < probe.BitLen() {
		probe = probe.Next()
	}
	best, _ := lookup(s, dev, table, probe)
	if len(best) == 0 {
		return ""
	}
	r := best[0]
	text := fmt.Sprintf("%s %s", r.Dst, routeText(r))
	if gw := parseIP(r.Gateway); gw.IsValid() && isPublic(gw) {
		text += " (шлюз провайдера: в интернет)"
	}
	return text
}

// sensitiveName — имя защищаемой сети, пересекающейся с prefix, или "".
func sensitiveName(list []Sensitive, prefix netip.Prefix) string {
	for _, x := range list {
		if x.Prefix.Overlaps(prefix) && prefix.Bits() > 0 {
			return or(x.Name, x.Prefix.String())
		}
	}
	return ""
}

func runAudit(s *Snapshot, cfg Config) ([]Finding, []PairResult) {
	out := routeChecks(s, cfg.Sensitive)
	out = append(out, policyChecks(s)...)
	results := []PairResult{}
	for _, w := range cfg.Watch {
		f, r := trace(s, w.Src, w.Dst, "", ""), trace(s, w.Dst, w.Src, "", "")
		cmp := compare(f, r)
		results = append(results, PairResult{w.Name, f, r, cmp})
		if cmp.Symmetric == "нет" {
			out = append(out, finding("asymmetric", "warning", "-", w.Name, fmt.Sprintf("%s ↔ %s: путь туда и обратно разный", w.Src, w.Dst), cmp.Detail))
		}
		endsMap := map[string]bool{}
		for _, p := range []*Path{f, r} {
			for _, role := range []string{"source", "destination"} {
				endsMap[endpointSite(s, p, role)] = true
			}
		}
		ends := sortedKeys(endsMap)
		for i, p := range []*Path{f, r} {
			direction := []string{"туда", "обратно"}[i]
			for _, v := range transitSites(s, p, ends, cfg.CoreSites) {
				layer := "L3"
				for _, h := range p.Hops {
					if h.Device == v.Device && h.Kind == "switch" {
						layer = "L2 (растянутая VLAN)"
					}
				}
				out = append(out, finding("transit_site", "warning", v.Device, w.Name, fmt.Sprintf("%s ↔ %s (%s): транзит через площадку %s, %s", w.Src, w.Dst, direction, v.Iface, layer), "концы: "+strings.Join(ends, ", ")))
			}
		}
	}
	uniq := []Finding{}
	seen := map[string]bool{}
	for _, f := range out {
		k := key(f.Check, f.Device, f.Object, f.Detail)
		if !seen[k] {
			seen[k] = true
			if f.Severity == "info" && slices.Contains(cfg.QuietDevices, f.Device) {
				continue
			}
			f.Accepted = acceptedReason(cfg.Accepted, f, s.At)
			uniq = append(uniq, f)
		}
	}
	return uniq, results
}

// acceptedReason — причина принятия находки или "" (правило не подошло или истекло).
func acceptedReason(rules []Accepted, f Finding, at float64) string {
	day := time.Unix(int64(at), 0).In(time.FixedZone("MSK", 3*3600)).Format("2006-01-02")
	for _, a := range rules {
		if a.Check != f.Check || (a.Device != "" && a.Device != f.Device) || !strings.Contains(f.Object, a.Object) {
			continue
		}
		if a.Until != "" && at > 0 && day > a.Until {
			continue
		}
		reason := or(a.Reason, "принято")
		if a.Until != "" {
			reason += " (до " + a.Until + ")"
		}
		return reason
	}
	return ""
}

// groupFindings объединяет одинаковые находки по разным объектам
// (несколько хостов с одной и той же причиной) в одну строку реестра.
func groupFindings(in []Finding) []Finding {
	type agg struct {
		f       Finding
		objects []string
	}
	order := []string{}
	groups := map[string]*agg{}
	for _, f := range in {
		k := key(f.Check, f.Severity, f.Device, f.Detail, f.Evidence, f.Accepted)
		if g, ok := groups[k]; ok {
			g.objects = append(g.objects, f.Object)
			continue
		}
		groups[k] = &agg{f, []string{f.Object}}
		order = append(order, k)
	}
	out := []Finding{}
	for _, k := range order {
		g := groups[k]
		if len(g.objects) > 1 {
			g.f.Object = fmt.Sprintf("%d объектов: %s", len(g.objects), strings.Join(g.objects, ", "))
		}
		out = append(out, g.f)
	}
	return out
}
