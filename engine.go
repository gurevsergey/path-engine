package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

func resolveEndpoint(s *Snapshot, text string) *Endpoint {
	text = strings.TrimSpace(text)
	ip := parseIP(text)
	if !ip.IsValid() {
		// Не адрес — пробуем как доменное имя.
		if a := lookupHost(text); a.IsValid() {
			ep := resolveEndpoint(s, a.String())
			ep.Name = strings.ToLower(strings.TrimSuffix(text, "."))
			return ep
		}
		return nil
	}
	return &Endpoint{IP: ip, MAC: s.ARP[ip]}
}
func isHostIn(s *Snapshot, dev, iface string, n netip.Prefix) bool {
	for _, r := range s.Routes[dev] {
		if r.Active && r.Table == "main" && r.Dst.Bits() == 0 {
			gw := parseIP(r.Gateway)
			if r.OutIf == iface || (gw.IsValid() && n.Contains(gw)) {
				return true
			}
		}
	}
	return false
}
func firstRouter(s *Snapshot, ep *Endpoint) (Port, string, string) {
	if o, ok := s.Owner[ep.IP]; ok {
		return Port{o.Device, ""}, "Inferred", "источник — адрес самого устройства"
	}
	for _, g := range s.Gateways {
		if g.Subnet.Contains(ep.IP) {
			if o, ok := s.Owner[g.Gateway]; ok {
				return o, "Inferred", fmt.Sprintf("шлюз сети %s — %s (config.yml)", g.Subnet, g.Gateway)
			}
		}
	}
	type candidate struct {
		port Port
		net  netip.Prefix
	}
	cands := []candidate{}
	for _, dev := range sortedKeys(s.Addresses) {
		for _, a := range s.Addresses[dev] {
			if a.Prefix.Contains(ep.IP) && a.Prefix.Bits() < 32 && s.Collected[dev] && !isHostIn(s, dev, a.Iface, a.Prefix) {
				cands = append(cands, candidate{Port{dev, a.Iface}, a.Prefix.Masked()})
			}
		}
	}
	if len(cands) == 1 {
		return cands[0].port, "Inferred", fmt.Sprintf("единственный роутер в %s", cands[0].net)
	}
	if len(cands) == 0 {
		return Port{}, "Unknown", "не найден роутер в сети источника"
	}
	names := map[string]bool{}
	for _, c := range cands {
		names[c.port.Device] = true
	}
	return cands[0].port, "Conflicting", fmt.Sprintf("в сети источника несколько роутеров (%s), шлюз хоста неизвестен", strings.Join(sortedKeys(names), ", "))
}
func endpointHop(ep *Endpoint, role string) *Hop {
	return &Hop{Device: or(ep.Name, ep.IP.String()), Kind: "host", Role: role, IP: ep.IP.String(), MAC: or(ep.MAC, "-")}
}
func subnetOf(s *Snapshot, ip netip.Addr) netip.Prefix {
	var best netip.Prefix
	for _, dev := range sortedKeys(s.Addresses) {
		for _, a := range s.Addresses[dev] {
			if a.Prefix.Contains(ip) && a.Prefix.Bits() < 31 && (!best.IsValid() || a.Prefix.Bits() > best.Bits()) {
				best = a.Prefix.Masked()
			}
		}
	}
	return best
}
func switchHop(s *Snapshot, h l2hop, mac string, reverse bool) *Hop {
	in, out := h.InIf, h.OutIf
	if reverse {
		in, out = h.OutIf, or(h.InIf, "-")
	}
	ev := []string{fmt.Sprintf("FDB: MAC %s на %s:%s", or(mac, "None"), h.Device, h.OutIf)}
	ev = append(ev, h.Notes...)
	return &Hop{Device: h.Device, Kind: "switch", InIf: in, OutIf: out, VLAN: h.VLAN, Status: "Inferred", Site: s.site(h.Device), Evidence: ev}
}
func unknownHop(dev, status, note string) *Hop {
	return &Hop{Device: dev, Kind: "unknown", Status: status, Evidence: []string{note}}
}
func sameSegment(s *Snapshot, src, dst *Endpoint) []*Hop {
	net := subnetOf(s, src.IP)
	if !net.IsValid() || !net.Contains(dst.IP) {
		return nil
	}
	dh := endpointHop(dst, "destination")
	hops := []*Hop{}
	var start Port
	for _, k := range sortedKeys(s.FDB) {
		parts := splitKey(k)
		entries := s.FDB[k]
		if len(parts) != 2 || parts[1] != src.MAC || len(entries) == 0 {
			continue
		}
		if _, ok := s.Links[key(parts[0], entries[0].Port)]; !ok && !isUplink(s, parts[0], entries[0].Port, "") {
			start = Port{parts[0], entries[0].Port}
			break
		}
	}
	if start.Device == "" {
		hops = append(hops, unknownHop("L2 ?", "Unknown", fmt.Sprintf("та же подсеть %s, но точка подключения источника не найдена в FDB", net)))
	} else {
		l2 := l2From(s, start.Device, start.Iface, dst.MAC)
		for _, h := range l2.Hops {
			hops = append(hops, switchHop(s, h, dst.MAC, false))
		}
		if l2.Note != "" {
			hops = append(hops, unknownHop("L2 ?", l2.Status, l2.Note))
		}
		dh.Attach = l2.Attach.text()
	}
	dh.Status = "Inferred"
	dh.Evidence = []string{fmt.Sprintf("та же подсеть %s: без маршрутизации, только L2", net)}
	return append(hops, dh)
}
func trace(s *Snapshot, srcText, dstText, proto, dport string) *Path {
	return traceDir(s, srcText, dstText, proto, dport, false)
}

// traceDir: reply=true — путь ответных пакетов (обратное направление пары):
// firewall проверяется как established, NAT не применяется (его снимает conntrack).
func traceDir(s *Snapshot, srcText, dstText, proto, dport string, reply bool) *Path {
	p := traceHops(s, srcText, dstText, proto, dport, reply)
	for _, h := range p.Hops {
		if h.Role != "" && h.IP != "" && h.Device != h.IP && strings.Contains(h.Device, ".") && h.Kind == "host" {
			h.Evidence = append([]string{fmt.Sprintf("DNS: %s → %s (резолвер сервера мониторинга, на момент запроса)", h.Device, h.IP)}, h.Evidence...)
		}
	}
	return p
}
func traceHops(s *Snapshot, srcText, dstText, proto, dport string, reply bool) *Path {
	src, dst := resolveEndpoint(s, srcText), resolveEndpoint(s, dstText)
	p := &Path{Src: srcText, Dst: dstText, Hops: []*Hop{}, Warnings: append([]string{}, s.Warnings...)}
	if src == nil || dst == nil {
		p.Status = "Unknown"
		who := "адрес назначения"
		if src == nil {
			who = "источник"
		}
		p.Warnings = append(p.Warnings, "не найден "+who)
		return p
	}
	sh := endpointHop(src, "source")
	sh.Status = "Inferred"
	sh.Evidence = []string{fmt.Sprintf("%s (%s)", src.IP, or(src.MAC, "MAC ?"))}
	srcExt := externalNet(s, src.IP)
	if srcExt != nil {
		sh.Evidence = append(sh.Evidence, externalText(srcExt))
	}
	p.Hops = append(p.Hops, sh)
	if local := sameSegment(s, src, dst); len(local) > 0 {
		p.Hops = append(p.Hops, local...)
		restatus(p)
		return p
	}
	port, st, note := firstRouter(s, src)
	fromInternet := false
	// Только для пары «снаружи → наш хост»: для двух адресов снаружи (интернет
	// или внешняя сеть) встречный путь снова искал бы точку входа —
	// бесконечная рекурсия.
	if port.Device == "" && isOutside(s, src.IP) && !isOutside(s, dst.IP) {
		if e := internetEntry(s, dstText, srcText); e.Device != "" {
			port, st, fromInternet = e, "Inferred", true
			note = fmt.Sprintf("ответ из интернета приходит туда, где прямой путь вышел в интернет (NAT): %s:%s", e.Device, e.Iface)
			if srcExt != nil {
				note = fmt.Sprintf("пакет из внешней сети приходит туда, куда уходит наш маршрут к ней: %s:%s (маршруты внешней сети не собираются, путь принят симметричным)", e.Device, e.Iface)
			}
		}
	}
	dev, inIf := port.Device, port.Iface
	if _, owned := s.Owner[src.IP]; dev != "" && !owned && !fromInternet {
		l2 := l2Walk(s, dev, src.MAC, ifaceIP(s, dev, inIf, src.IP))
		sh.Attach = l2.Attach.text()
		if l2.Attach == nil && l2.Note != "" {
			p.Hops = append(p.Hops, unknownHop("L2 ?", l2.Status, l2.Note))
		}
		for i := len(l2.Hops) - 1; i >= 0; i-- {
			p.Hops = append(p.Hops, switchHop(s, l2.Hops[i], src.MAC, true))
		}
	}
	if dev == "" {
		p.Hops = append(p.Hops, unknownHop("?", st, note))
		restatus(p)
		return p
	}
	pkt := Packet{Src: src.IP, Dst: dst.IP, InIf: inIf, Proto: proto, DPort: dport, State: "new"}
	if reply {
		// Ответ: порт назначения запроса стал портом источника, порт
		// назначения ответа (эфемерный порт клиента) неизвестен.
		pkt.State, pkt.DPort = "established", ""
	}
	for step := 0; step < maxHops; step++ {
		h := &Hop{Device: dev, Kind: "router", InIf: or(inIf, "-"), Site: s.site(dev), Status: "Inferred", Evidence: []string{}}
		if step == 0 {
			h.Status = st
			h.Evidence = append(h.Evidence, note)
		}
		p.Hops = append(p.Hops, h)
		if !s.Collected[dev] {
			h.Status = "Unknown"
			h.Evidence = append(h.Evidence, dev+": маршруты не собираются")
			break
		}
		pkt.InIf, pkt.OutIf = inIf, ""
		fw := s.firewallKnown(dev)
		flow := &flowResult{}
		setFlow := func() {
			if fw {
				h.Flow, h.Verdict = flow.steps, verdictOf(flow.steps)
			}
		}
		// RouterOS: raw → mangle prerouting → dstnat → выбор маршрута.
		// Таблица mangle выбирается в прежнем режиме (без состояния соединения)
		// и по адресу назначения до dst-nat; маршрут ищется по адресу после него.
		sel := Packet{Src: pkt.Src, Dst: pkt.Dst, InIf: pkt.InIf, Proto: pkt.Proto, DPort: dport}
		table, tev, unsure, msteps := selectTableSteps(s, dev, sel)
		if fw {
			pkt.ConnMark, pkt.ConnKnown = connMarkOf(s, dev, sel)
			rawStage(s, dev, pkt, flow)
			flow.add(msteps)
			if nd := dstNat(s, dev, &pkt, flow); nd.IsValid() {
				h.Evidence = append(h.Evidence, fmt.Sprintf("dst-nat: назначение %s → %s, дальше путь к новому адресу", dst.IP, nd))
				if ep := resolveEndpoint(s, nd.String()); ep != nil {
					dst = ep
				}
			}
		}
		if s.Owner[dst.IP].Device == dev {
			h.Evidence = append(h.Evidence, "адрес назначения принадлежит этому устройству")
			if fw {
				filterStage(s, dev, pkt, true, flow)
			}
			setFlow()
			break
		}
		h.Table = table
		h.Evidence = append(h.Evidence, tev...)
		if len(unsure) > 0 {
			h.Status = worst(h.Status, "Conflicting")
			h.Evidence = append(h.Evidence, "может сработать (условия не вычислить): "+strings.Join(unsure[:min(3, len(unsure))], "; "))
		}
		routes, plen := lookup(s, dev, table, dst.IP)
		if len(routes) == 0 {
			h.Status = "Unknown"
			h.Evidence = append(h.Evidence, fmt.Sprintf("в таблице %s нет активного маршрута к %s", table, dst.IP))
			break
		}
		r := routes[0]
		h.OutIf = r.OutIf
		if fw {
			pkt.OutIf = r.OutIf
			filterStage(s, dev, pkt, false, flow)
			gw := parseIP(r.Gateway)
			if !gw.IsValid() {
				gw = dst.IP
			}
			if ns := srcNat(s, dev, pkt, gw, flow); ns.IsValid() {
				h.Evidence = append(h.Evidence, fmt.Sprintf("src-nat: источник %s → %s", pkt.Src, ns))
				pkt.Src = ns
			}
		}
		setFlow()
		h.Route = fmt.Sprintf("%s via %s (%s, d=%d)", r.Dst, r.Gateway, r.Protocol, r.Distance)
		if present(r.Comment) {
			h.Route += " «" + r.Comment + "»"
		}
		h.Evidence = append(h.Evidence, fmt.Sprintf("route %s в таблице %s", h.Route, table))
		alts := map[string]bool{}
		for _, r := range routes {
			alts[key(r.Gateway, r.OutIf)] = true
		}
		if len(alts) > 1 && r.Protocol != "connect" {
			h.Status = worst(h.Status, "Conflicting")
			a := []string{}
			for _, k := range sortedKeys(alts) {
				v := splitKey(k)
				a = append(a, v[0]+"/"+v[1])
			}
			h.Evidence = append(h.Evidence, "ECMP: "+strings.Join(a, ", "))
		}
		if s.BGPDevices[dev] && plen < 32 {
			h.Evidence = append(h.Evidence, "на устройстве есть BGP-маршруты (не выгружаются): более точный BGP-префикс может перекрыть этот маршрут")
			if plen == 0 {
				h.Status = worst(h.Status, "Unknown")
			}
		}
		if tun := tunnelOf(s, dev, r.OutIf); tun != nil {
			h.Tunnel = tun.Name
			h.Encrypted = yes(tun.Encrypted)
			enc := "без шифрования"
			if tun.Encrypted {
				enc = "шифруется"
			}
			ev := fmt.Sprintf("туннель %s %s → %s, %s (%s)", tun.Type, tun.Local, tun.Remote, enc, tun.Why)
			if !tun.Running {
				ev += ", НЕ running"
			}
			h.Evidence = append(h.Evidence, ev)
		}
		connected := r.Protocol == "connect"
		if !parseIP(r.Gateway).IsValid() {
			for _, a := range ifaceNet(s, dev, r.OutIf) {
				connected = connected || a.Contains(dst.IP)
			}
		}
		if connected {
			if o, ok := s.Owner[dst.IP]; ok && o.Device != dev {
				dev, inIf = o.Device, o.Iface
				continue
			}
			l2 := l2Walk(s, dev, dst.MAC, ifaceIP(s, dev, r.OutIf, dst.IP))
			for _, lh := range l2.Hops {
				p.Hops = append(p.Hops, switchHop(s, lh, dst.MAC, false))
			}
			if l2.Note != "" {
				p.Hops = append(p.Hops, unknownHop("L2 ?", l2.Status, l2.Note))
			}
			dh := endpointHop(dst, "destination")
			dh.Status = "Inferred"
			dh.Evidence = []string{fmt.Sprintf("подключённая сеть %s на %s:%s", r.Dst, dev, r.OutIf)}
			dh.Attach = l2.Attach.text()
			p.Hops = append(p.Hops, dh)
			break
		}
		next, how := nextDevice(s, dev, r)
		h.Evidence = append(h.Evidence, how)
		if next.Device == "" && isPublic(dst.IP) && (plen == 0 || s.IfaceLists[key(dev, "WAN")][r.OutIf]) {
			dh := endpointHop(dst, "destination")
			dh.Status = "Inferred"
			dh.Evidence = []string{fmt.Sprintf("выход в интернет: %s:%s, шлюз провайдера %s; дальше — чужая сеть", dev, r.OutIf, r.Gateway)}
			p.Hops = append(p.Hops, dh)
			break
		}
		if ext := externalNet(s, dst.IP); next.Device == "" && ext != nil {
			dh := endpointHop(dst, "destination")
			dh.Status = "Inferred"
			via := ""
			if r.Gateway != r.OutIf {
				via = ", шлюз " + r.Gateway
			}
			dh.Evidence = []string{fmt.Sprintf("%s: выход через %s:%s%s; дальше — чужая сеть", externalText(ext), dev, r.OutIf, via)}
			p.Hops = append(p.Hops, dh)
			break
		}
		if next.Device == "" {
			p.Hops = append(p.Hops, unknownHop("? "+r.Gateway, "Unknown", how))
			break
		}
		loop := false
		for _, prev := range p.Hops {
			loop = loop || (prev.Device == next.Device && prev.Kind == "router")
		}
		if loop {
			p.Hops = append(p.Hops, &Hop{Device: next.Device, Kind: "router", Status: "Conflicting", Evidence: []string{"петля маршрутизации: устройство уже было на пути"}})
			break
		}
		dev, inIf = next.Device, next.Iface
	}
	restatus(p)
	return p
}
func l3Devices(p *Path) []string {
	out := []string{}
	for _, h := range p.Hops {
		if h.Kind == "router" {
			out = append(out, h.Device)
		}
	}
	return out
}
func l3Complete(p *Path) bool {
	for _, h := range p.Hops {
		if h.Kind == "router" && h.Status == "Unknown" {
			return false
		}
		if h.Kind == "unknown" && strings.HasPrefix(h.Device, "? ") {
			return false
		}
	}
	return len(l3Devices(p)) > 0
}
func coverage(p *Path) string {
	if l3Complete(p) {
		for _, h := range p.Hops {
			if h.Status == "Unknown" {
				return "L3 полностью, L2 частично"
			}
		}
		return "полностью"
	}
	if len(l3Devices(p)) > 0 {
		return "неполный: L3 оборван"
	}
	return "не посчитан"
}
func compare(fwd, rev *Path) Comparison {
	a, b := l3Devices(fwd), l3Devices(rev)
	slices.Reverse(b)
	empty := len(a) == 0 && len(b) == 0
	if !(l3Complete(fwd) || empty) || !(l3Complete(rev) || empty) {
		return Comparison{"Unknown", "L3-путь в одну из сторон посчитан не целиком"}
	}
	if slices.Equal(a, b) {
		detail := "одинаковые роутеры"
		for _, h := range append(slices.Clone(fwd.Hops), rev.Hops...) {
			if h.Status == "Unknown" {
				detail += " (часть L2-участков неизвестна)"
				break
			}
		}
		return Comparison{"да", detail}
	}
	onlyF, onlyR := []string{}, []string{}
	for _, d := range a {
		if !slices.Contains(b, d) {
			onlyF = append(onlyF, d)
		}
	}
	for _, d := range b {
		if !slices.Contains(a, d) {
			onlyR = append(onlyR, d)
		}
	}
	slices.Reverse(b)
	detail := fmt.Sprintf("туда: %s; обратно: %s", strings.Join(a, " → "), strings.Join(b, " → "))
	if len(onlyF) > 0 {
		detail += "; только туда: " + strings.Join(onlyF, ", ")
	}
	if len(onlyR) > 0 {
		detail += "; только обратно: " + strings.Join(onlyR, ", ")
	}
	return Comparison{"нет", detail}
}
func endpointSite(s *Snapshot, p *Path, role string) string {
	for _, h := range p.Hops {
		if h.Role == role && h.Attach != "" {
			return s.site(strings.SplitN(h.Attach, ":", 2)[0])
		}
	}
	r := l3Devices(p)
	if len(r) == 0 {
		return "?"
	}
	if role == "source" {
		return s.site(r[0])
	}
	return s.site(r[len(r)-1])
}
func transitSites(s *Snapshot, p *Path, ends, core []string) []Port {
	out := []Port{}
	for _, h := range p.Hops {
		if h.Kind != "router" && h.Kind != "switch" {
			continue
		}
		site := s.site(h.Device)
		if !slices.Contains(ends, site) && !slices.Contains(core, site) && !strings.HasPrefix(site, "DC") && site != "?" {
			out = append(out, Port{h.Device, site})
		}
	}
	return out
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPublic — адрес из интернета: не частный, не служебный и не CGNAT.
func isPublic(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

// externalNet — внешняя сеть из config.yml (самый точный префикс), в которой
// лежит адрес. Если адрес из этой сети есть на опрашиваемом устройстве, сеть
// уже не внешняя: путь считается обычным порядком.
func externalNet(s *Snapshot, ip netip.Addr) *External {
	var best *External
	for i, e := range s.External {
		if e.Prefix.Contains(ip) && (best == nil || e.Prefix.Bits() > best.Prefix.Bits()) {
			best = &s.External[i]
		}
	}
	if best != nil && subnetOf(s, ip).IsValid() {
		return nil
	}
	return best
}
func externalText(e *External) string {
	return fmt.Sprintf("внешняя сеть «%s» (%s, config.yml)", e.Name, e.Prefix)
}

// isOutside — адрес за пределами опрашиваемой сети: интернет или внешняя сеть.
func isOutside(s *Snapshot, ip netip.Addr) bool {
	return isPublic(ip) || externalNet(s, ip) != nil
}

// internetEntry — роутер и интерфейс, через которые путь от host к public
// выходит в интернет или во внешнюю сеть. Туда же возвращается ответ.
func internetEntry(s *Snapshot, host, public string) Port {
	fwd := trace(s, host, public, "", "")
	if len(fwd.Hops) < 2 {
		return Port{}
	}
	last := fwd.Hops[len(fwd.Hops)-1]
	if last.Kind == "router" || last.Kind == "unknown" || last.Kind == "warning" {
		return Port{}
	}
	for i := len(fwd.Hops) - 2; i >= 0; i-- {
		if h := fwd.Hops[i]; h.Kind == "router" {
			if h.OutIf == "" || h.OutIf == "-" {
				return Port{}
			}
			return Port{h.Device, h.OutIf}
		}
	}
	return Port{}
}

var (
	dnsMu    sync.Mutex
	dnsCache = map[string]dnsEntry{}
)

type dnsEntry struct {
	ip netip.Addr
	at time.Time
}

// lookupHost резолвит доменное имя в IPv4 (кэш 60 с, таймаут 3 с).
// Строки без точки и с пробелами за имя не считаются.
func lookupHost(name string) netip.Addr {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if !strings.Contains(name, ".") || strings.ContainsAny(name, " /\\:@") || len(name) > 253 {
		return netip.Addr{}
	}
	dnsMu.Lock()
	if e, ok := dnsCache[name]; ok && time.Since(e.at) < time.Minute {
		dnsMu.Unlock()
		return e.ip
	}
	dnsMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := lookupNetIP(ctx, name)
	ip := netip.Addr{}
	if err == nil {
		for _, a := range ips {
			if a.Unmap().Is4() {
				ip = a.Unmap()
				break
			}
		}
	}
	dnsMu.Lock()
	if len(dnsCache) > 1024 {
		dnsCache = map[string]dnsEntry{}
	}
	dnsCache[name] = dnsEntry{ip, time.Now()}
	dnsMu.Unlock()
	return ip
}

// lookupNetIP подменяется в тестах.
var lookupNetIP = func(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
}
