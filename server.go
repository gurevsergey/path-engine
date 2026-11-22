package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var colors = map[string]string{"Observed": "#56A64B", "Inferred": "#3274D9", "Unknown": "#8E8E8E", "Conflicting": "#E02F44"}
var dirColors = map[string]string{"forward": "#3274D9", "reverse": "#FF9830"}

func hopRows(p *Path, d string) []object {
	out := []object{}
	for i, h := range p.Hops {
		out = append(out, object{"direction": d, "seq": i + 1, "device": or(h.Device, "?"), "kind": or(h.Kind, "-"), "site": or(h.Site, "-"), "in_if": or(h.InIf, "-"), "out_if": or(h.OutIf, "-"), "vlan": or(h.VLAN, "-"), "table": or(h.Table, "-"), "route": or(h.Route, "-"), "tunnel": or(h.Tunnel, "-"), "encrypted": or(h.Encrypted, "-"), "status": or(h.Status, "Unknown"), "ip": or(h.IP, "-"), "attach": or(h.Attach, "-"), "evidence": strings.Join(h.Evidence, " | ")})
		if h.Verdict != "" {
			out[len(out)-1]["verdict"], out[len(out)-1]["flow"] = h.Verdict, h.Flow
		}
	}
	return out
}
func (s *State) observedText(f, r *Path) string {
	if !s.nf.enabled() {
		return "нет: NetFlow не подключён, все участки — вывод по таблицам"
	}
	parts := []string{}
	for i, p := range []*Path{f, r} {
		name := []string{"туда", "обратно"}[i]
		obs := []string{}
		for _, h := range p.Hops {
			if h.Status == "Observed" {
				obs = append(obs, h.Device)
			}
		}
		if len(obs) > 0 {
			parts = append(parts, name+": подтверждено на "+strings.Join(obs, ", "))
		} else if p.NetFlow != nil && len(p.NetFlow.Exporters) > 0 {
			parts = append(parts, name+": на "+strings.Join(p.NetFlow.Exporters, ", ")+" потоков за период нет")
		} else {
			parts = append(parts, name+": на пути нет экспортёров NetFlow")
		}
	}
	return strings.Join(parts, "; ")
}
func graph(paths map[string]*Path, want string) []object {
	nodes := map[string]object{}
	nodeOrder := []string{}
	edges := []object{}
	for _, d := range []string{"forward", "reverse"} {
		p := paths[d]
		if p == nil {
			continue
		}
		var prev *Hop
		prevID := ""
		for i, h := range p.Hops {
			id := or(h.Device, "?")
			if h.Kind == "unknown" {
				id = fmt.Sprintf("%s:%d:%s", d, i, id)
			}
			st := or(h.Status, "Unknown")
			n := nodes[id]
			if n == nil {
				subtitle := or(h.Kind, "-")
				if h.Site != "" {
					subtitle += " · " + h.Site
				}
				n = object{"id": id, "title": or(h.Device, "?"), "subtitle": subtitle, "mainstat": or(h.IP, h.Table), "secondarystat": st, "color": or(colors[st], "#8E8E8E"), "detail__status": st, "detail__evidence": strings.Join(h.Evidence, " | "), "detail__attach": or(h.Attach, "-")}
				nodes[id] = n
				nodeOrder = append(nodeOrder, id)
			} else if statusRank[st] > statusRank[str(n["secondarystat"])] {
				n["secondarystat"] = st
				n["color"] = colors[st]
				n["detail__status"] = st
			}
			if prev != nil {
				extra := []string{}
				if prev.Tunnel != "" {
					enc := "без шифрования"
					if prev.Encrypted == "да" {
						enc = "IPsec"
					}
					extra = append(extra, prev.Tunnel+" ("+enc+")")
				}
				if present(h.VLAN) {
					extra = append(extra, "VLAN "+h.VLAN)
				}
				edges = append(edges, object{"id": fmt.Sprintf("%s:%d", d, i), "source": prevID, "target": id, "mainstat": or(prev.OutIf, "-") + " → " + or(h.InIf, "-"), "secondarystat": or(strings.Join(extra, ", "), d), "color": dirColors[d], "detail__direction": d, "detail__status": st})
			}
			prev, prevID = h, id
		}
	}
	if want == "edges" {
		return edges
	}
	out := []object{}
	for _, id := range nodeOrder {
		out = append(out, nodes[id])
	}
	return out
}
func (s *State) hostIPs(ctx context.Context, params map[string]string) (*Snapshot, []string, error) {
	snap, err := s.snap(ctx, nowSeconds())
	if err != nil {
		return nil, nil, err
	}
	ips := []string{}
	if ep := resolveEndpoint(snap, or(params["host"], params["src"])); ep != nil {
		ips = append(ips, ep.IP.String())
	}
	return snap, ips, nil
}
func (s *State) api(ctx context.Context, path string, params map[string]string) (any, error) {
	switch path {
	case "/api/path", "/api/summary", "/api/graph/nodes", "/api/graph/edges":
		if path == "/api/summary" {
			params["mode"] = "both"
		}
		snap, paths, err := s.pathsFor(ctx, params)
		if err != nil {
			return nil, err
		}
		if path == "/api/path" {
			rows := []object{}
			for _, d := range []string{"forward", "reverse"} {
				if p := paths[d]; p != nil {
					rows = append(rows, hopRows(p, d)...)
					for _, w := range p.Warnings {
						rows = append(rows, object{"direction": d, "seq": 0, "device": "⚠", "kind": "warning", "status": "Unknown", "evidence": w})
					}
				}
			}
			return rows, nil
		}
		if path == "/api/summary" {
			f, r := paths["forward"], paths["reverse"]
			cmp := compare(f, r)
			return []object{{"forward_status": f.Status, "reverse_status": r.Status, "forward_coverage": coverage(f), "reverse_coverage": coverage(r), "symmetric": cmp.Symmetric, "detail": cmp.Detail, "forward_routers": or(strings.Join(l3Devices(f), " → "), "-"), "reverse_routers": or(strings.Join(l3Devices(r), " → "), "-"), "observed": s.observedText(f, r), "snapshot_time": time.UnixMilli(int64(snap.At * 1000)).UTC().Format("2006-01-02 15:04:05 UTC")}}, nil
		}
		return graph(paths, strings.TrimPrefix(path, "/api/graph/")), nil
	case "/api/audit":
		findings := []Finding{}
		if params["time"] != "" {
			at, err := paramFloat(params, "time", nowSeconds())
			if err != nil {
				return nil, err
			}
			snap, err := s.snap(ctx, at)
			if err != nil {
				return nil, err
			}
			findings, _ = runAudit(snap, s.cfg)
		} else {
			s.mu.RLock()
			findings = append(findings, s.findings...)
			s.mu.RUnlock()
		}
		sort.SliceStable(findings, func(i, j int) bool {
			a, b := findings[i], findings[j]
			if (a.Accepted == "") != (b.Accepted == "") {
				return a.Accepted == ""
			}
			if a.Severity != b.Severity {
				return a.Severity == "warning"
			}
			if a.Check != b.Check {
				return a.Check < b.Check
			}
			return a.Device < b.Device
		})
		if params["group"] == "1" {
			return groupFindings(findings), nil
		}
		return findings, nil
	case "/api/watch":
		// Пары под наблюдением одной строкой: маршрутизаторы туда и обратно,
		// достоверность L3 (без пробелов L2), число пробелов L2, симметрия.
		pairs := []PairResult{}
		if params["time"] != "" {
			at, err := paramFloat(params, "time", nowSeconds())
			if err != nil {
				return nil, err
			}
			snap, err := s.snap(ctx, at)
			if err != nil {
				return nil, err
			}
			_, pairs = runAudit(snap, s.cfg)
		} else {
			s.mu.RLock()
			pairs = append(pairs, s.pairs...)
			s.mu.RUnlock()
		}
		rows := []object{}
		for _, p := range pairs {
			w := Watch{}
			for _, x := range s.cfg.Watch {
				if x.Name == p.Pair {
					w = x
				}
			}
			routers := func(path *Path) string {
				return or(strings.Join(l3Devices(path), " → "), "-")
			}
			rows = append(rows, object{"pair": p.Pair, "src": w.Src, "dst": w.Dst,
				"forward_routers": routers(p.Forward), "reverse_routers": routers(p.Reverse),
				"l3_forward": l3Status(p.Forward), "l3_reverse": l3Status(p.Reverse),
				"l2_gaps": l2Gaps(p.Forward) + l2Gaps(p.Reverse), "symmetric": or(p.Compare.Symmetric, "Unknown"),
				"detail": p.Compare.Detail})
		}
		return rows, nil
	case "/api/flows/top", "/api/flows/conversations", "/api/flows/timeline", "/api/flows/pair":
		if !s.nf.enabled() {
			return nil, fmt.Errorf("NetFlow не подключён (не заданы NETFLOW_OS_URL, NETFLOW_OS_USER, NETFLOW_OS_PASSWORD)")
		}
		from, to, err := window(params)
		if err != nil {
			return nil, err
		}
		if path == "/api/flows/pair" {
			at, err := paramFloat(params, "time", nowSeconds())
			if err != nil {
				return nil, err
			}
			snap, err := s.snap(ctx, at)
			if err != nil {
				return nil, err
			}
			a, b := resolveEndpoint(snap, params["src"]), resolveEndpoint(snap, params["dst"])
			rows := []object{}
			if a == nil || b == nil {
				return rows, nil
			}
			for i, pair := range [][2]*Endpoint{{a, b}, {b, a}} {
				flows, err := s.nf.pair(ctx, pair[0].IP, pair[1].IP, from, to, params["proto"], params["dport"])
				if err != nil {
					return nil, err
				}
				for _, f := range flows {
					data, _ := json.Marshal(f)
					var row object
					_ = json.Unmarshal(data, &row)
					row["direction"] = []string{"forward", "reverse"}[i]
					rows = append(rows, row)
				}
			}
			return rows, nil
		}
		snap, ips, err := s.hostIPs(ctx, params)
		if err != nil {
			return nil, err
		}
		if path == "/api/flows/timeline" {
			return s.nf.timeline(ctx, ips, from, to)
		}
		size := 50
		if params["size"] != "" {
			size, err = strconv.Atoi(params["size"])
			if err != nil || size < 0 {
				return nil, fmt.Errorf("invalid size")
			}
		}
		if path == "/api/flows/conversations" {
			return s.nf.conversations(ctx, ips, from, to, size)
		}
		rows, err := s.nf.topPeers(ctx, ips, from, to, size)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			ip := parseIP(str(r["peer"]))
			name := "-"
			if owner, ok := snap.Owner[ip]; ok {
				name = owner.Device
			}
			r["peer_name"] = name
		}
		return rows, nil
	}
	return nil, fmt.Errorf("not found")
}

var apiRoutes = map[string]bool{"/api/path": true, "/api/summary": true, "/api/graph/nodes": true, "/api/graph/edges": true, "/api/audit": true, "/api/watch": true, "/api/flows/top": true, "/api/flows/conversations": true, "/api/flows/timeline": true, "/api/flows/pair": true}

func (s *State) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := 200
		defer func() { log.Printf("%s %s %s -> %d", r.RemoteAddr, r.Method, r.URL.String(), code) }()
		if r.Method != http.MethodGet {
			code = 405
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", code)
			return
		}
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ok"))
			return
		}
		if r.URL.Path == "/metrics" {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write([]byte(s.metrics()))
			return
		}
		params := map[string]string{}
		for k, v := range r.URL.Query() {
			for _, val := range v {
				if val != "" {
					params[k] = val
				}
			}
			if (k == "time" || k == "from") && params[k] == "now" {
				delete(params, k)
			}
		}
		var result any
		var err error
		if !apiRoutes[r.URL.Path] {
			code = 404
			result = object{"error": "not found"}
		} else {
			result, err = s.api(r.Context(), r.URL.Path, params)
			if err != nil {
				code = 500
				result = object{"error": err.Error()}
				log.Printf("%s: %v", r.URL.Path, err)
			}
		}
		body, err := json.Marshal(result)
		if err != nil {
			code = 500
			body = []byte(`{"error":"JSON encoding failed"}`)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(code)
		_, _ = w.Write(body)
	})
}
