package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type object = map[string]any

func obj(v any) object { m, _ := v.(map[string]any); return m }
func arr(v any) []any  { a, _ := v.([]any); return a }
func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func buckets(m object, k string) []any      { return arr(obj(m[k])["buckets"]) }
func value(m object, k string) float64      { return num(obj(m[k])["value"]) }
func fieldTerm(field string, v any) object  { return object{"term": object{field: v}} }
func fieldTerms(field string, v any) object { return object{"terms": object{field: v}} }
func timeRange(from, to float64) object {
	return object{"range": object{"timestamp": object{"gte": int64(from * 1000), "lte": int64(to * 1000), "format": "epoch_millis"}}}
}
func sumAgg(field string) object { return object{"sum": object{"field": field}} }
func timeAgg(kind string) object { return object{kind: object{"field": "timestamp"}} }
func termsAgg(field string, size int) object {
	return object{"terms": object{"field": field, "size": size}}
}
func baseAggs() object {
	return object{"b": sumAgg("nf_bytes"), "p": sumAgg("nf_pkts"), "f": timeAgg("min"), "l": timeAgg("max")}
}
func compositeAgg(size int, fields ...string) object {
	sources := []any{}
	for i := 0; i < len(fields); i += 2 {
		sources = append(sources, object{fields[i]: object{"terms": object{"field": fields[i+1]}}})
	}
	return object{"composite": object{"size": size, "sources": sources}, "aggs": baseAggs()}
}
func searchBody(filters []any, aggs object) object {
	return object{"size": 0, "query": object{"bool": object{"filter": filters}}, "aggs": aggs}
}
func aggregation(r object, name string) object { return obj(obj(r["aggregations"])[name]) }
func bucketTime(b object, k string) string     { return str(obj(b[k])["value_as_string"]) }

type Flow struct {
	ObserverIP string `json:"observer_ip"`
	Observer   string `json:"observer"`
	InIf       string `json:"in_if"`
	OutIf      string `json:"out_if"`
	Bytes      int64  `json:"bytes"`
	Packets    int64  `json:"pkts"`
	Flows      int64  `json:"flows"`
	First      string `json:"first"`
	Last       string `json:"last"`
}
type NetFlow struct {
	URL, User, Password, Index string
	Client                     *http.Client
	mu                         sync.Mutex
	exporterAt                 time.Time
	exporterCache              map[string]string
}

func newNetFlow() *NetFlow {
	return &NetFlow{URL: strings.TrimRight(os.Getenv("NETFLOW_OS_URL"), "/"), User: os.Getenv("NETFLOW_OS_USER"), Password: os.Getenv("NETFLOW_OS_PASSWORD"), Index: or(os.Getenv("NETFLOW_INDEX"), "netflow_*"), Client: &http.Client{Timeout: 60 * time.Second}}
}
func (n *NetFlow) enabled() bool { return n != nil && n.URL != "" && n.User != "" && n.Password != "" }
func (n *NetFlow) search(ctx context.Context, body object) (object, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL+"/"+or(n.Index, "netflow_*")+"/_search", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(n.User, n.Password)
	req.Header.Set("Content-Type", "application/json")
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NetFlow: HTTP %d", resp.StatusCode)
	}
	var out object
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out)
	if err != nil {
		return nil, err
	}
	if out["error"] != nil {
		return nil, fmt.Errorf("NetFlow: %v", out["error"])
	}
	if obj(out["aggregations"]) == nil {
		return nil, fmt.Errorf("NetFlow: response has no aggregations")
	}
	return out, nil
}
func (n *NetFlow) exporters(ctx context.Context) (map[string]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if time.Since(n.exporterAt) < 600*time.Second && len(n.exporterCache) > 0 {
		return n.exporterCache, nil
	}
	now := float64(time.Now().UnixMilli()) / 1000
	agg := termsAgg("observer_ip", 50)
	agg["aggs"] = object{"n": termsAgg("observer_name", 1)}
	r, err := n.search(ctx, searchBody([]any{timeRange(now-3600, now)}, object{"o": agg}))
	if err != nil {
		return nil, err
	}
	cache := map[string]string{}
	for _, raw := range arr(aggregation(r, "o")["buckets"]) {
		b := obj(raw)
		names := buckets(b, "n")
		name := str(b["key"])
		if len(names) > 0 {
			name = str(obj(names[0])["key"])
		}
		ip := str(b["key_as_string"])
		if ip == "" {
			ip = str(b["key"])
		}
		cache[ip] = name
	}
	n.exporterCache = cache
	n.exporterAt = time.Now()
	return cache, nil
}
func (n *NetFlow) pair(ctx context.Context, src, dst netip.Addr, from, to float64, proto, dport string) ([]Flow, error) {
	flt := []any{timeRange(from, to)}
	for _, v := range []struct{ field, xlate, val string }{{"nf_src_address", "nf_xlate_src_addr_ipv4", src.String()}, {"nf_dst_address", "nf_xlate_dst_addr_ipv4", dst.String()}} {
		flt = append(flt, object{"bool": object{"should": []any{fieldTerm(v.field, v.val), fieldTerm(v.xlate, v.val)}, "minimum_should_match": 1}})
	}
	if proto != "" {
		flt = append(flt, fieldTerm("nf_proto_name", strings.ToUpper(proto)))
	}
	if dport != "" {
		flt = append(flt, fieldTerm("nf_dst_port", integer(dport)))
	}
	r, err := n.search(ctx, searchBody(flt, object{"g": compositeAgg(100, "obs", "observer_ip", "name", "observer_name", "in", "nf_in_if", "out", "nf_out_if")}))
	if err != nil {
		return nil, err
	}
	out := []Flow{}
	for _, raw := range arr(aggregation(r, "g")["buckets"]) {
		b := obj(raw)
		k := obj(b["key"])
		out = append(out, Flow{str(k["obs"]), str(k["name"]), str(k["in"]), str(k["out"]), int64(value(b, "b")), int64(value(b, "p")), int64(num(b["doc_count"])), bucketTime(b, "f"), bucketTime(b, "l")})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out, nil
}
func (n *NetFlow) side(ctx context.Context, ips []string, field, peer string, from, to float64, size int) (map[string]object, error) {
	aggs := baseAggs()
	aggs["proto"] = termsAgg("nf_proto_name", 3)
	port, iface := "nf_src_port", "nf_in_if"
	if field == "nf_src_address" {
		port, iface = "nf_dst_port", "nf_out_if"
	}
	aggs["port"] = termsAgg(port, 3)
	aggs["obs"] = termsAgg("observer_name", 3)
	aggs["ifs"] = termsAgg(iface, 3)
	agg := object{"terms": object{"field": peer, "size": size, "order": object{"b": "desc"}}, "aggs": aggs}
	r, err := n.search(ctx, searchBody([]any{timeRange(from, to), fieldTerms(field, ips)}, object{"peer": agg}))
	if err != nil {
		return nil, err
	}
	out := map[string]object{}
	for _, raw := range arr(aggregation(r, "peer")["buckets"]) {
		b := obj(raw)
		out[str(b["key"])] = b
	}
	return out, nil
}
func bucketKeys(b object, k string) []string {
	out := []string{}
	for _, v := range buckets(b, k) {
		out = append(out, str(obj(v)["key"]))
	}
	return out
}
func mergedKeys(a, b object, k string) string {
	m := map[string]bool{}
	for _, v := range append(bucketKeys(a, k), bucketKeys(b, k)...) {
		m[v] = true
	}
	return strings.Join(sortedKeys(m), ", ")
}
func (n *NetFlow) topPeers(ctx context.Context, ips []string, from, to float64, size int) ([]object, error) {
	sent, err := n.side(ctx, ips, "nf_src_address", "nf_dst_address", from, to, size)
	if err != nil {
		return nil, err
	}
	recv, err := n.side(ctx, ips, "nf_dst_address", "nf_src_address", from, to, size)
	if err != nil {
		return nil, err
	}
	peers := map[string]bool{}
	for k := range sent {
		peers[k] = true
	}
	for k := range recv {
		peers[k] = true
	}
	rows := []object{}
	secs := math.Max(to-from, 1)
	for _, peer := range sortedKeys(peers) {
		s, r := sent[peer], recv[peer]
		out, in := int64(value(s, "b")), int64(value(r, "b"))
		first, last := []string{}, []string{}
		for _, b := range []object{s, r} {
			if f := bucketTime(b, "f"); f != "" {
				first = append(first, f)
			}
			if l := bucketTime(b, "l"); l != "" {
				last = append(last, l)
			}
		}
		sort.Strings(first)
		sort.Strings(last)
		f, l := "", ""
		if len(first) > 0 {
			f = first[0]
		}
		if len(last) > 0 {
			l = last[len(last)-1]
		}
		ports := bucketKeys(s, "port")
		ports = ports[:min(3, len(ports))]
		rows = append(rows, object{"peer": peer, "bytes_out": out, "bytes_in": in, "bytes_total": out + in, "avg_bps_out": math.RoundToEven(float64(out) * 8 / secs), "avg_bps_in": math.RoundToEven(float64(in) * 8 / secs), "flows": int64(num(s["doc_count"]) + num(r["doc_count"])), "protocols": mergedKeys(s, r, "proto"), "ports": or(strings.Join(ports, ", "), "-"), "observers": mergedKeys(s, r, "obs"), "interfaces": mergedKeys(s, r, "ifs"), "first_seen": f, "last_seen": l})
	}
	sort.SliceStable(rows, func(i, j int) bool { return num(rows[i]["bytes_total"]) > num(rows[j]["bytes_total"]) })
	return rows[:min(size, len(rows))], nil
}
func (n *NetFlow) conversations(ctx context.Context, ips []string, from, to float64, size int) ([]object, error) {
	body := searchBody([]any{timeRange(from, to)}, object{"g": compositeAgg(1000, "src", "nf_src_address", "dst", "nf_dst_address", "proto", "nf_proto_name", "dport", "nf_dst_port")})
	q := obj(obj(body["query"])["bool"])
	q["should"] = []any{fieldTerms("nf_src_address", ips), fieldTerms("nf_dst_address", ips)}
	q["minimum_should_match"] = 1
	r, err := n.search(ctx, body)
	if err != nil {
		return nil, err
	}
	rows := []object{}
	for _, raw := range arr(aggregation(r, "g")["buckets"]) {
		b := obj(raw)
		k := obj(b["key"])
		rows = append(rows, object{"src": k["src"], "dst": k["dst"], "proto": k["proto"], "dport": k["dport"], "bytes": int64(value(b, "b")), "pkts": int64(value(b, "p")), "flows": int64(num(b["doc_count"])), "first_seen": bucketTime(b, "f"), "last_seen": bucketTime(b, "l")})
	}
	sort.SliceStable(rows, func(i, j int) bool { return num(rows[i]["bytes"]) > num(rows[j]["bytes"]) })
	return rows[:min(size, len(rows))], nil
}
func (n *NetFlow) timeline(ctx context.Context, ips []string, from, to float64) ([]object, error) {
	interval := math.Max(60, math.Floor((to-from)/120/60)*60)
	aggs := object{}
	for _, v := range []struct{ name, field string }{{"out", "nf_src_address"}, {"in", "nf_dst_address"}} {
		aggs[v.name] = object{"filter": fieldTerms(v.field, ips), "aggs": object{"b": sumAgg("nf_bytes")}}
	}
	body := searchBody([]any{timeRange(from, to)}, object{"t": object{"date_histogram": object{"field": "timestamp", "fixed_interval": fmt.Sprintf("%.0fs", interval), "min_doc_count": 0}, "aggs": aggs}})
	q := obj(obj(body["query"])["bool"])
	q["should"] = []any{fieldTerms("nf_src_address", ips), fieldTerms("nf_dst_address", ips)}
	q["minimum_should_match"] = 1
	r, err := n.search(ctx, body)
	if err != nil {
		return nil, err
	}
	rows := []object{}
	for _, raw := range arr(aggregation(r, "t")["buckets"]) {
		b := obj(raw)
		rows = append(rows, object{"time": b["key"], "out_bps": value(obj(b["out"]), "b") * 8 / interval, "in_bps": value(obj(b["in"]), "b") * 8 / interval})
	}
	return rows, nil
}
func ifaceName(s string) string {
	if strings.HasPrefix(s, "(") {
		return s
	}
	return strings.SplitN(s, " (", 2)[0]
}
func sameIface(a, b string) bool {
	return a != "" && b != "" && (ifaceName(a) == ifaceName(b) || a == b)
}
func shortTime(s string) string { r := []rune(s); return string(r[:min(16, len(r))]) }
func annotate(p *Path, s *Snapshot, flows []Flow, exporters map[string]string) {
	expDev := map[string]string{}
	devices := map[string]bool{}
	for ip, name := range exporters {
		d := name
		if o, ok := s.Owner[parseIP(ip)]; ok {
			d = o.Device
		}
		expDev[ip] = d
		devices[d] = true
	}
	seen := map[string][]Flow{}
	for _, f := range flows {
		dev := or(expDev[f.ObserverIP], f.Observer)
		seen[dev] = append(seen[dev], f)
	}
	routers := map[string]bool{}
	for _, h := range p.Hops {
		if h.Kind == "router" {
			routers[h.Device] = true
		}
	}
	for _, h := range p.Hops {
		if h.Kind != "router" || !devices[h.Device] {
			continue
		}
		mine := seen[h.Device]
		if len(mine) == 0 {
			h.Evidence = append(h.Evidence, "NetFlow: роутер экспортирует, но потоков этой пары за период нет (не доказательство отсутствия трафика)")
			continue
		}
		matching, other := []Flow{}, []Flow{}
		for _, f := range mine {
			if sameIface(f.InIf, h.InIf) && sameIface(f.OutIf, h.OutIf) {
				matching = append(matching, f)
			} else {
				other = append(other, f)
			}
		}
		if len(matching) > 0 {
			m := matching[0]
			h.Status = "Observed"
			h.Evidence = append(h.Evidence, fmt.Sprintf("NetFlow %s: %d потоков, %d байт, %s → %s, %s … %s UTC", m.Observer, m.Flows, m.Bytes, m.InIf, m.OutIf, shortTime(m.First), shortTime(m.Last)))
		}
		if len(other) > 0 {
			o := other[0]
			msg := fmt.Sprintf("NetFlow %s: поток шёл %s → %s (%d байт, %s … %s UTC)", o.Observer, o.InIf, o.OutIf, o.Bytes, shortTime(o.First), shortTime(o.Last))
			if len(matching) > 0 {
				msg += " — в периоде путь менялся"
			} else {
				h.Status = "Conflicting"
				msg += fmt.Sprintf(", а по таблицам — %s → %s", or(h.InIf, "None"), or(h.OutIf, "None"))
			}
			h.Evidence = append(h.Evidence, msg)
			h.ObservedAlt = o.InIf + " → " + o.OutIf
		}
	}
	for _, dev := range sortedKeys(seen) {
		if !routers[dev] {
			f := seen[dev][0]
			p.Warnings = append(p.Warnings, fmt.Sprintf("NetFlow видел поток этой пары на %s (%s → %s, %d байт), а расчётный путь идёт мимо него — расчёт и наблюдение расходятся", dev, f.InIf, f.OutIf, f.Bytes))
			p.Status = "Conflicting"
		}
	}
	summary := &FlowSummary{Exporters: []string{}}
	for _, f := range flows {
		summary.Flows += f.Flows
		summary.Bytes += f.Bytes
	}
	for _, d := range sortedKeys(routers) {
		if devices[d] {
			summary.Exporters = append(summary.Exporters, d)
		}
	}
	p.NetFlow = summary
}
func (n *NetFlow) annotate(ctx context.Context, p *Path, s *Snapshot, from, to float64, proto, dport string) {
	if !n.enabled() {
		return
	}
	a, b := resolveEndpoint(s, p.Src), resolveEndpoint(s, p.Dst)
	if a == nil || b == nil {
		return
	}
	flows, err := n.pair(ctx, a.IP, b.IP, from, to, proto, dport)
	var exporters map[string]string
	if err == nil {
		exporters, err = n.exporters(ctx)
	}
	if err != nil {
		p.Warnings = append(p.Warnings, "NetFlow недоступен: "+err.Error())
		return
	}
	annotate(p, s, flows, exporters)
}
