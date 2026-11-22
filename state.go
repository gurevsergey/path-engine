package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type State struct {
	cfg         Config
	prom        *Prom
	nf          *NetFlow
	mu          sync.RWMutex
	cache       map[int64]*Snapshot
	findings    []Finding
	pairs       []PairResult
	lastRefresh float64
	lastError   string
	watchWindow float64
}

func loadConfig(path, netmap string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if err = compileSites(cfg.Sites); err != nil {
		return cfg, err
	}
	for _, g := range cfg.Gateways {
		if !g.Subnet.IsValid() || !g.Gateway.IsValid() || g.Subnet.Addr().BitLen() != g.Gateway.BitLen() {
			return cfg, fmt.Errorf("invalid subnet gateway: %v", g)
		}
	}
	for _, v := range cfg.Sensitive {
		if !v.Prefix.IsValid() {
			return cfg, fmt.Errorf("invalid sensitive prefix")
		}
	}
	for _, v := range cfg.External {
		if !v.Prefix.IsValid() || v.Name == "" {
			return cfg, fmt.Errorf("invalid external network: %v", v)
		}
	}
	var links struct {
		Links []Link `json:"links"`
	}
	data, err = os.ReadFile(netmap)
	if err == nil {
		err = json.Unmarshal(data, &links)
	}
	if err != nil {
		log.Printf("%s: ручные связи не прочитаны (%v)", netmap, err)
	} else {
		cfg.Links = links.Links
	}
	return cfg, nil
}
func nowSeconds() float64 { return float64(time.Now().UnixNano()) / 1e9 }
func (s *State) snap(ctx context.Context, at float64) (*Snapshot, error) {
	now := nowSeconds()
	at = math.Min(at, now)
	k := int64(math.Floor(at / 60))
	s.mu.RLock()
	cached := s.cache[k]
	s.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	snapshot, err := loadSnapshot(ctx, s.prom, at, s.cfg)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.cache[k]; old != nil {
		return old, nil
	}
	s.cache[k] = snapshot
	keys := make([]int64, 0, len(s.cache))
	for k := range s.cache {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, old := range keys[:max(0, len(keys)-6)] {
		delete(s.cache, old)
	}
	return snapshot, nil
}
func (s *State) refresh(ctx context.Context) {
	snap, err := s.snap(ctx, nowSeconds())
	if err != nil {
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
		log.Printf("audit refresh: %v", err)
		return
	}
	findings, pairs := runAudit(snap, s.cfg)
	now := nowSeconds()
	for _, pair := range pairs {
		for _, p := range []*Path{pair.Forward, pair.Reverse} {
			s.nf.annotate(ctx, p, snap, now-s.watchWindow, now, "", "")
			restatus(p)
			for _, h := range p.Hops {
				if h.ObservedAlt != "" && h.Status == "Conflicting" {
					ev := ""
					if len(h.Evidence) > 0 {
						ev = h.Evidence[len(h.Evidence)-1]
					}
					findings = append(findings, finding("observed_differs", "warning", h.Device, pair.Pair, fmt.Sprintf("%s → %s: NetFlow видит %s, а по таблицам %s → %s", p.Src, p.Dst, h.ObservedAlt, or(h.InIf, "None"), or(h.OutIf, "None")), ev))
				}
			}
		}
	}
	s.mu.Lock()
	s.findings, s.pairs = findings, pairs
	s.lastRefresh = nowSeconds()
	s.lastError = ""
	s.mu.Unlock()
}
func (s *State) loop(ctx context.Context, interval time.Duration) {
	for {
		s.refresh(ctx)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func paramFloat(params map[string]string, k string, fallback float64) (float64, error) {
	v := params[k]
	if v == "" || v == "now" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("invalid %s: %q", k, v)
	}
	return f, nil
}
func window(params map[string]string) (float64, float64, error) {
	to, err := paramFloat(params, "time", nowSeconds())
	if err != nil {
		return 0, 0, err
	}
	from, err := paramFloat(params, "from", to-3600)
	return math.Min(from, to), to, err
}
func (s *State) pathsFor(ctx context.Context, params map[string]string) (*Snapshot, map[string]*Path, error) {
	at, err := paramFloat(params, "time", nowSeconds())
	if err != nil {
		return nil, nil, err
	}
	snap, err := s.snap(ctx, at)
	if err != nil {
		return nil, nil, err
	}
	from, to, err := window(params)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]*Path{}
	mode := or(params["mode"], "both")
	if mode == "both" || mode == "compare" || mode == "forward" {
		out["forward"] = trace(snap, params["src"], params["dst"], params["proto"], params["dport"])
	}
	if mode == "both" || mode == "compare" || mode == "reverse" {
		out["reverse"] = traceDir(snap, params["dst"], params["src"], params["proto"], params["dport"], true)
	}
	for _, d := range []string{"forward", "reverse"} {
		if p := out[d]; p != nil {
			s.nf.annotate(ctx, p, snap, from, to, params["proto"], params["dport"])
			restatus(p)
		}
	}
	return snap, out, nil
}
