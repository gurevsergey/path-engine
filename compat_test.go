package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Frozen expected results for synthetic snapshots. Full paths include the
// evidence strings.
type goldenCases struct {
	Snapshots []Snapshot
	Trace     []struct {
		SnapshotIndex          int `json:"snapshot_index"`
		Src, Dst, Proto, Dport string
		Expected               Path
	}
	Audit []struct {
		SnapshotIndex int `json:"snapshot_index"`
		Config        Config
		Findings      []Finding
		Pairs         []PairResult
	}
	Annotate []struct {
		SnapshotIndex int `json:"snapshot_index"`
		Path          Path
		Flows         []Flow
		Exporters     map[string]string
		Expected      Path
	}
	Compare []struct {
		Forward, Reverse Path
		Expected         Comparison
	}
	API []struct {
		SnapshotIndex int `json:"snapshot_index"`
		Path          string
		Params        map[string]string
		Expected      any
	}
	Metrics []struct {
		SnapshotIndex int `json:"snapshot_index"`
		Config        Config
		Expected      string
	}
}

func loadGolden(t *testing.T) goldenCases {
	t.Helper()
	data, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases goldenCases
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for i := range cases.Snapshots {
		if err = compileSites(cases.Snapshots[i].Sites); err != nil {
			t.Fatal(err)
		}
	}
	return cases
}
func canonical(t *testing.T, v any) any {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var out any
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func equalJSON(t *testing.T, want, got any) {
	t.Helper()
	if !reflect.DeepEqual(canonical(t, want), canonical(t, got)) {
		a, _ := json.MarshalIndent(want, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("want:\n%s\ngot:\n%s", a, b)
	}
}
func TestGoldenTrace(t *testing.T) {
	cases := loadGolden(t)
	for i, c := range cases.Trace {
		t.Run(testName(i, c.Src+"-"+c.Dst), func(t *testing.T) {
			got := trace(&cases.Snapshots[c.SnapshotIndex], c.Src, c.Dst, c.Proto, c.Dport)
			equalJSON(t, &c.Expected, got)
		})
	}
}
func TestGoldenAudit(t *testing.T) {
	cases := loadGolden(t)
	for i, c := range cases.Audit {
		t.Run(testName(i, "audit"), func(t *testing.T) {
			findings, pairs := runAudit(&cases.Snapshots[c.SnapshotIndex], c.Config)
			sortFindings(c.Findings)
			sortFindings(findings)
			// Обоснование dead_route и backup_route_active намеренно подробнее,
			// чем в эталоне; его проверяет audit_refactor_test.go.
			for _, fs := range [][]Finding{c.Findings, findings} {
				for i := range fs {
					if fs[i].Check == "dead_route" || fs[i].Check == "backup_route_active" {
						fs[i].Evidence = ""
					}
				}
			}
			equalJSON(t, c.Findings, findings)
			equalJSON(t, c.Pairs, pairs)
		})
	}
}
func sortFindings(f []Finding) {
	// Match conditions are a map in Go; their display order has no meaning.
	for i := range f {
		if f[i].Check == "policy_without_lan" {
			parts := strings.Split(f[i].Evidence, ";")
			sort.Strings(parts)
			f[i].Evidence = strings.Join(parts, ";")
		}
	}
	sort.Slice(f, func(i, j int) bool {
		a, b := f[i], f[j]
		return key(a.Check, a.Device, a.Object, a.Detail) < key(b.Check, b.Device, b.Object, b.Detail)
	})
}
func TestGoldenNetFlow(t *testing.T) {
	cases := loadGolden(t)
	for i, c := range cases.Annotate {
		t.Run(testName(i, "netflow"), func(t *testing.T) {
			annotate(&c.Path, &cases.Snapshots[c.SnapshotIndex], c.Flows, c.Exporters)
			equalJSON(t, &c.Expected, &c.Path)
		})
	}
}
func TestGoldenCompare(t *testing.T) {
	for i, c := range loadGolden(t).Compare {
		t.Run(testName(i, "compare"), func(t *testing.T) { equalJSON(t, c.Expected, compare(&c.Forward, &c.Reverse)) })
	}
}
func fixtureState(snap *Snapshot) *State {
	k := int64(nowSeconds() / 60)
	return &State{cache: map[int64]*Snapshot{0: snap, k: snap, k + 1: snap}, nf: &NetFlow{}}
}
func TestGoldenAPI(t *testing.T) {
	cases := loadGolden(t)
	for i, c := range cases.API {
		t.Run(testName(i, c.Path), func(t *testing.T) {
			s := fixtureState(&cases.Snapshots[c.SnapshotIndex])
			got, err := s.api(context.Background(), c.Path, c.Params)
			if err != nil {
				t.Fatal(err)
			}
			equalJSON(t, c.Expected, got)
		})
	}
}
func testName(i int, label string) string { return fmt.Sprintf("%02d-%s", i, label) }

var labelPattern = regexp.MustCompile(`[a-zA-Z_][a-zA-Z0-9_]*="(?:\\.|[^"\\])*"`)

func metricSamples(t *testing.T, text string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := strings.LastIndex(line, " ")
		if at < 0 {
			t.Fatalf("invalid metric: %s", line)
		}
		v, err := strconv.ParseFloat(line[at+1:], 64)
		if err != nil {
			t.Fatal(err)
		}
		name := line[:at]
		if idx := strings.IndexByte(name, '{'); idx >= 0 {
			labels := labelPattern.FindAllString(name[idx:], -1)
			sort.Strings(labels)
			name = name[:idx] + "{" + strings.Join(labels, ",") + "}"
		}
		if _, exists := out[name]; exists {
			t.Fatalf("duplicate metric: %s", name)
		}
		out[name] = v
	}
	return out
}
func TestGoldenMetrics(t *testing.T) {
	cases := loadGolden(t)
	for _, c := range cases.Metrics {
		s := fixtureState(&cases.Snapshots[c.SnapshotIndex])
		s.findings, s.pairs = runAudit(&cases.Snapshots[c.SnapshotIndex], c.Config)
		s.lastRefresh = 42
		got := metricSamples(t, s.metrics())
		equalJSON(t, metricSamples(t, c.Expected), got)
	}
}
