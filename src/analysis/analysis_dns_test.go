package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

func writeDNSLine(t *testing.T, f *os.File, runTag string, traceDNS, legacyDNS int64) {
	t.Helper()
	sr := &monitor.SiteResult{}
	if traceDNS > 0 {
		sr.TraceDNSMs = traceDNS
	}
	if legacyDNS > 0 {
		sr.DNSTimeMs = legacyDNS
	}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	b, err := json.Marshal(&env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestDNSAggregation_TracePrecedenceAndLegacyOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "D1"
	// Line 1: trace DNS 10ms
	writeDNSLine(t, f, tag, 10, 0)
	// Line 2: only legacy dns_time_ms 20ms (no trace)
	writeDNSLine(t, f, tag, 0, 20)
	// Line 3: both trace 30ms and legacy 40ms → trace used for AvgDNSMs, legacy still tracked separately
	writeDNSLine(t, f, tag, 30, 40)

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	// AvgDNSMs = avg(10, 20, 30) = 20
	if diff := abs(b.AvgDNSMs - 20.0); diff > 1e-6 {
		t.Fatalf("avg dns got %.3f want 20.000", b.AvgDNSMs)
	}
	// AvgDNSLegacyMs averages all lines with legacy present: avg(20, 40) = 30
	if diff := abs(b.AvgDNSLegacyMs - 30.0); diff > 1e-6 {
		t.Fatalf("avg legacy dns got %.3f want 30.000", b.AvgDNSLegacyMs)
	}
}
