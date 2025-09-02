package analysis

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper: write a SiteResult line marking a pre-TTFB stall via http_error
func writePreTTFBLine(t *testing.T, w *bufio.Writer, runTag, family string, mark bool) {
	t.Helper()
	sr := &monitor.SiteResult{IPFamily: family}
	if mark {
		sr.HTTPError = "stall_pre_ttfb"
	}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func TestPreTTFBStallRate_Computation_OverallAndPerFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	bw := bufio.NewWriter(f)

	tag := "PTTFB1"
	// Four lines: two pre-TTFB (one per family), two normal
	writePreTTFBLine(t, bw, tag, "ipv4", true)
	writePreTTFBLine(t, bw, tag, "ipv4", false)
	writePreTTFBLine(t, bw, tag, "ipv6", true)
	writePreTTFBLine(t, bw, tag, "ipv6", false)
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	sums, err := AnalyzeRecentResultsFullWithOptions(path, monitor.SchemaVersion, 5, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]
	// Overall
	if diff := abs(b.PreTTFBStallRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("overall pre-TTFB stall rate got %.3f want 50.000", b.PreTTFBStallRatePct)
	}
	if b.IPv4 == nil || b.IPv6 == nil {
		t.Fatalf("expected per-family summaries present")
	}
	if diff := abs(b.IPv4.PreTTFBStallRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("ipv4 pre-TTFB stall rate got %.3f want 50.000", b.IPv4.PreTTFBStallRatePct)
	}
	if diff := abs(b.IPv6.PreTTFBStallRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("ipv6 pre-TTFB stall rate got %.3f want 50.000", b.IPv6.PreTTFBStallRatePct)
	}
}
