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

func writeStallLine(t *testing.T, w *bufio.Writer, runTag, family string, stalled bool, stallMs int64) {
	t.Helper()
	sr := &monitor.SiteResult{IPFamily: family, TransferStalled: stalled, StallElapsedMs: stallMs}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func TestStallMetrics_Computation_OverallAndPerFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	bw := bufio.NewWriter(f)

	tag := "STALL1"
	// Four lines: two stalled (one per family), two not stalled
	writeStallLine(t, bw, tag, "ipv4", true, 1000)
	writeStallLine(t, bw, tag, "ipv4", false, 0)
	writeStallLine(t, bw, tag, "ipv6", true, 500)
	writeStallLine(t, bw, tag, "ipv6", false, 0)
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
	if diff := abs(b.StallRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("overall stall rate got %.3f want 50.000", b.StallRatePct)
	}
	if diff := abs(b.AvgStallElapsedMs - 750.0); diff > 1e-6 {
		t.Fatalf("overall avg stall ms got %.3f want 750.000", b.AvgStallElapsedMs)
	}
	// Per-family
	if b.IPv4 == nil || b.IPv6 == nil {
		t.Fatalf("expected per-family summaries present")
	}
	if diff := abs(b.IPv4.StallRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("ipv4 stall rate got %.3f want 50.000", b.IPv4.StallRatePct)
	}
	if diff := abs(b.IPv4.AvgStallElapsedMs - 1000.0); diff > 1e-6 {
		t.Fatalf("ipv4 avg stall ms got %.3f want 1000.000", b.IPv4.AvgStallElapsedMs)
	}
	if diff := abs(b.IPv6.StallRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("ipv6 stall rate got %.3f want 50.000", b.IPv6.StallRatePct)
	}
	if diff := abs(b.IPv6.AvgStallElapsedMs - 500.0); diff > 1e-6 {
		t.Fatalf("ipv6 avg stall ms got %.3f want 500.000", b.IPv6.AvgStallElapsedMs)
	}
	// No partials in this set
	if b.PartialBodyRatePct != 0 {
		t.Fatalf("expected 0 partial body rate got %.3f", b.PartialBodyRatePct)
	}
}

func TestStallMetrics_NoStallsZeroes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	bw := bufio.NewWriter(f)

	tag := "STALL2"
	// Two non-stalled lines
	writeStallLine(t, bw, tag, "ipv4", false, 0)
	writeStallLine(t, bw, tag, "ipv6", false, 0)
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
	if b.StallRatePct != 0 {
		t.Fatalf("expected 0 stall rate got %.3f", b.StallRatePct)
	}
	if b.AvgStallElapsedMs != 0 {
		t.Fatalf("expected 0 avg stall elapsed got %.3f", b.AvgStallElapsedMs)
	}
}
