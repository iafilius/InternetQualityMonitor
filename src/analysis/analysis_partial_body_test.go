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

// helper: write a SiteResult line with minimal fields
func writeLinePartial(t *testing.T, f *os.File, runTag, family string, clMismatch bool, httpErr string) {
	t.Helper()
	sr := &monitor.SiteResult{IPFamily: family, TransferSpeedKbps: 1000, TransferSizeBytes: 1024, ContentLengthMismatch: clMismatch, HTTPError: httpErr}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestPartialBodyRate_Computation_OverallAndPerFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "PB1"
	// 4 lines total: 2 partial (1 via mismatch, 1 via http_error), 2 complete.
	writeLinePartial(t, f, tag, "ipv4", true, "")                   // partial by mismatch
	writeLinePartial(t, f, tag, "ipv4", false, "partial_body: eof") // partial by http_error token prefix
	writeLinePartial(t, f, tag, "ipv6", false, "")                  // good
	writeLinePartial(t, f, tag, "ipv6", false, "timeout")           // good (not partial)

	sums, err := AnalyzeRecentResultsFullWithOptions(path, monitor.SchemaVersion, 5, AnalyzeOptions{LowSpeedThresholdKbps: 1000})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]
	if diff := abs(b.PartialBodyRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("overall partial rate got %.3f want 50.000", b.PartialBodyRatePct)
	}
	if b.IPv4 == nil || b.IPv6 == nil {
		t.Fatalf("expected per-family summaries")
	}
	if diff := abs(b.IPv4.PartialBodyRatePct - 100.0); diff > 1e-6 {
		t.Fatalf("ipv4 partial rate got %.3f want 100.000", b.IPv4.PartialBodyRatePct)
	}
	if diff := abs(b.IPv6.PartialBodyRatePct - 0.0); diff > 1e-6 {
		t.Fatalf("ipv6 partial rate got %.3f want 0.000", b.IPv6.PartialBodyRatePct)
	}
}

func TestPartialBodyRate_DetectedWithoutSpeedAnalysis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "PB2"
	// SiteResult without SpeedAnalysis should still count partials
	sr := &monitor.SiteResult{IPFamily: "ipv4", ContentLengthMismatch: true}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: tag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	bw := bufio.NewWriter(f)
	if err := json.NewEncoder(bw).Encode(env); err != nil {
		t.Fatalf("encode: %v", err)
	}
	// add one good line too
	env.SiteResult = &monitor.SiteResult{IPFamily: "ipv4"}
	if err := json.NewEncoder(bw).Encode(env); err != nil {
		t.Fatalf("encode: %v", err)
	}
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
	if diff := abs(b.PartialBodyRatePct - 50.0); diff > 1e-6 {
		t.Fatalf("overall partial rate got %.3f want 50.000", b.PartialBodyRatePct)
	}
}
