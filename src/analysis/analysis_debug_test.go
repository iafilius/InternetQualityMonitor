package analysis

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// Verifies that when ANALYSIS_DEBUG=1, the analysis summary logs include stall stats
// (stalls=..% avg_stall=..ms) if input contains stalled lines.
func TestAnalyzeRecentResults_DebugLogsIncludeStalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	bw := bufio.NewWriter(f)
	// One stalled and one non-stalled line in same batch
	tag := "DBG1"
	enc := json.NewEncoder(bw)
	if err := enc.Encode(monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: tag, SchemaVersion: monitor.SchemaVersion}, SiteResult: &monitor.SiteResult{TransferStalled: true, StallElapsedMs: 500}}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := enc.Encode(monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: tag, SchemaVersion: monitor.SchemaVersion}, SiteResult: &monitor.SiteResult{}}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	f.Close()

	// Enable debug and capture stdout to assert the debug summary includes stalls
	oldEnv := os.Getenv("ANALYSIS_DEBUG")
	_ = os.Setenv("ANALYSIS_DEBUG", "1")
	defer func() { _ = os.Setenv("ANALYSIS_DEBUG", oldEnv) }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	summaries, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary got %d", len(summaries))
	}
	if summaries[0].StallRatePct <= 0 {
		t.Fatalf("expected stall rate > 0, got %.3f", summaries[0].StallRatePct)
	}
	s := string(out)
	if !strings.Contains(s, "stalls=") || !strings.Contains(s, "avg_stall=") {
		t.Fatalf("expected debug output to include stalls and avg_stall, got: %s", s)
	}
	// Echo captured debug output so it’s visible with -v
	t.Logf("captured analysis debug output:\n%s", s)
}
