package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

func writeTTFBLine(t *testing.T, f *os.File, runTag string, ttfbMs int64) {
	t.Helper()
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: &monitor.SiteResult{TraceTTFBMs: ttfbMs}}
	b, err := json.Marshal(&env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestTTFBAggregationAndPercentiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "T1"
	// Three lines with TTFB 50, 100, 150
	writeTTFBLine(t, f, tag, 50)
	writeTTFBLine(t, f, tag, 100)
	writeTTFBLine(t, f, tag, 150)

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	if diff := abs(b.AvgTTFB - 100.0); diff > 1e-6 {
		t.Fatalf("avg ttfb got %.3f want 100.000", b.AvgTTFB)
	}
	if b.AvgP50TTFBMs == 0 || b.AvgP90TTFBMs == 0 || b.AvgP95TTFBMs == 0 || b.AvgP99TTFBMs == 0 {
		t.Fatalf("expected TTFB percentiles populated: %+v", b)
	}
}
