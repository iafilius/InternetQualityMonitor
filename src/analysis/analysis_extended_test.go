package analysis

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/arjan/internet-monitor-monitor/src/monitor"
)

// helper to write a typed envelope line
func writeTypedLine(f *os.File, runTag string, speed float64, ttfb int64, jitter float64, p50 float64, p99 float64) error {
	env := monitor.ResultEnvelope{
		Meta:       &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion},
		SiteResult: &monitor.SiteResult{TransferSpeedKbps: speed, TraceTTFBMs: ttfb, TransferSizeBytes: 1000, FirstRTTGoodputKbps: speed * 0.1, SpeedAnalysis: &monitor.SpeedAnalysis{P50Kbps: p50, P99Kbps: p99, PlateauCount: 1, LongestPlateauMs: 500, JitterMeanAbsPct: jitter}},
	}
	b, _ := json.Marshal(&env)
	_, err := f.Write(append(b, '\n'))
	return err
}

func TestExtendedMetrics(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// First batch
	for i := 0; i < 5; i++ {
		writeTypedLine(f, "batchA", 1000+float64(i*50), 40, 0.10, 900, 1000)
	}
	// Second batch higher ttfb, lower speed
	for i := 0; i < 5; i++ {
		writeTypedLine(f, "batchB", 700+float64(i*30), 80, 0.20, 650, 900)
	}
	f.Close()

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 10, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("expected 2 batches got %d", len(sums))
	}
	var batchA, batchB *BatchSummary
	for i := range sums {
		if sums[i].RunTag == "batchA" {
			batchA = &sums[i]
		} else if sums[i].RunTag == "batchB" {
			batchB = &sums[i]
		}
	}
	if batchA == nil || batchB == nil {
		t.Fatalf("missing batches in summaries: %+v", sums)
	}
	if batchA.AvgSpeed <= batchB.AvgSpeed {
		t.Fatalf("expected batchA faster speedA=%.1f speedB=%.1f", batchA.AvgSpeed, batchB.AvgSpeed)
	}
	if batchB.AvgTTFB <= batchA.AvgTTFB {
		t.Fatalf("expected batchB higher ttfb")
	}
	if batchA.AvgP50Speed <= 0 || batchA.AvgP99P50Ratio <= 0 {
		t.Fatalf("expected extended metrics populated")
	}
	if batchA.AvgJitterPct <= 0 {
		t.Fatalf("expected jitter pct populated")
	}
	if batchA.AvgJitterPct < 5 || batchA.AvgJitterPct > 15 {
		t.Fatalf("unexpected jitter pct batchA %.2f", batchA.AvgJitterPct)
	}
}

func TestCompareLastVsPrevious(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// prior batches speeds ~1000, last ~600 to force drop
	for b := 0; b < 2; b++ {
		for i := 0; i < 3; i++ {
			writeTypedLine(f, "A", 950+float64(i*10), 50, 0.05, 900, 1000)
		}
	}
	for i := 0; i < 3; i++ {
		writeTypedLine(f, "B", 600+float64(i*5), 90, 0.05, 550, 800)
	}
	f.Close()
	// Limit n large enough
	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 10, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) < 2 {
		t.Fatalf("need at least 2 batches for comparison")
	}
	spdDelta, ttfbDelta, prevS, prevT := CompareLastVsPrevious(sums)
	_ = prevS
	_ = prevT
	if spdDelta >= 0 {
		t.Fatalf("expected speed drop delta=%.2f", spdDelta)
	}
	if ttfbDelta <= 0 {
		t.Fatalf("expected ttfb increase delta=%.2f", ttfbDelta)
	}
}

// tempFile creates a temp file path and closes it.
func tempFile(t *testing.T) string {
	f, err := os.CreateTemp(t.TempDir(), "results-*.jsonl")
	if err != nil {
		t.Fatalf("tmp: %v", err)
	}
	name := f.Name()
	f.Close()
	return name
}
