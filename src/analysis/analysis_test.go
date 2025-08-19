package analysis

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write a synthetic line
func writeLine(f *os.File, runTag string, speed float64, ttfbMs int64) error {
	env := &monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: &monitor.SiteResult{Name: "test", TransferSpeedKbps: speed, TraceTTFBMs: ttfbMs, TransferSizeBytes: 1000}}
	b, _ := json.Marshal(env)
	_, err := f.Write(append(b, '\n'))
	return err
}

func TestAnalyzeRecentResults(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "results-*.jsonl")
	if err != nil {
		t.Fatalf("tmp file: %v", err)
	}
	// two batches
	for i := 0; i < 5; i++ {
		writeLine(tmp, "20240101_000000", 1000+float64(i*10), 50)
	}
	for i := 0; i < 5; i++ {
		writeLine(tmp, "20240102_000000", 800+float64(i*20), 60)
	}
	tmp.Close()
	sums, err := AnalyzeRecentResults(tmp.Name(), monitor.SchemaVersion, 10)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("expected 2 batches got %d", len(sums))
	}
	if sums[0].RunTag != "20240101_000000" || sums[1].RunTag != "20240102_000000" {
		t.Fatalf("unexpected run tag order: %+v", sums)
	}
	// spot check averages roughly
	if sums[0].AvgSpeed < 1000 || sums[0].AvgSpeed > 1100 {
		t.Fatalf("batch1 avg speed out of range: %.2f", sums[0].AvgSpeed)
	}
	if sums[1].AvgSpeed < 800 || sums[1].AvgSpeed > 900 {
		t.Fatalf("batch2 avg speed out of range: %.2f", sums[1].AvgSpeed)
	}
	spDelta, ttfbDelta, prevSpeed, prevTTFB := CompareLastVsPrevious(sums)
	_ = prevSpeed
	_ = prevTTFB
	if spDelta >= 0 {
		t.Fatalf("expected last batch slower speedDelta=%.2f", spDelta)
	}
	if ttfbDelta <= 0 {
		t.Fatalf("expected last batch higher ttfb ttfbDelta=%.2f", ttfbDelta)
	}
}
