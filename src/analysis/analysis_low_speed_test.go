package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write one envelope line with samples
func writeEnvLineWithSamples(t *testing.T, f *os.File, runTag string, family string, speeds []float64) {
	t.Helper()
	samples := make([]monitor.SpeedSample, 0, len(speeds))
	var bytesAccum int64
	for i, sp := range speeds {
		// populate sample time and bytes only for realism; analysis uses count*interval
		tm := int64(i) * int64(monitor.SpeedSampleInterval/time.Millisecond)
		// rough bytes for the interval at kbps
		b := int64(sp * 1000.0 / 8.0 * float64(monitor.SpeedSampleInterval) / float64(time.Second))
		bytesAccum += b
		samples = append(samples, monitor.SpeedSample{TimeMs: tm, Bytes: bytesAccum, Speed: sp})
	}
	sr := &monitor.SiteResult{IPFamily: family, TransferSpeedKbps: 1000, TransferSizeBytes: 1024, TransferSpeedSamples: samples}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestLowSpeedTimeShare_Computation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	runTag := "LSS1"
	// IPv4: 10 samples, 5 below threshold (e.g., < 1000 kbps)
	ipv4Speeds := []float64{500, 1500, 600, 1400, 700, 1300, 800, 1200, 900, 1100} // 5 < 1000
	writeEnvLineWithSamples(t, f, runTag, "ipv4", ipv4Speeds)
	// IPv6: 10 samples, 7 below threshold
	ipv6Speeds := []float64{400, 800, 900, 950, 700, 600, 500, 1200, 1300, 800} // 7 < 1000
	writeEnvLineWithSamples(t, f, runTag, "ipv6", ipv6Speeds)

	// Analyze with explicit low-speed threshold
	opts := AnalyzeOptions{SituationFilter: "", LowSpeedThresholdKbps: 1000}
	sums, err := AnalyzeRecentResultsFullWithOptions(path, monitor.SchemaVersion, 5, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	// Overall: (5 + 8) of (10 + 10) = 13/20 = 65%
	if d := abs(b.LowSpeedTimeSharePct - 65.0); d > 1e-6 {
		t.Fatalf("overall low-speed share got %.3f want 65.000", b.LowSpeedTimeSharePct)
	}
	if b.IPv4 == nil || b.IPv6 == nil {
		t.Fatalf("expected per-family summaries present")
	}
	if d := abs(b.IPv4.LowSpeedTimeSharePct - 50.0); d > 1e-6 {
		t.Fatalf("ipv4 low-speed share got %.3f want 50.000", b.IPv4.LowSpeedTimeSharePct)
	}
	if d := abs(b.IPv6.LowSpeedTimeSharePct - 80.0); d > 1e-6 {
		t.Fatalf("ipv6 low-speed share got %.3f want 80.000", b.IPv6.LowSpeedTimeSharePct)
	}
}
