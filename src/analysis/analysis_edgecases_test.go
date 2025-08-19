package analysis

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write a line with optional SpeedAnalysis and flags
func writeLineExt(f *os.File, runTag string, schema int, speed float64, ttfb int64, withSA bool, slope float64, coefVar float64, jitter float64, flags map[string]bool) {
	sr := &monitor.SiteResult{TransferSpeedKbps: speed, TraceTTFBMs: ttfb, TransferSizeBytes: 1000,
		CachePresent: flags["cache"], ProxySuspected: flags["proxy"], IPMismatch: flags["ip_mismatch"], PrefetchSuspected: flags["prefetch"], WarmCacheSuspected: flags["warm_cache"], ConnectionReusedSecond: flags["reused"], HeadGetTimeRatio: flagsRatio(flags)}
	if withSA {
		sr.SpeedAnalysis = &monitor.SpeedAnalysis{P50Kbps: speed * 0.9, P90Kbps: speed * 0.92, P95Kbps: speed * 0.95, P99Kbps: speed * 0.99, SlopeKbpsPerSec: slope, CoefVariation: coefVar, PlateauCount: 1, LongestPlateauMs: 100, PlateauStable: flags["plateau_stable"], JitterMeanAbsPct: jitter}
	}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: schema}, SiteResult: sr}
	b, _ := json.Marshal(&env)
	f.Write(append(b, '\n'))
}

// flagsRatio returns a deterministic ratio if set via flag "ratioX10" (0..10) else 0.
func flagsRatio(flags map[string]bool) float64 {
	for k, v := range flags {
		if v && len(k) > 5 && k[:5] == "ratio" { // e.g. ratio6 -> 0.6
			// parse digit(s) after ratio
			n := 0
			for i := 5; i < len(k); i++ {
				if k[i] >= '0' && k[i] <= '9' {
					n = n*10 + int(k[i]-'0')
				}
			}
			return float64(n) / 10.0
		}
	}
	return 0
}

func TestNoRecordsError(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// Write lines with wrong schema version so they are filtered out
	for i := 0; i < 3; i++ {
		writeLineExt(f, "X", monitor.SchemaVersion+1, 1000, 50, true, 0, 0, 0.01, map[string]bool{})
	}
	f.Close()
	if _, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, ""); err == nil {
		t.Fatalf("expected error for no matching records")
	}
}

func TestMaxBatchesTruncation(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// create 6 batches; limit later to 4
	for b := 1; b <= 6; b++ {
		tag := time.Now().Add(time.Duration(b) * time.Minute).Format("20060102_150405")
		for i := 0; i < 2; i++ {
			writeLineExt(f, tag, monitor.SchemaVersion, 500+float64(b*10), 40, false, 0, 0, 0, map[string]bool{})
		}
	}
	f.Close()
	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 4, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 4 {
		t.Fatalf("expected 4 summaries got %d", len(sums))
	}
}

func TestErrorLineCounting(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// Create lines with tcp_error/http_error by injecting substrings directly (simulate raw)
	// We'll leverage writeLineExt then append error strings to raw file to trip detection logic.
	writeLineExt(f, "E1", monitor.SchemaVersion, 0, 0, false, 0, 0, 0, map[string]bool{})
	f.WriteString("{\"meta\":{\"run_tag\":\"E1\",\"schema_version\":3},\"site_result\":{\"tcp_error\":\"timeout\"}}\n")
	f.WriteString("{\"meta\":{\"run_tag\":\"E1\",\"schema_version\":3},\"site_result\":{\"http_error\":\"500\"}}\n")
	f.Close()
	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 2, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if sums[0].ErrorLines < 2 {
		t.Fatalf("expected >=2 error lines got %d", sums[0].ErrorLines)
	}
}

func TestMissingSpeedAnalysisAndZeroRates(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// Lines without SpeedAnalysis -> extended percentiles remain zero
	for i := 0; i < 5; i++ {
		writeLineExt(f, "B1", monitor.SchemaVersion, 800+float64(i), 60, false, 0, 0, 0, map[string]bool{})
	}
	f.Close()
	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	s := sums[0]
	if s.AvgP90Speed != 0 || s.AvgSlopeKbpsPerSec != 0 || s.CacheHitRatePct != 0 {
		t.Fatalf("expected zeros for extended metrics got %+v", s)
	}
}

func TestCompareSingleBatch(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	writeLineExt(f, "ONLY", monitor.SchemaVersion, 900, 50, true, 5, 0.1, 0.02, map[string]bool{"cache": true})
	f.Close()
	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 2, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	spd, ttfb, prevS, prevT := CompareLastVsPrevious(sums)
	if spd != 0 || ttfb != 0 || prevS != 0 || prevT != 0 {
		t.Fatalf("expected zero deltas for single batch got %.2f %.2f %.2f %.2f", spd, ttfb, prevS, prevT)
	}
}
