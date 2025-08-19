package analysis

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// writeRichLine writes a ResultEnvelope line with many extended metric fields populated.
func writeRichLine(f *os.File, runTag string, speed float64, ttfb int64, p50, p90, p95, p99, slope, coefVar float64, flags map[string]bool, headGetRatio float64) error {
	sa := &monitor.SpeedAnalysis{P50Kbps: p50, P90Kbps: p90, P95Kbps: p95, P99Kbps: p99, SlopeKbpsPerSec: slope, CoefVariation: coefVar, PlateauCount: 1, LongestPlateauMs: 100, PlateauStable: flags["plateau_stable"], JitterMeanAbsPct: 0.05}
	sr := &monitor.SiteResult{TransferSpeedKbps: speed, TraceTTFBMs: ttfb, TransferSizeBytes: 5000, FirstRTTGoodputKbps: speed * 0.2, SpeedAnalysis: sa,
		CachePresent: flags["cache"], ProxySuspected: flags["proxy"], IPMismatch: flags["ip_mismatch"], PrefetchSuspected: flags["prefetch"], WarmCacheSuspected: flags["warm_cache"], ConnectionReusedSecond: flags["reused"], HeadGetTimeRatio: headGetRatio}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	b, _ := json.Marshal(&env)
	_, err := f.Write(append(b, '\n'))
	return err
}

func TestExtendedRateAndSlopeMetrics(t *testing.T) {
	path := tempFile(t)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	// Five lines single batch B1
	writeRichLine(f, "B1", 1000, 40, 900, 920, 930, 940, 10, 0.10, map[string]bool{"cache": true, "reused": true, "plateau_stable": true}, 0.5)
	writeRichLine(f, "B1", 1100, 42, 910, 930, 940, 950, 20, 0.20, map[string]bool{"cache": true, "proxy": true}, 0.7)
	writeRichLine(f, "B1", 900, 38, 880, 900, 920, 930, 0, 0.00, map[string]bool{"prefetch": true, "ip_mismatch": true, "warm_cache": true}, 0.4)
	writeRichLine(f, "B1", 950, 39, 890, 910, 930, 935, 0, 0.00, map[string]bool{"plateau_stable": true}, 0.6)
	writeRichLine(f, "B1", 980, 41, 905, 915, 925, 945, 0, 0.00, map[string]bool{"reused": true}, 0.8)
	f.Close()

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	s := sums[0]
	// Percent based flags
	if mathAbs(s.CacheHitRatePct-40) > 0.001 {
		t.Fatalf("cache rate got %.2f want 40%%", s.CacheHitRatePct)
	}
	if mathAbs(s.ProxySuspectedRatePct-20) > 0.001 {
		t.Fatalf("proxy rate got %.2f want 20%%", s.ProxySuspectedRatePct)
	}
	if mathAbs(s.IPMismatchRatePct-20) > 0.001 {
		t.Fatalf("ip mismatch rate got %.2f want 20%%", s.IPMismatchRatePct)
	}
	if mathAbs(s.PrefetchSuspectedRatePct-20) > 0.001 {
		t.Fatalf("prefetch rate got %.2f want 20%%", s.PrefetchSuspectedRatePct)
	}
	if mathAbs(s.WarmCacheSuspectedRatePct-20) > 0.001 {
		t.Fatalf("warm cache rate got %.2f want 20%%", s.WarmCacheSuspectedRatePct)
	}
	if mathAbs(s.ConnReuseRatePct-40) > 0.001 {
		t.Fatalf("reuse rate got %.2f want 40%%", s.ConnReuseRatePct)
	}
	if mathAbs(s.PlateauStableRatePct-40) > 0.001 {
		t.Fatalf("plateau stable rate got %.2f want 40%%", s.PlateauStableRatePct)
	}
	// Averages
	if mathAbs(s.AvgSlopeKbpsPerSec-15) > 0.001 {
		t.Fatalf("avg slope got %.2f want 15", s.AvgSlopeKbpsPerSec)
	}
	if mathAbs(s.AvgCoefVariationPct-15) > 0.001 {
		t.Fatalf("avg coef variation pct got %.2f want 15", s.AvgCoefVariationPct)
	}
	if mathAbs(s.AvgHeadGetTimeRatio-0.6) > 0.0001 {
		t.Fatalf("avg head/get ratio got %.3f want 0.600", s.AvgHeadGetTimeRatio)
	}
	// Percentiles presence
	if s.AvgP90Speed <= 0 || s.AvgP95Speed <= 0 || s.AvgP99Speed <= 0 {
		t.Fatalf("expected percentile averages populated: %+v", s)
	}
}

func mathAbs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
