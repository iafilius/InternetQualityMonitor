package analysis

import (
	"encoding/json"
	"testing"
)

// We place the test in analysis package to reuse BatchSummary; referencing main's writeAlertJSON via import alias is not feasible since main is package main.
// Instead we duplicate minimal struct shapes to validate JSON schema expectations produced in main.

type alertThresholds struct {
	SpeedDropPct    float64 `json:"speed_drop_pct"`
	TTFBIncreasePct float64 `json:"ttfb_increase_pct"`
	ErrorRatePct    float64 `json:"error_rate_pct"`
	JitterPct       float64 `json:"jitter_pct"`
	P99P50Ratio     float64 `json:"p99_p50_ratio"`
}

type lastBatchSummary struct {
	Lines               int     `json:"lines"`
	AvgSpeedKbps        float64 `json:"avg_speed_kbps"`
	MedianSpeedKbps     float64 `json:"median_speed_kbps"`
	AvgTTFBMs           float64 `json:"avg_ttfb_ms"`
	AvgBytes            float64 `json:"avg_bytes"`
	ErrorLines          int     `json:"error_lines"`
	ErrorRatePct        float64 `json:"error_rate_pct"`
	FirstRTTGoodputKbps float64 `json:"first_rtt_goodput_kbps"`
	P50Kbps             float64 `json:"p50_kbps"`
	P99P50Ratio         float64 `json:"p99_p50_ratio"`
	PlateauCount        float64 `json:"plateau_count"`
	LongestPlateauMs    float64 `json:"longest_plateau_ms"`
	JitterMeanAbsPct    float64 `json:"jitter_mean_abs_pct"`
}

// comparisonSummary omitted in single-batch scenario

type alertReport struct {
	GeneratedAt      string           `json:"generated_at"`
	SchemaVersion    int              `json:"schema_version"`
	RunTag           string           `json:"run_tag"`
	BatchesCompared  int              `json:"batches_compared"`
	LastBatchSummary lastBatchSummary `json:"last_batch_summary"`
	Comparison       *struct{}        `json:"comparison,omitempty"`
	SingleBatch      bool             `json:"single_batch,omitempty"`
	Alerts           []string         `json:"alerts"`
	Thresholds       alertThresholds  `json:"thresholds"`
}

// TestAlertReportMarshalling ensures struct tags align and optional fields behave.
func TestAlertReportMarshalling(t *testing.T) {
	rep := alertReport{
		GeneratedAt:      "2025-08-18T00:00:00Z",
		SchemaVersion:    3,
		RunTag:           "20250818_000000",
		BatchesCompared:  1,
		LastBatchSummary: lastBatchSummary{Lines: 5, AvgSpeedKbps: 1000, MedianSpeedKbps: 900, AvgTTFBMs: 50, AvgBytes: 12345, ErrorLines: 0, ErrorRatePct: 0, FirstRTTGoodputKbps: 800, P50Kbps: 950, P99P50Ratio: 1.2, PlateauCount: 0, LongestPlateauMs: 0, JitterMeanAbsPct: 5},
		SingleBatch:      true,
		Alerts:           []string{"speed_drop"},
		Thresholds:       alertThresholds{SpeedDropPct: 25, TTFBIncreasePct: 30, ErrorRatePct: 5, JitterPct: 40, P99P50Ratio: 2},
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)
	// Must include single_batch and not include comparison
	if !contains(js, "\"single_batch\":true") {
		t.Errorf("expected single_batch true: %s", js)
	}
	if contains(js, "comparison") {
		t.Errorf("did not expect comparison in single batch: %s", js)
	}
	// Alerts array shouldn't be null
	if !contains(js, "\"alerts\":[\"speed_drop\"]") {
		t.Errorf("alerts array mismatch: %s", js)
	}
}

// contains is a tiny helper (avoid pulling strings just for one test)
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
