package main

import (
	"math"
	"testing"

	"github.com/wcharczuk/go-chart/v2"
)

// Helper to assert condition (unused currently but kept for future additions).
func must(t *testing.T, cond bool, msg string) {
	if !cond {
		t.Fatalf(msg)
	}
}

func TestBuildRangeAndTicksBasicPadding(t *testing.T) {
	min, max := 10.0, 10.0 // degenerate
	rng, ticks := buildRangeAndTicks(min, max, 6, 0.05)
	if rng.Min >= rng.Max {
		t.Fatalf("expected widened range; got %v >= %v", rng.Min, rng.Max)
	}
	if len(ticks) < 2 {
		t.Fatalf("expected >=2 ticks, got %d", len(ticks))
	}
	// padding should expand beyond first/last tick when padPct>0
	first, last := ticks[0].Value, ticks[len(ticks)-1].Value
	if !(rng.Min < first && rng.Max > last) {
		t.Fatalf("expected padding beyond tick span: range [%v,%v] ticks [%v,%v]", rng.Min, rng.Max, first, last)
	}
}

func TestBuildRangeAndTicksNoPadding(t *testing.T) {
	min, max := 5.0, 123.0
	rng, ticks := buildRangeAndTicks(min, max, 6, 0)
	if len(ticks) < 2 {
		t.Fatalf("expected ticks")
	}
	first, last := ticks[0].Value, ticks[len(ticks)-1].Value
	if math.Abs(rng.Min-first) > 1e-9 || math.Abs(rng.Max-last) > 1e-9 {
		t.Fatalf("expected no padding: range [%v,%v] vs tick span [%v,%v]", rng.Min, rng.Max, first, last)
	}
}

func TestBuildZeroAnchoredRangeAndTicksMedianOnlyVsNormal(t *testing.T) {
	maxVal := 93.0
	rngNormal, _ := buildZeroAnchoredRangeAndTicks(maxVal, 6, 0.04, false)
	rngMedian, _ := buildZeroAnchoredRangeAndTicks(maxVal, 6, 0.04, true)
	if rngNormal.Min != 0 || rngMedian.Min != 0 {
		t.Fatalf("expected zero anchor")
	}
	if !(rngNormal.Max >= rngMedian.Max) { // normal should not be tighter than median mode
		t.Fatalf("expected normal mode max >= median-only max: %v vs %v", rngNormal.Max, rngMedian.Max)
	}
	// median-only pad ≈ rawMax*padPct
	expectedMedianMaxLower := maxVal + math.Min(math.Max(1, maxVal*0.04), maxVal*0.05)
	if rngMedian.Max < expectedMedianMaxLower { // loose check
		t.Fatalf("median range too small: got %v expected >= %v", rngMedian.Max, expectedMedianMaxLower)
	}
}

func TestBuildSignedRangeAndTicksForceIncludeZeroFromPositive(t *testing.T) {
	rng, _ := buildSignedRangeAndTicks(10, 20, 6, 0.04, true)
	if !(rng.Min <= 0 && rng.Max > 20) {
		t.Fatalf("expected zero inclusion with padding; got [%v,%v]", rng.Min, rng.Max)
	}
}

func TestBuildSignedRangeAndTicksForceIncludeZeroFromNegative(t *testing.T) {
	rng, _ := buildSignedRangeAndTicks(-30, -10, 6, 0.04, true)
	if !(rng.Max >= 0 && rng.Min < -30) {
		t.Fatalf("expected zero inclusion from negative range; got [%v,%v]", rng.Min, rng.Max)
	}
}

func TestComputeYAxisRangePercentAbsolute(t *testing.T) {
	rng, ticks := computeYAxisRangePercent(12, 34, false)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min != 0 || cr.Max != 100 {
		t.Fatalf("expected fixed [0,100] domain; got [%v,%v]", cr.Min, cr.Max)
	}
	if len(ticks) != 5 {
		t.Fatalf("expected 5 ticks; got %d", len(ticks))
	}
}

func TestComputeYAxisRangePercentRelative(t *testing.T) {
	minY, maxY := 42.0, 78.0
	rng, ticks := computeYAxisRangePercent(minY, maxY, true)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min < 0 { // should not force zero in relative percent case
		t.Fatalf("unexpected negative min")
	}
	if len(ticks) < 2 {
		t.Fatalf("expected ticks")
	}
	if cr.Max-cr.Min <= 0 {
		t.Fatalf("invalid span")
	}
}

func TestTickLabelsNonEmpty(t *testing.T) {
	rng, ticks := buildRangeAndTicks(1, 9, 6, 0.02)
	_ = rng
	for i, tk := range ticks {
		if tk.Label == "" {
			t.Fatalf("empty label at index %d", i)
		}
	}
}
