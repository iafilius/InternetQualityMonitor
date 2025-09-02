package main

import (
	"testing"

	chart "github.com/wcharczuk/go-chart/v2"
)

// Percent charts must clamp to [0,100] in Absolute and fit in Relative (nice bounds allowed).

func TestYAxis_CacheHitRate_PercentAxis(t *testing.T) {
	rng, _ := computeYAxisRangePercent(10, 65, false /* absolute */)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min != 0 || cr.Max != 100 {
		t.Fatalf("absolute percent axis must be [0,100], got [%.0f,%.0f]", cr.Min, cr.Max)
	}
	rng, _ = computeYAxisRangePercent(10, 65, true /* relative */)
	cr = rng.(*chart.ContinuousRange)
	if !(cr.Min <= 10 && cr.Max >= 65) {
		t.Fatalf("relative percent axis must fit band, got [%.2f,%.2f] for data [10,65]", cr.Min, cr.Max)
	}
}

func TestYAxis_Jitter_PercentAxis(t *testing.T) {
	rng, _ := computeYAxisRangePercent(1, 35, false)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min != 0 || cr.Max != 100 {
		t.Fatalf("absolute percent axis must be [0,100], got [%.0f,%.0f]", cr.Min, cr.Max)
	}
}

func TestYAxis_PlateauStable_PercentAxis(t *testing.T) {
	rng, _ := computeYAxisRangePercent(5, 80, false)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min != 0 || cr.Max != 100 {
		t.Fatalf("absolute percent axis must be [0,100], got [%.0f,%.0f]", cr.Min, cr.Max)
	}
}
