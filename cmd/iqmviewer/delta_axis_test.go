package main

import (
	"testing"

	chart "github.com/wcharczuk/go-chart/v2"
)

// These tests validate Y-axis policies for each delta chart individually.
// Requirement: Delta charts (signed metrics) must include zero in Absolute mode and must not clip negative values.
// In Relative mode, the range should fit the observed band without forcing zero.

func TestYAxis_FamilyDeltaTTFBPct_Absolute_IncludesZero_NegativeOnly(t *testing.T) {
	minY, maxY := -30.0, -5.0 // negative-only percent delta
	rng, _ := computeYAxisRangeSigned(minY, maxY, false /* absolute */)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > 0 || cr.Max < 0 {
		t.Fatalf("expected zero included in range, got min=%.2f max=%.2f", cr.Min, cr.Max)
	}
	if cr.Min > minY {
		t.Fatalf("expected min <= %.2f, got %.2f", minY, cr.Min)
	}
}

func TestYAxis_FamilyDeltaTTFBPct_Relative_FitsNegativeBand(t *testing.T) {
	minY, maxY := -30.0, -5.0
	rng, _ := computeYAxisRangeSigned(minY, maxY, true /* relative */)
	cr := rng.(*chart.ContinuousRange)
	// Relative should fit the negative band; zero may be crossed slightly due to padding
	span := maxY - minY
	tol := 0.1 * span // allow up to 10% overshoot towards zero
	if cr.Min > minY {
		t.Fatalf("expected min <= %.2f, got %.2f", minY, cr.Min)
	}
	if cr.Max < maxY {
		t.Fatalf("expected max >= %.2f, got %.2f", maxY, cr.Max)
	}
	if cr.Max > tol {
		t.Fatalf("relative overshoot above zero too large: max=%.2f tol=%.2f", cr.Max, tol)
	}
}

func TestYAxis_FamilyDeltaSpeedPct_Absolute_IncludesZero_PositiveOnly(t *testing.T) {
	minY, maxY := 5.0, 20.0 // positive-only percent delta
	rng, _ := computeYAxisRangeSigned(minY, maxY, false /* absolute */)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > 0 || cr.Max < 0 {
		t.Fatalf("expected zero included in range, got min=%.2f max=%.2f", cr.Min, cr.Max)
	}
	if cr.Max < maxY {
		t.Fatalf("expected max >= %.2f, got %.2f", maxY, cr.Max)
	}
}

func TestYAxis_FamilyDeltaSpeedPct_Relative_FitsPositiveBand(t *testing.T) {
	minY, maxY := 5.0, 20.0
	rng, _ := computeYAxisRangeSigned(minY, maxY, true /* relative */)
	cr := rng.(*chart.ContinuousRange)
	span := maxY - minY
	tol := 0.1 * span // allow up to 10% overshoot below zero
	if cr.Min < -tol {
		t.Fatalf("relative overshoot below zero too large: min=%.2f tol=%.2f", cr.Min, tol)
	}
	if cr.Max < maxY {
		t.Fatalf("expected max >= data max, got max=%.2f dataMax=%.2f", cr.Max, maxY)
	}
}

func TestYAxis_FamilyDeltaTTFBAbs_Absolute_IncludesZero_BothSigns(t *testing.T) {
	minY, maxY := -10.0, 15.0 // ms delta can be both signs
	rng, _ := computeYAxisRangeSigned(minY, maxY, false /* absolute */)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > 0 || cr.Max < 0 {
		t.Fatalf("expected zero included in range for both-signs, got min=%.2f max=%.2f", cr.Min, cr.Max)
	}
}

func TestYAxis_FamilyDeltaSpeedAbs_Absolute_IncludesZero_NegativeOnly(t *testing.T) {
	minY, maxY := -2000.0, -500.0 // speed delta negative-only
	rng, _ := computeYAxisRangeSigned(minY, maxY, false /* absolute */)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > 0 || cr.Max < 0 {
		t.Fatalf("expected zero included in range, got min=%.2f max=%.2f", cr.Min, cr.Max)
	}
}

func TestYAxis_SLA_Deltas_Absolute_IncludesZero(t *testing.T) {
	// Speed SLA pp delta (both signs)
	rng, _ := computeYAxisRangeSigned(-12.0, 8.0, false /* absolute */)
	cr := rng.(*chart.ContinuousRange)
	if !(cr.Min <= 0 && cr.Max >= 0) {
		t.Fatalf("speed SLA delta: expected zero inclusion, got min=%.2f max=%.2f", cr.Min, cr.Max)
	}
	// TTFB SLA pp delta (negative-only)
	rng2, _ := computeYAxisRangeSigned(-25.0, -3.0, false /* absolute */)
	cr2 := rng2.(*chart.ContinuousRange)
	if !(cr2.Min <= 0 && cr2.Max >= 0) {
		t.Fatalf("ttfb SLA delta: expected zero inclusion, got min=%.2f max=%.2f", cr2.Min, cr2.Max)
	}
}
