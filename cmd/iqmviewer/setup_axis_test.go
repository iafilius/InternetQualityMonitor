package main

import (
	"math"
	"testing"

	chart "github.com/wcharczuk/go-chart/v2"
)

// For DNS/TCP/TLS setup times and Plateau Count, we use computeYAxisRange (non-signed).
// In Absolute, axis should anchor to zero unless zoomed by policy; Relative fits band.

func TestYAxis_DNSLookup_Absolute_AnchorsZero(t *testing.T) {
	minY, maxY := 8.0, 42.0
	rng, _ := computeYAxisRange(minY, maxY, false /* absolute */, false /* medianOnly */)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > 0+1e-6 {
		t.Fatalf("expected min anchored at zero, got %.2f", cr.Min)
	}
	if cr.Max <= maxY {
		t.Fatalf("expected headroom above maxY, got %.2f <= %.2f", cr.Max, maxY)
	}
}

func TestYAxis_TCPConnect_Relative_FitsBand(t *testing.T) {
	minY, maxY := 15.0, 30.0
	rng, _ := computeYAxisRange(minY, maxY, true /* relative */, false)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > minY || cr.Max < maxY {
		t.Fatalf("relative should fit band, got [%.2f,%.2f] for data [%.2f,%.2f]", cr.Min, cr.Max, minY, maxY)
	}
}

func TestYAxis_TLSHandshake_Absolute_NoNegative(t *testing.T) {
	// Even if data are tiny, absolute should avoid negative minima
	minY, maxY := 0.1, 1.0
	rng, _ := computeYAxisRange(minY, maxY, false, false)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min < -1e-6 {
		t.Fatalf("absolute should not go negative for unsigned metrics, got min %.2f", cr.Min)
	}
}

func TestYAxis_PlateauCount_Absolute_AnchorsZero(t *testing.T) {
	minY, maxY := 1.0, 6.0
	rng, _ := computeYAxisRange(minY, maxY, false, false)
	cr := rng.(*chart.ContinuousRange)
	if math.Abs(cr.Min-0) > 1e-6 {
		t.Fatalf("expected min anchored at zero, got %.2f", cr.Min)
	}
}
