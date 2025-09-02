package main

import (
	"math"
	"testing"

	chart "github.com/wcharczuk/go-chart/v2"
)

// epsilon for strict inequalities
const eps = 1e-6

// occupancy returns the fraction of the y-scale used by [dataMin,dataMax].
func occupancy(ymin, ymax, dataMin, dataMax float64) float64 {
	if ymax <= ymin {
		return 0
	}
	span := ymax - ymin
	used := dataMax - dataMin
	if used < 0 {
		used = 0
	}
	return used / span
}

// TestYAxis_MedianAbsolute_NoClipping_TTFB ensures TTFB median-only absolute charts
// anchor to zero, do not clip the data or IQR upper bound, and occupy >= 50% of the scale.
func TestYAxis_MedianAbsolute_NoClipping_TTFB(t *testing.T) {
	// Synthetic medians around 2600-2800 ms, with IQR reaching ~2900 ms
	medians := []float64{2400, 2600, 2750, 2800}
	p25s := []float64{2000, 2200, 2300, 2400}
	p75s := []float64{2600, 2800, 2900, 2950}

	// Compute data min/max including IQR bands when median-only
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64
	update := func(vals []float64) {
		for _, v := range vals {
			if math.IsNaN(v) {
				continue
			}
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
		}
	}
	update(medians)
	update(p25s)
	update(p75s)

	rng, _ := computeYAxisRange(minY, maxY, false /*absolute*/, true /*medianOnly*/)
	cr, ok := rng.(*chart.ContinuousRange)
	if !ok {
		t.Fatalf("expected ContinuousRange")
	}
	ymin, ymax := cr.Min, cr.Max

	// Anchor to zero in absolute median-only
	if ymin > 0+eps {
		t.Fatalf("ymin not anchored to zero: got %v", ymin)
	}
	// No clipping of data or IQR upper
	dataMax := maxSlice(medians)
	iqrMax := maxSlice(p75s)
	needMax := math.Max(dataMax, iqrMax)
	if ymax <= needMax+eps {
		t.Fatalf("ymax clips data/iqr: ymax=%v need>%v", ymax, needMax)
	}
	// Occupancy >= 50%
	occ := occupancy(ymin, ymax, 0, dataMax)
	if occ < 0.5 {
		t.Fatalf("occupancy too small: got %.3f want >= 0.5 (y=[%v,%v], dataMax=%v)", occ, ymin, ymax, dataMax)
	}
}

// TestYAxis_MedianAbsolute_NoClipping_Speed mirrors the TTFB test for Speed scale.
func TestYAxis_MedianAbsolute_NoClipping_Speed(t *testing.T) {
	// Synthetic medians around 180k-200k, IQR up to ~210k
	medians := []float64{160000, 180000, 195000, 200000}
	p25s := []float64{120000, 140000, 150000, 160000}
	p75s := []float64{180000, 200000, 205000, 210000}

	minY := math.MaxFloat64
	maxY := -math.MaxFloat64
	update := func(vals []float64) {
		for _, v := range vals {
			if math.IsNaN(v) {
				continue
			}
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
		}
	}
	update(medians)
	update(p25s)
	update(p75s)

	rng, _ := computeYAxisRange(minY, maxY, false /*absolute*/, true /*medianOnly*/)
	cr, ok := rng.(*chart.ContinuousRange)
	if !ok {
		t.Fatalf("expected ContinuousRange")
	}
	ymin, ymax := cr.Min, cr.Max

	if ymin > 0+eps {
		t.Fatalf("ymin not anchored to zero: got %v", ymin)
	}
	dataMax := maxSlice(medians)
	iqrMax := maxSlice(p75s)
	needMax := math.Max(dataMax, iqrMax)
	if ymax <= needMax+eps {
		t.Fatalf("ymax clips data/iqr: ymax=%v need>%v", ymax, needMax)
	}
	occ := occupancy(ymin, ymax, 0, dataMax)
	if occ < 0.5 {
		t.Fatalf("occupancy too small: got %.3f want >= 0.5 (y=[%v,%v], dataMax=%v)", occ, ymin, ymax, dataMax)
	}
}

// maxSlice returns max value in a slice (NaNs ignored). Panics on empty slice.
func maxSlice(vs []float64) float64 {
	m := -math.MaxFloat64
	for _, v := range vs {
		if math.IsNaN(v) {
			continue
		}
		if v > m {
			m = v
		}
	}
	return m
}

// TestYAxis_TwoFamilies_MedianAbsolute_Speed ensures that when exactly two families are visible
// in median-only absolute mode, we still get >=50% occupancy and no clipping when the raw data
// would otherwise cause a tall axis.
func TestYAxis_TwoFamilies_MedianAbsolute_Speed(t *testing.T) {
	// Family A medians around 180k-200k, IQR up to 210k
	fA_meds := []float64{160000, 180000, 195000, 200000}
	fA_p75s := []float64{180000, 200000, 205000, 210000}
	// Family B similar scale, slightly higher, ensure threshold uses the larger family
	fB_meds := []float64{170000, 185000, 198000, 205000}
	fB_p75s := []float64{185000, 202000, 208000, 215000}

	// Compute combined min/max including both families' medians and P75s (median-only behavior includes IQR)
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64
	upd := func(vs []float64) {
		for _, v := range vs {
			if math.IsNaN(v) {
				continue
			}
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
		}
	}
	upd(fA_meds)
	upd(fA_p75s)
	upd(fB_meds)
	upd(fB_p75s)

	rng, _ := computeYAxisRange(minY, maxY, false /*absolute*/, true /*medianOnly*/)
	cr := rng.(*chart.ContinuousRange)
	ymin, ymax := cr.Min, cr.Max
	if ymin > 0+eps {
		t.Fatalf("ymin not anchored to zero: got %v", ymin)
	}
	// no clipping at top for max of medians/p75s
	needMax := math.Max(math.Max(maxSlice(fA_meds), maxSlice(fA_p75s)), math.Max(maxSlice(fB_meds), maxSlice(fB_p75s)))
	if ymax <= needMax+eps {
		t.Fatalf("ymax clips data: ymax=%v need>%v", ymax, needMax)
	}
	// occupancy >= 50% using the larger family's median max
	dataMax := math.Max(maxSlice(fA_meds), maxSlice(fB_meds))
	occ := occupancy(ymin, ymax, 0, dataMax)
	if occ < 0.5 {
		t.Fatalf("occupancy too small: got %.3f want >= 0.5 (y=[%v,%v], dataMax=%v)", occ, ymin, ymax, dataMax)
	}
}

// TestYAxis_TwoFamilies_MedianAbsolute_TTFB mirrors the speed test for TTFB scale.
func TestYAxis_TwoFamilies_MedianAbsolute_TTFB(t *testing.T) {
	// Family A medians around 2400-2800, IQR up to ~2950
	fA_meds := []float64{2400, 2600, 2750, 2800}
	fA_p75s := []float64{2600, 2800, 2900, 2950}
	// Family B slightly higher
	fB_meds := []float64{2500, 2650, 2800, 2850}
	fB_p75s := []float64{2650, 2850, 2950, 3000}

	minY := math.MaxFloat64
	maxY := -math.MaxFloat64
	upd := func(vs []float64) {
		for _, v := range vs {
			if math.IsNaN(v) {
				continue
			}
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
		}
	}
	upd(fA_meds)
	upd(fA_p75s)
	upd(fB_meds)
	upd(fB_p75s)

	rng, _ := computeYAxisRange(minY, maxY, false /*absolute*/, true /*medianOnly*/)
	cr := rng.(*chart.ContinuousRange)
	ymin, ymax := cr.Min, cr.Max
	if ymin > 0+eps {
		t.Fatalf("ymin not anchored to zero: got %v", ymin)
	}
	needMax := math.Max(math.Max(maxSlice(fA_meds), maxSlice(fA_p75s)), math.Max(maxSlice(fB_meds), maxSlice(fB_p75s)))
	if ymax <= needMax+eps {
		t.Fatalf("ymax clips data: ymax=%v need>%v", ymax, needMax)
	}
	dataMax := math.Max(maxSlice(fA_meds), maxSlice(fB_meds))
	occ := occupancy(ymin, ymax, 0, dataMax)
	if occ < 0.5 {
		t.Fatalf("occupancy too small: got %.3f want >= 0.5 (y=[%v,%v], dataMax=%v)", occ, ymin, ymax, dataMax)
	}
}

// TestYAxis_Signed_IncludesZero_Absolute ensures signed metrics include 0 in absolute mode.
func TestYAxis_Signed_IncludesZero_Absolute(t *testing.T) {
	// All positive band should include zero at min
	rng, _ := computeYAxisRangeSigned(10, 20, false)
	cr := rng.(*chart.ContinuousRange)
	if cr.Min > 0+eps {
		t.Fatalf("expected min to include zero, got %v", cr.Min)
	}
	if cr.Max <= 20 {
		t.Fatalf("expected max > data max, got %v", cr.Max)
	}
	// All negative band should include zero at max
	rng, _ = computeYAxisRangeSigned(-20, -5, false)
	cr = rng.(*chart.ContinuousRange)
	if cr.Max < 0-eps {
		t.Fatalf("expected max to include zero, got %v", cr.Max)
	}
}
