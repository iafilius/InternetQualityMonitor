package uihelpers

import (
	"math"
	"strconv"
)

// ComputeChartDimensions applies width/height clamp rules used for charts.
// Input: desired raw width (e.g., canvas width). Returns clamped width & height.
func ComputeChartDimensions(rawW int) (int, int) {
	w := rawW
	if w < 800 {
		w = 800
	}
	h := int(float32(w) * 0.33)
	if h < 280 {
		h = 280
	}
	if h > 520 {
		h = 520
	}
	return w, h
}

// ComputeTableColumnWidths returns the 10 column widths for the summary table given a window width.
// Order: RunTag, Count, AvgSpeed, AvgTTFB, Errs, IPv4Speed, IPv4TTFB, IPv6Speed, IPv6TTFB, Quality
func ComputeTableColumnWidths(winW float32) [10]int {
	const compactBreakpoint = 900
	const ultraCompactBreakpoint = 520
	if winW < ultraCompactBreakpoint {
		return [10]int{110, 0, 70, 0, 0, 0, 0, 0, 0, 24}
	}
	if winW < compactBreakpoint {
		if winW < 760 {
			return [10]int{140, 55, 90, 70, 55, 0, 0, 0, 0, 32}
		}
		return [10]int{140, 55, 90, 70, 55, 90, 70, 90, 70, 32}
	}
	return [10]int{220, 70, 130, 100, 70, 120, 110, 120, 110, 60}
}

// ComputeMiniChartHeight derives a reasonable mini-chart height (used for stacked detailed
// session panels) from the full chart height. Ensures readability while conserving vertical space.
// Rules: half the full height but clamped between 180 and 360.
func ComputeMiniChartHeight(fullChartHeight int) int {
	h := fullChartHeight / 2
	if h < 180 {
		h = 180
	}
	if h > 360 {
		h = 360
	}
	return h
}

// BuildTimeAxisTicks returns an approximate set of up to n ticks between 0 and maxDomainSeconds.
// Simplified helper so detailed & average charts can stay visually consistent without duplicating logic.
// It returns slice of float64 tick positions (callers can map to chart.Tick). Falls back to {0,max} when domain small.
func BuildTimeAxisTicks(maxDomainSeconds float64, n int) []float64 {
	if n < 2 || maxDomainSeconds <= 0 {
		return []float64{0, maxDomainSeconds}
	}
	span := maxDomainSeconds
	// target step
	rawStep := span / float64(n-1)
	// normalize to 1,2,2.5,5 * 10^k pattern
	mag := pow10Floor(rawStep)
	norm := rawStep / mag
	step := mag
	switch {
	case norm <= 1:
		step = 1 * mag
	case norm <= 2:
		step = 2 * mag
	case norm <= 2.5:
		step = 2.5 * mag
	case norm <= 5:
		step = 5 * mag
	default:
		step = 10 * mag
	}
	// build ticks
	var out []float64
	for v := 0.0; v <= span+step*0.25; v += step { // small slack for float
		if v < 0 {
			continue
		}
		if v > span && span > 0 {
			v = span
		}
		out = append(out, round6(v))
		if v == span { // avoid extra after clamp
			break
		}
	}
	if len(out) < 2 { // ensure at least two
		out = []float64{0, span}
	}
	return out
}

// pow10Floor returns 10^floor(log10(x)) safeguarding tiny values.
func pow10Floor(x float64) float64 {
	if x <= 0 {
		return 1
	}
	e := 0.0
	e = float64(int64(math.Floor(math.Log10(x))))
	return math.Pow(10, e)
}

// round6 rounds to 6 decimal places to stabilize test comparisons / labels prep.
func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// BuildNumericTicks generates up to n tick marks spanning [min,max] using the same 1,2,2.5,5 pattern.
// Returns slice of raw numeric positions (label formatting left to caller for domain specific units).
func BuildNumericTicks(min, max float64, n int) []float64 {
	if n < 2 || math.IsNaN(min) || math.IsNaN(max) {
		return nil
	}
	if max <= min {
		max = min + 1
	}
	span := max - min
	mag := math.Pow(10, math.Floor(math.Log10(span/float64(n-1))))
	candidates := []float64{1, 2, 2.5, 5, 10}
	bestStep := mag
	bestScore := math.MaxFloat64
	for _, c := range candidates {
		step := c * mag
		count := math.Ceil(span/step) + 1
		if count < 2 {
			count = 2
		}
		diff := math.Abs(count - float64(n))
		if diff < bestScore {
			bestScore = diff
			bestStep = step
		}
	}
	start := math.Floor(min/bestStep) * bestStep
	end := math.Ceil(max/bestStep) * bestStep
	var out []float64
	for v := start; v <= end+bestStep*0.5; v += bestStep {
		out = append(out, round6(v))
	}
	if len(out) < 2 {
		out = []float64{min, max}
	}
	return out
}

// FormatNumericTick provides a compact label similar to original viewer logic.
func FormatNumericTick(v float64) string {
	av := math.Abs(v)
	switch {
	case av >= 100:
		return strconv.FormatInt(int64(math.Round(v)), 10)
	case av >= 10:
		return strconv.FormatFloat(v, 'f', 1, 64)
	case av >= 1:
		return strconv.FormatFloat(v, 'f', 2, 64)
	case av >= 0.01:
		return strconv.FormatFloat(v, 'f', 3, 64)
	default:
		return strconv.FormatFloat(v, 'f', 4, 64)
	}
}
