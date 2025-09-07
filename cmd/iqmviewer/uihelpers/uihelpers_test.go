package uihelpers

import (
	"math"
	"testing"
)

func TestComputeChartDimensions(t *testing.T) {
	cases := []struct {
		in    int
		wantW int
	}{
		{100, 800},
		{799, 800},
		{800, 800},
		{1600, 1600},
	}
	for _, c := range cases {
		w, h := ComputeChartDimensions(c.in)
		if w != c.wantW {
			t.Fatalf("input %d => width %d want %d", c.in, w, c.wantW)
		}
		if h < 280 || h > 520 {
			t.Fatalf("height clamp violated for input %d => h=%d", c.in, h)
		}
	}
}

func TestComputeTableColumnWidths(t *testing.T) {
	ultra := ComputeTableColumnWidths(400)
	if ultra != [10]int{110, 0, 70, 0, 0, 0, 0, 0, 0, 24} {
		t.Fatalf("ultra widths mismatch: %#v", ultra)
	}
	compactHide := ComputeTableColumnWidths(700)
	if compactHide[5] != 0 || compactHide[6] != 0 || compactHide[7] != 0 || compactHide[8] != 0 {
		t.Fatalf("expected ipv4/ipv6 hidden at 700: %#v", compactHide)
	}
	compactFull := ComputeTableColumnWidths(850)
	if compactFull[5] == 0 || compactFull[7] == 0 {
		t.Fatalf("expected ipv4/ipv6 visible at 850: %#v", compactFull)
	}
	full := ComputeTableColumnWidths(1200)
	expectedFull := [10]int{220, 70, 130, 100, 70, 120, 110, 120, 110, 60}
	if full != expectedFull {
		t.Fatalf("full widths mismatch got %#v want %#v", full, expectedFull)
	}

	// Edge transitions around breakpoints
	preUltra := ComputeTableColumnWidths(521)
	if preUltra[0] != 140 {
		t.Fatalf("expected compact layout at 521 got %#v", preUltra)
	}
	ultraEdge := ComputeTableColumnWidths(519)
	if ultraEdge[0] != 110 || ultraEdge[2] != 70 {
		t.Fatalf("expected ultra layout at 519 got %#v", ultraEdge)
	}
	preHide := ComputeTableColumnWidths(761)
	if preHide[5] == 0 {
		t.Fatalf("expected ipv4 visible at 761: %#v", preHide)
	}
	postHide := ComputeTableColumnWidths(759)
	if postHide[5] != 0 {
		t.Fatalf("expected ipv4 hidden at 759: %#v", postHide)
	}
	preFull := ComputeTableColumnWidths(901)
	if preFull[0] != 220 {
		t.Fatalf("expected full layout at 901: %#v", preFull)
	}
}

func TestComputeMiniChartHeight(t *testing.T) {
	cases := []struct{ in, wantMin, wantMax int }{
		{100, 180, 180}, // half would be 50 -> clamp up
		{360, 180, 180}, // half 180 exact
		{800, 180, 360}, // half 400 -> clamp down 360
		{520, 180, 260}, // half 260 within range
	}
	for _, c := range cases {
		h := ComputeMiniChartHeight(c.in)
		if h < c.wantMin || h > c.wantMax {
			t.Fatalf("input %d => mini height %d outside expected [%d,%d]", c.in, h, c.wantMin, c.wantMax)
		}
	}
}

func TestBuildTimeAxisTicks(t *testing.T) {
	ticks := BuildTimeAxisTicks(10, 6)
	if len(ticks) < 2 {
		t.Fatalf("expected at least 2 ticks got %v", ticks)
	}
	if ticks[0] != 0 {
		t.Fatalf("first tick should be 0 got %v", ticks[0])
	}
	if last := ticks[len(ticks)-1]; last != 10 {
		t.Fatalf("last tick should equal domain (10) got %v (%v)", last, ticks)
	}
	// very small domain
	tiny := BuildTimeAxisTicks(0.05, 5)
	if tiny[0] != 0 {
		t.Fatalf("tiny domain first tick !=0: %v", tiny)
	}
	lastTiny := tiny[len(tiny)-1]
	if math.Abs(lastTiny-0.05) > 0.011 { // allow rounding/step selection variance
		t.Fatalf("tiny domain last tick not near 0.05 (got %v ticks=%v)", lastTiny, tiny)
	}
	// invalid n
	invalid := BuildTimeAxisTicks(5, 1)
	if len(invalid) != 2 || invalid[0] != 0 || invalid[1] != 5 {
		t.Fatalf("fallback for invalid n failed: %v", invalid)
	}
}

func TestBuildNumericTicksAndFormat(t *testing.T) {
	cases := []struct {
		min, max float64
		n        int
	}{
		{0, 100, 6},
		{0, 1, 5},
		{5, 5.2, 4},
		{-10, 10, 7},
	}
	for _, c := range cases {
		vals := BuildNumericTicks(c.min, c.max, c.n)
		if len(vals) < 2 {
			t.Fatalf("expected >=2 ticks for %#v got %v", c, vals)
		}
		if vals[0] > c.min && math.Abs(vals[0]-c.min) > 1e-6 { // allow start below min but not above
			t.Fatalf("first tick %v should not exceed min %v", vals[0], c.min)
		}
		if last := vals[len(vals)-1]; last < c.max && math.Abs(last-c.max) > 1e-6 { // allow end above max but not below
			t.Fatalf("last tick %v should not be below max %v (vals=%v)", last, c.max, vals)
		}
		// formatting smoke check
		for _, v := range vals {
			_ = FormatNumericTick(v)
		}
	}

	// Specific formatting thresholds
	if got := FormatNumericTick(123.4); got != "123" {
		t.Fatalf("format 123.4 => %q want 123", got)
	}
	if got := FormatNumericTick(12.34); got != "12.3" {
		t.Fatalf("format 12.34 => %q want 12.3", got)
	}
	if got := FormatNumericTick(1.234); got != "1.23" {
		t.Fatalf("format 1.234 => %q want 1.23", got)
	}
	if got := FormatNumericTick(0.1234); got != "0.123" {
		t.Fatalf("format 0.1234 => %q want 0.123", got)
	}
	if got := FormatNumericTick(0.001234); got != "0.0012" {
		t.Fatalf("format 0.001234 => %q want 0.0012", got)
	}
}
