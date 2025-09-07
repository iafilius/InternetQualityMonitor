//go:build crosshair
// +build crosshair

package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	chart "github.com/wcharczuk/go-chart/v2"
)

// Test crosshair index-mode center positions and nearest-index selection across sizes
func TestIndexModeMapping_CentersAndSelection(t *testing.T) {
	cases := []struct {
		n            int
		imgW, imgH   float32
		viewW, viewH float32
	}{
		{2, 800, 400, 800, 400},
		{10, 800, 400, 1200, 400},
		{54, 800, 400, 1000, 600},
	}
	for _, tc := range cases {
		centers := xCentersIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH)
		if len(centers) != tc.n {
			t.Fatalf("expected %d centers, got %d", tc.n, len(centers))
		}
		// Centers must be strictly increasing
		for i := 1; i < tc.n; i++ {
			if !(centers[i] > centers[i-1]) {
				t.Fatalf("centers not increasing at %d: %.2f <= %.2f", i, centers[i], centers[i-1])
			}
		}
		// Midpoint between centers should select the left index; exact center selects its own index
		for i := 0; i < tc.n; i++ {
			idx := indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, centers[i])
			if idx != i {
				t.Fatalf("exact center selection mismatch: want %d got %d", i, idx)
			}
			if i+1 < tc.n {
				mid := (centers[i] + centers[i+1]) / 2
				idx = indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, mid-0.1)
				if idx != i {
					t.Fatalf("mid-left selection mismatch: want %d got %d", i, idx)
				}
				idx = indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, mid+0.1)
				if idx != i+1 {
					t.Fatalf("mid-right selection mismatch: want %d got %d", i+1, idx)
				}
			}
		}
		// Ends: slightly outside drawn area should clamp to nearest valid index
		left := centers[0]
		right := centers[len(centers)-1]
		for _, x := range []float32{left - 50, left - 1} {
			idx := indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, x)
			if idx != 0 {
				t.Fatalf("left clamp mismatch: want 0 got %d (x=%.2f)", idx, x)
			}
		}
		for _, x := range []float32{right + 1, right + 50} {
			idx := indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, x)
			if idx != tc.n-1 {
				t.Fatalf("right clamp mismatch: want %d got %d (x=%.2f)", tc.n-1, idx, x)
			}
		}
		// Distance monotonicity near a center
		i := int(math.Max(1, float64(tc.n/3)))
		c := centers[i]
		l := indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, c-5)
		r := indexFromMouseIndexMode(tc.n, tc.imgW, tc.imgH, tc.viewW, tc.viewH, c+5)
		if l != i && l != i-1 {
			t.Fatalf("unexpected left neighbor at %d: %d", i, l)
		}
		if r != i && r != i+1 {
			t.Fatalf("unexpected right neighbor at %d: %d", i, r)
		}
	}
}

func TestCrosshair_SnapsAndShowsCorrectContent_IndexMode(t *testing.T) {
	// Simulate 7 batches, ensure snapping exactly to centers and label consistency
	n := 7
	imgW, imgH := float32(800), float32(400)
	viewW, viewH := float32(1000), float32(500)
	centers := xCentersIndexMode(n, imgW, imgH, viewW, viewH)
	rows := make([]analysis.BatchSummary, n)
	for i := 0; i < n; i++ {
		rows[i].RunTag = "run_" + fmt.Sprintf("%02d", i+1)
	}
	// Test exact center and midpoint decisions
	for i := 0; i < n; i++ {
		idx, lineX := snappedIndexAndLineX_IndexMode(n, imgW, imgH, viewW, viewH, centers[i])
		if idx != i {
			t.Fatalf("exact center idx mismatch: want %d got %d", i, idx)
		}
		if math.Abs(float64(lineX-centers[i])) > 0.01 {
			t.Fatalf("lineX not snapped: got %.2f want %.2f", lineX, centers[i])
		}
		// Label must match selected index
		got := labelForIndex(rows, "run_tag", idx)
		want := rows[i].RunTag
		if got != want {
			t.Fatalf("label mismatch at %d: got %q want %q", i, got, want)
		}
		if i+1 < n {
			mid := (centers[i] + centers[i+1]) / 2
			idxL, lineXL := snappedIndexAndLineX_IndexMode(n, imgW, imgH, viewW, viewH, mid-0.1)
			if idxL != i {
				t.Fatalf("mid-left idx mismatch: want %d got %d", i, idxL)
			}
			if math.Abs(float64(lineXL-centers[i])) > 0.01 {
				t.Fatalf("mid-left not snapped to i=%d", i)
			}
			idxR, lineXR := snappedIndexAndLineX_IndexMode(n, imgW, imgH, viewW, viewH, mid+0.1)
			if idxR != i+1 {
				t.Fatalf("mid-right idx mismatch: want %d got %d", i+1, idxR)
			}
			if math.Abs(float64(lineXR-centers[i+1])) > 0.01 {
				t.Fatalf("mid-right not snapped to i+1=%d", i+1)
			}
		}
	}
	// Clamp outside bounds
	idxL, lineXL := snappedIndexAndLineX_IndexMode(n, imgW, imgH, viewW, viewH, centers[0]-100)
	if idxL != 0 || math.Abs(float64(lineXL-centers[0])) > 0.01 {
		t.Fatalf("left clamp mismatch")
	}
	idxR, lineXR := snappedIndexAndLineX_IndexMode(n, imgW, imgH, viewW, viewH, centers[n-1]+100)
	if idxR != n-1 || math.Abs(float64(lineXR-centers[n-1])) > 0.01 {
		t.Fatalf("right clamp mismatch")
	}
}

func TestCrosshair_SnapsAndShowsCorrectContent_TimeMode(t *testing.T) {
	// Create increasing times with a small jitter to mimic real data (renderer normalizes span)
	base := time.Now().Add(-time.Hour)
	times := []time.Time{
		base.Add(0 * time.Second),
		base.Add(10 * time.Second),
		base.Add(20 * time.Second),
		base.Add(35 * time.Second),
		base.Add(60 * time.Second),
	}
	n := len(times)
	imgW, imgH := float32(800), float32(400)
	viewW, viewH := float32(1200), float32(500)
	centers := xCentersTimeMode(times, imgW, imgH, viewW, viewH)
	if len(centers) != n {
		t.Fatalf("expected %d centers, got %d", n, len(centers))
	}
	rows := make([]analysis.BatchSummary, n)
	for i := 0; i < n; i++ {
		rows[i].RunTag = times[i].Format("20060102_150405")
	}
	for i := 0; i < n; i++ {
		idx, lineX := snappedIndexAndLineX_TimeMode(times, imgW, imgH, viewW, viewH, centers[i])
		if idx != i {
			t.Fatalf("time exact center idx mismatch: want %d got %d", i, idx)
		}
		if math.Abs(float64(lineX-centers[i])) > 0.01 {
			t.Fatalf("time lineX not snapped: got %.2f want %.2f", lineX, centers[i])
		}
		got := labelForIndex(rows, "time", idx)
		want := times[i].Format("01-02 15:04:05")
		if got != want {
			t.Fatalf("time label mismatch at %d: got %q want %q", i, got, want)
		}
		if i+1 < n {
			mid := (centers[i] + centers[i+1]) / 2
			idxL, lineXL := snappedIndexAndLineX_TimeMode(times, imgW, imgH, viewW, viewH, mid-0.1)
			if idxL != i {
				t.Fatalf("time mid-left idx mismatch: want %d got %d", i, idxL)
			}
			if math.Abs(float64(lineXL-centers[i])) > 0.01 {
				t.Fatalf("time mid-left not snapped to i=%d", i)
			}
			idxR, lineXR := snappedIndexAndLineX_TimeMode(times, imgW, imgH, viewW, viewH, mid+0.1)
			if idxR != i+1 {
				t.Fatalf("time mid-right idx mismatch: want %d got %d", i+1, idxR)
			}
			if math.Abs(float64(lineXR-centers[i+1])) > 0.01 {
				t.Fatalf("time mid-right not snapped to i+1=%d", i+1)
			}
		}
	}
}

// (removed: batch include/exclude filter tests)

// Render a simple index-mode chart with red dot markers, and detect actual plotted X centers.
func renderIndexModeDotsImage(n, w, h int) (image.Image, []string, error) {
	xs := make([]float64, n)
	ys := make([]float64, n)
	runTags := make([]string, n)
	for i := 0; i < n; i++ {
		xs[i] = float64(i + 1)
		ys[i] = 50
		runTags[i] = fmt.Sprintf("run_%02d", i+1)
	}
	ticks := make([]chart.Tick, 0, n)
	for i := 0; i < n; i++ {
		ticks = append(ticks, chart.Tick{Value: xs[i], Label: runTags[i]})
	}
	ch := chart.Chart{
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: 48}},
		Width:      w,
		Height:     h,
		XAxis:      chart.XAxis{Range: &chart.ContinuousRange{Min: 0.5, Max: float64(n) + 0.5}, Ticks: ticks},
		YAxis:      chart.YAxis{Range: &chart.ContinuousRange{Min: 0, Max: 100}},
		Series: []chart.Series{
			chart.ContinuousSeries{
				XValues: xs,
				YValues: ys,
				Style: chart.Style{
					StrokeWidth: 2,
					StrokeColor: chart.ColorBlue,
					DotWidth:    10,
					DotColor:    chart.ColorRed,
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return nil, nil, err
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return nil, nil, err
	}
	return img, runTags, nil
}

func nearRed(c color.Color) bool {
	r, g, b, a := c.RGBA()
	if a < 0x4000 {
		return false
	}
	// Normalize to 0..255
	R := float64(r >> 8)
	G := float64(g >> 8)
	B := float64(b >> 8)
	// Heuristic: red dominance and not dark blue/green
	if R > 180 && R > G+20 && R > B+20 {
		return true
	}
	// Also accept strong orange hues
	if R > 170 && G > 40 && B < 80 {
		return true
	}
	return false
}

// findDotCentersX finds clusters of red pixels by x column and estimates their centers.
func findDotCentersX(img image.Image) []float64 {
	b := img.Bounds()
	w := b.Dx()
	h := b.Dy()
	colCounts := make([]int, w)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if nearRed(img.At(b.Min.X+x, b.Min.Y+y)) {
				colCounts[x]++
			}
		}
	}
	// Identify clusters separated by gaps with zero counts
	type cluster struct{ start, end int }
	var clusters []cluster
	in := false
	s := 0
	for x := 0; x < w; x++ {
		if colCounts[x] > 0 {
			if !in {
				in = true
				s = x
			}
		} else if in {
			in = false
			clusters = append(clusters, cluster{start: s, end: x - 1})
		}
	}
	if in {
		clusters = append(clusters, cluster{start: s, end: w - 1})
	}
	// Compute weighted centers using counts as weights
	centers := make([]float64, 0, len(clusters))
	for _, c := range clusters {
		sumW := 0
		sumX := 0.0
		for x := c.start; x <= c.end; x++ {
			sumW += colCounts[x]
			sumX += float64(x * colCounts[x])
		}
		if sumW > 0 {
			centers = append(centers, sumX/float64(sumW))
		}
	}
	sort.Float64s(centers)
	return centers
}

func TestCrosshair_RenderedChartAlignment_IndexMode(t *testing.T) {
	n, w, h := 8, 1000, 500
	img, runTags, err := renderIndexModeDotsImage(n, w, h)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	centersImg := findDotCentersX(img)
	if len(centersImg) != n {
		t.Fatalf("expected %d detected centers, got %d", n, len(centersImg))
	}
	// Check snapping and labels at midpoints
	rows := make([]analysis.BatchSummary, n)
	for i := 0; i < n; i++ {
		rows[i].RunTag = runTags[i]
	}
	for i := 0; i+1 < n; i++ {
		mid := float32((centersImg[i] + centersImg[i+1]) / 2)
		// Build expected centers array in view space from detected image pixels
		centersView := make([]float32, n)
		for k := 0; k < n; k++ {
			centersView[k] = float32(centersImg[k])
		}
		// Slightly left of midpoint selects i
		idxL, lineXL := nearestIndexAndLineXFromCenters(centersView, mid-0.1)
		if idxL != i {
			t.Fatalf("snap idx left of midpoint i=%d got %d", i, idxL)
		}
		if math.Abs(float64(lineXL)-centersImg[i]) > 1.0 {
			t.Fatalf("snap lineX left mismatch i=%d", i)
		}
		lbl := labelForIndex(rows, "run_tag", idxL)
		if lbl != runTags[i] {
			t.Fatalf("label left mismatch: got %q want %q", lbl, runTags[i])
		}
		// Slightly right of midpoint selects i+1
		idxR, lineXR := nearestIndexAndLineXFromCenters(centersView, mid+0.1)
		if idxR != i+1 {
			t.Fatalf("snap idx right of midpoint i=%d got %d", i+1, idxR)
		}
		if math.Abs(float64(lineXR)-centersImg[i+1]) > 1.0 {
			t.Fatalf("snap lineX right mismatch i=%d", i+1)
		}
		lblR := labelForIndex(rows, "run_tag", idxR)
		if lblR != runTags[i+1] {
			t.Fatalf("label right mismatch: got %q want %q", lblR, runTags[i+1])
		}
	}
}

// Test oversized geometry helpers for batch host/IP chart.
func TestComputeBatchHostIPGeometryAndFont(t *testing.T) {
	samples := []int{1, 2, 4, 6, 8, 10, 12, 16, 20, 24, 28, 32, 36, 40}
	prevH := 9999
	for _, n := range samples {
		barH, gap := computeBatchHostIPBarGeometry(n)
		if barH > prevH { // Should not grow when n increases
			t.Fatalf("bar height increased for n=%d: %d -> %d", n, prevH, barH)
		}
		if gap <= 0 {
			t.Fatalf("gap <=0 for n=%d", n)
		}
		fs := computeBatchHostIPFontSize(barH)
		if fs <= 0 {
			t.Fatalf("font size invalid for barH=%d", barH)
		}
		// Expect large bars to correlate with large fonts
		if barH >= 64 && fs < 24 {
			t.Fatalf("expected font >=24 for barH=%d got %.1f", barH, fs)
		}
		prevH = barH
	}
	// Idempotence
	b1, g1 := computeBatchHostIPBarGeometry(8)
	b2, g2 := computeBatchHostIPBarGeometry(8)
	if b1 != b2 || g1 != g2 {
		t.Fatalf("geometry not stable for repeated n=8")
	}
}

// TEMP debug helper to print centers; will be removed after fixing mapping
// TestDebug_PrintCenters_IndexMode was a temporary debug helper; removed after calibration stabilized.
