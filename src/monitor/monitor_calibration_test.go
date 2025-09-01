package monitor

import (
	"math"
	"testing"
	"time"
)

// TestCalibrationAccuracyWithin10Percent ensures the local calibration produces
// observed speeds within 10% of the requested targets under controlled loopback.
func TestCalibrationAccuracyWithin10Percent(t *testing.T) {
	targets := []float64{300, 1000, 3000} // kbps; moderate to avoid resource contention
	// Use a slightly longer duration to reduce timer jitter impact and allow warm-up exclusion
	dur := 800 * time.Millisecond
	cal, err := RunLocalSpeedCalibration(targets, dur)
	if err != nil {
		t.Fatalf("RunLocalSpeedCalibration error: %v", err)
	}
	if len(cal.Ranges) != len(targets) {
		t.Fatalf("unexpected ranges len=%d, want=%d", len(cal.Ranges), len(targets))
	}
	for i, p := range cal.Ranges {
		tgt := targets[i]
		if tgt <= 0 {
			continue
		}
		if p.Samples <= 0 {
			t.Fatalf("target %.0f kbps produced zero samples", tgt)
		}
		if p.ObservedKbps <= 0 {
			t.Fatalf("target %.0f kbps observed=%.2f", tgt, p.ObservedKbps)
		}
		relErr := math.Abs(p.ObservedKbps-tgt) / tgt
		if relErr > 0.10 {
			t.Fatalf("target %.0f kbps observed %.1f kbps (err=%.1f%%) exceeds 10%%", tgt, p.ObservedKbps, relErr*100)
		}
	}
}

// TestCalibrationAccuracyLowRates covers very low targets which are sensitive to timer granularity.
func TestCalibrationAccuracyLowRates(t *testing.T) {
	targets := []float64{10, 30, 100, 300}
	// Longer duration to average out jitter at very low rates
	dur := 1500 * time.Millisecond
	cal, err := RunLocalSpeedCalibration(targets, dur)
	if err != nil {
		t.Fatalf("RunLocalSpeedCalibration error: %v", err)
	}
	if len(cal.Ranges) != len(targets) {
		t.Fatalf("unexpected ranges len=%d, want=%d", len(cal.Ranges), len(targets))
	}
	for i, p := range cal.Ranges {
		tgt := targets[i]
		if p.Samples == 0 {
			t.Fatalf("low-rate target %.0f kbps had zero samples", tgt)
		}
		relErr := math.Abs(p.ObservedKbps-tgt) / tgt
		if relErr > 0.10 {
			t.Fatalf("low-rate target %.0f kbps observed %.2f (err=%.1f%%) > 10%%", tgt, p.ObservedKbps, relErr*100)
		}
	}
}
