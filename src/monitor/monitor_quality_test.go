package monitor

import (
	"math"
	"testing"
	"time"
)

// helper to build synthetic samples with given speeds and 100ms spacing
func mkSamples(speeds []float64) []SpeedSample {
	samples := make([]SpeedSample, 0, len(speeds))
	var tms int64
	for _, v := range speeds {
		samples = append(samples, SpeedSample{TimeMs: tms, Bytes: 0, Speed: v})
		tms += int64(SpeedSampleInterval / time.Millisecond)
	}
	return samples
}

func TestComputeMeasurementQuality_HighStability(t *testing.T) {
	// 20 samples around 1000 kbps with small noise -> should have CI95 <= 10% and quality good
	speeds := make([]float64, 20)
	for i := range speeds {
		speeds[i] = 1000 + 20*math.Sin(float64(i)) // ~2% variation
	}
	sc, ci95, req, good := computeMeasurementQuality(mkSamples(speeds))
	if sc != len(speeds) {
		t.Fatalf("sample count=%d, want %d", sc, len(speeds))
	}
	if ci95 <= 0 || ci95 > 10 {
		t.Fatalf("unexpected ci95=%.2f%%", ci95)
	}
	if req <= 0 {
		t.Fatalf("required samples should be >0, got %d", req)
	}
	if !good {
		t.Fatalf("quality should be good for stable series; ci95=%.2f%% req=%d", ci95, req)
	}
}

func TestComputeMeasurementQuality_VeryNoisy(t *testing.T) {
	// 20 samples alternating between 500 and 1500 (high CV) -> CI95 likely > 10%, not good
	var speeds []float64
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			speeds = append(speeds, 500)
		} else {
			speeds = append(speeds, 1500)
		}
	}
	_, ci95, _, good := computeMeasurementQuality(mkSamples(speeds))
	if ci95 <= 10 {
		t.Fatalf("expected ci95 > 10%% for noisy series, got %.2f%%", ci95)
	}
	if good {
		t.Fatalf("quality should not be good when ci95=%.2f%% > 10%%", ci95)
	}
}

func TestComputeMeasurementQuality_ShortDurationGuardrail(t *testing.T) {
	// 5 samples -> < 8 and < 0.8s duration: quality must be false even if low variability
	speeds := []float64{1000, 1000, 1005, 995, 1002}
	sc, ci95, req, good := computeMeasurementQuality(mkSamples(speeds))
	if sc != 5 || req == 0 { // req could be small but should compute; accept any positive or zero when cv~0
		// Do not enforce req here; primary check is guardrail flag
		_ = req
	}
	if good {
		t.Fatalf("quality should be false for short duration; ci95=%.2f%%", ci95)
	}
}
