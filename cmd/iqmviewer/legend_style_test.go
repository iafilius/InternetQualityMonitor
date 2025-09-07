package main

import (
	"testing"

	chart "github.com/wcharczuk/go-chart/v2"
)

// TestLegendStyleUniform ensures that when representative charts are constructed, a
// legend style spec is captured and is uniform (prefix, colors, alpha, font size).
func TestLegendStyleUniform(t *testing.T) {
	// Reset slice
	lastLegendSpecs = nil

	// Build two synthetic charts invoking attachLegend directly (faster & deterministic).
	for i := 0; i < 2; i++ {
		c := chart.Chart{Title: "Synthetic"}
		attachLegend(&c)
	}

	if len(lastLegendSpecs) == 0 {
		t.Fatalf("expected legend specs to be captured, got 0")
	}
	// All specs must match the first.
	base := lastLegendSpecs[0]
	for i, spec := range lastLegendSpecs {
		if spec.Prefix != base.Prefix {
			t.Errorf("spec %d prefix mismatch: %q != %q", i, spec.Prefix, base.Prefix)
		}
		if spec.Background != base.Background {
			t.Errorf("spec %d background mismatch", i)
		}
		if spec.Text != base.Text {
			t.Errorf("spec %d text color mismatch", i)
		}
		if spec.FontSize != base.FontSize {
			t.Errorf("spec %d font size mismatch: %d != %d", i, spec.FontSize, base.FontSize)
		}
		if spec.Alpha != base.Alpha {
			t.Errorf("spec %d alpha mismatch: %d != %d", i, spec.Alpha, base.Alpha)
		}

		// Also assert that a synthetic chart includes a first series named with the prefix.
		c := chart.Chart{Title: "Synthetic2"}
		attachLegend(&c)
		if len(c.Series) == 0 || c.Series[0].GetName() != base.Prefix {
			t.Fatalf("expected first series legend prefix %q, got %q", base.Prefix, func() string {
				if len(c.Series) == 0 {
					return "<none>"
				}
				return c.Series[0].GetName()
			}())
		}
	}
}
