//go:build ticks
// +build ticks

package main

import (
	"testing"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
)

// TestBuildXAxisBatch_Unified verifies unified batch axis tick generation caps tick count and includes last.
func TestBuildXAxisBatch_Unified(t *testing.T) {
	rows := make([]analysis.BatchSummary, 37)
	for i := range rows {
		rows[i].RunTag = "RT" + fastItoa(i+1)
	}
	_, _, xs, xa := buildXAxis(rows, "batch")
	if len(xs) != len(rows) {
		t.Fatalf("xs length mismatch: got %d want %d", len(xs), len(rows))
	}
	if len(xa.Ticks) == 0 {
		t.Fatalf("no ticks returned")
	}
	foundLast := false
	for _, tk := range xa.Ticks {
		if int(tk.Value+0.5) == len(rows) {
			foundLast = true
			break
		}
	}
	if !foundLast {
		t.Fatalf("last batch tick missing (n=%d)", len(rows))
	}
	if len(xa.Ticks) > 15 {
		t.Fatalf("too many ticks: %d (expected <=15)", len(xa.Ticks))
	}
}

func TestBuildXAxisBatch_Single(t *testing.T) {
	rows := []analysis.BatchSummary{{RunTag: "Only"}}
	_, _, xs, xa := buildXAxis(rows, "batch")
	if len(xs) != 1 {
		t.Fatalf("xs length: %d", len(xs))
	}
	if xa.Range.GetMax() <= xa.Range.GetMin() {
		t.Fatalf("range not expanded: min=%.2f max=%.2f", xa.Range.GetMin(), xa.Range.GetMax())
	}
}

func TestBuildXAxisRunTag_Mode(t *testing.T) {
	rows := make([]analysis.BatchSummary, 5)
	for i := range rows {
		rows[i].RunTag = fastItoa(i + 1)
	}
	_, _, xs, xa := buildXAxis(rows, "run_tag")
	if len(xs) != len(rows) {
		t.Fatalf("xs mismatch")
	}
	if len(rows) > 1 && len(xa.Ticks) != len(rows) {
		t.Fatalf("expected %d ticks got %d", len(rows), len(xa.Ticks))
	}
}

// fastItoa avoids fmt for tiny speed (not critical but keeps test minimal deps)
func fastItoa(i int) string {
	if i == 0 {
		return "0"
	}
	buf := [16]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
