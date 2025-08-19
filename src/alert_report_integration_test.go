package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/arjan/internet-monitor-monitor/src/analysis"
)

// TestWriteAlertJSONComparison ensures comparison block appears when comp provided.
func TestWriteAlertJSONComparison(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "alerts_*.json")
	if err != nil {
		t.Fatalf("tmp: %v", err)
	}
	path := tmp.Name()
	_ = tmp.Close()
	last := analysis.BatchSummary{RunTag: "20250818_120000", Lines: 10, AvgSpeed: 1000, MedianSpeed: 950, AvgTTFB: 100, AvgBytes: 2048, ErrorLines: 1, AvgFirstRTTGoodput: 700, AvgP50Speed: 900, AvgP99P50Ratio: 1.5, AvgPlateauCount: 1, AvgLongestPlateau: 500, AvgJitterPct: 12}
	comp := &struct{ PrevSpeed, PrevTTFB, SpeedDelta, TTFBDelta, ErrorRate float64 }{PrevSpeed: 1200, PrevTTFB: 80, SpeedDelta: -16.7, TTFBDelta: 25, ErrorRate: 10}
	writeAlertJSON(path, 3, last, comp, []string{"speed_drop 16.7% >= 10%"}, 10, 50, 20, 25, 2, 5)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := parsed["comparison"]; !ok {
		t.Fatalf("expected comparison present: %s", string(b))
	}
	if _, ok := parsed["single_batch"]; ok {
		t.Fatalf("did not expect single_batch when comparison present: %s", string(b))
	}
	alerts, ok := parsed["alerts"].([]interface{})
	if !ok || len(alerts) != 1 {
		t.Fatalf("expected 1 alert: %v", parsed["alerts"])
	}
}
