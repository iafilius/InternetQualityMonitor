package main

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	chart "github.com/wcharczuk/go-chart/v2"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// RunScreenshotsMode renders a curated set of charts and writes them as PNGs under outDir.
// It runs headlessly without creating a UI window.
func RunScreenshotsMode(filePath, outDir, situation string, rollingWindow int, showBand bool) error {
	if filePath == "" {
		filePath = "monitor_results.jsonl"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	// Analyze data
	sums, err := analysis.AnalyzeRecentResultsFullWithOptions(filePath, monitor.SchemaVersion, 50, analysis.AnalyzeOptions{SituationFilter: "", LowSpeedThresholdKbps: 1000})
	if err != nil {
		return err
	}
	st := &uiState{
		filePath:        filePath,
		batchesN:        50,
		xAxisMode:       "batch",
		yScaleMode:      "absolute",
		showOverall:     true,
		showIPv4:        true,
		showIPv6:        true,
		speedUnit:       "kbps",
		showRolling:     true,
		showRollingBand: showBand,
		rollingWindow:   rollingWindow,
		showHints:       false,
	}
	st.summaries = sums
	// Infer runTag→situation and set desired situation filter
	st.runTagSituation = map[string]string{}
	for _, r := range sums {
		if r.RunTag != "" {
			st.runTagSituation[r.RunTag] = strings.TrimSpace(r.Situation)
		}
	}
	st.situation = strings.TrimSpace(situation)

	// Render a representative set: Avg Speed, Avg TTFB, Low-Speed Share, Stall Rate, Stall Time, Stalled Count, Speed Percentiles, TTFB Percentiles, SLA charts.
	toRender := []struct {
		name string
		fn   func(*uiState) image.Image
	}{
		{"speed_avg.png", renderSpeedChart},
		{"ttfb_avg.png", renderTTFBChart},
		{"low_speed_share.png", renderLowSpeedShareChart},
		{"stall_rate.png", renderStallRateChart},
		{"stall_time.png", renderStallTimeChart},
		{"stall_count.png", renderStallCountChart},
		{"sla_speed.png", renderSLASpeedChart},
		{"sla_ttfb.png", renderSLATTFBChart},
	}

	// Use default chart size from chartSize when state.window is nil.
	_ = chart.ColorBlack // silence unused import if chart not referenced elsewhere

	for _, item := range toRender {
		img := item.fn(st)
		if img == nil {
			continue
		}
		// Encode
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return fmt.Errorf("png encode %s: %w", item.name, err)
		}
		outPath := filepath.Join(outDir, item.name)
		if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
	}
	return nil
}
