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
// variants: "none" or "averages" (controls extra action variants for averages)
// theme: "auto", "dark", or "light" (controls background and overlay styling)
// showDNSLegacy: when true, include dashed legacy dns_time_ms overlay on the DNS chart
// includeSelfTest: when true, include the Local Throughput Self-Test chart
func RunScreenshotsMode(filePath, outDir, situation string, rollingWindow int, showBand bool, batches int, lowSpeedThresholdKbps int, variants string, theme string, showDNSLegacy bool, includeSelfTest bool, includePreTTFB bool) error {
	if filePath == "" {
		filePath = "monitor_results.jsonl"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	// Configure screenshot theme globally for helpers
	t := strings.ToLower(strings.TrimSpace(theme))
	screenshotThemeMode = t
	if screenshotThemeMode == "" {
		screenshotThemeMode = "auto"
	}
	screenshotThemeGlobal = resolveTheme(screenshotThemeMode, nil)
	// Analyze data
	if batches <= 0 {
		batches = 50
	}
	// Respect situation filter unless "All"
	sitFilter := strings.TrimSpace(situation)
	if strings.EqualFold(sitFilter, "all") {
		sitFilter = ""
	}
	if lowSpeedThresholdKbps <= 0 {
		lowSpeedThresholdKbps = 1000
	}
	sums, err := analysis.AnalyzeRecentResultsFullWithOptions(filePath, monitor.SchemaVersion, batches, analysis.AnalyzeOptions{SituationFilter: sitFilter, LowSpeedThresholdKbps: float64(lowSpeedThresholdKbps)})
	if err != nil {
		return err
	}
	st := &uiState{
		filePath:        filePath,
		batchesN:        batches,
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
	// Enable legacy dns overlay in DNS chart if requested
	st.showDNSLegacy = showDNSLegacy
	st.summaries = sums
	// Infer runTag→situation and set desired situation filter
	st.runTagSituation = map[string]string{}
	for _, r := range sums {
		if r.RunTag != "" {
			st.runTagSituation[r.RunTag] = strings.TrimSpace(r.Situation)
		}
	}
	st.situation = strings.TrimSpace(situation)

	// Expanded set for richer documentation and more visual action.
	baseSet := []struct {
		name string
		fn   func(*uiState) image.Image
	}{
		// Averages
		{"speed_avg.png", renderSpeedChart},
		{"ttfb_avg.png", renderTTFBChart},
		// Stability & quality
		{"low_speed_share.png", renderLowSpeedShareChart},
		{"stall_rate.png", renderStallRateChart},
		{"stall_time.png", renderStallTimeChart},
		{"partial_body_rate.png", renderPartialBodyRateChart},
		{"stall_count.png", renderStallCountChart},
		{"jitter.png", renderJitterChart},
		{"cov.png", renderCoVChart},
		{"plateau_count.png", renderPlateauCountChart},
		{"plateau_longest.png", renderPlateauLongestChart},
		{"plateau_stable.png", renderPlateauStableChart},
		// Setup breakdown (connection setup timings)
		{"dns_lookup_time.png", renderDNSLookupChart},
		{"tcp_connect_time.png", renderTCPConnectChart},
		{"tls_handshake_time.png", renderTLSHandshakeChart},
		// Percentiles (Speed)
		{"speed_percentiles_overall.png", func(s *uiState) image.Image { return renderPercentilesChartWithFamily(s, "overall") }},
		{"speed_percentiles_ipv4.png", func(s *uiState) image.Image { return renderPercentilesChartWithFamily(s, "ipv4") }},
		{"speed_percentiles_ipv6.png", func(s *uiState) image.Image { return renderPercentilesChartWithFamily(s, "ipv6") }},
		// Percentiles (TTFB)
		{"ttfb_percentiles_overall.png", func(s *uiState) image.Image { return renderTTFBPercentilesChartWithFamily(s, "overall") }},
		{"ttfb_percentiles_ipv4.png", func(s *uiState) image.Image { return renderTTFBPercentilesChartWithFamily(s, "ipv4") }},
		{"ttfb_percentiles_ipv6.png", func(s *uiState) image.Image { return renderTTFBPercentilesChartWithFamily(s, "ipv6") }},
		// Tail & gaps
		{"tail_heaviness_speed.png", renderTailHeavinessChart},
		{"tail_heaviness_ttfb.png", renderTTFBTailHeavinessChart},
		{"ttfb_p95_p50_gap.png", renderTTFBP95GapChart},
		// Family deltas
		{"delta_speed_abs.png", renderFamilyDeltaSpeedChart},
		{"delta_ttfb_abs.png", renderFamilyDeltaTTFBChart},
		{"delta_speed_pct.png", renderFamilyDeltaSpeedPctChart},
		{"delta_ttfb_pct.png", renderFamilyDeltaTTFBPctChart},
		// SLA & SLA deltas
		{"sla_speed.png", renderSLASpeedChart},
		{"sla_ttfb.png", renderSLATTFBChart},
		{"sla_speed_delta.png", renderSLASpeedDeltaChart},
		{"sla_ttfb_delta.png", renderSLATTFBDeltaChart},
		// Signals
		{"cache_hit_rate.png", renderCacheHitRateChart},
		{"proxy_suspected_rate.png", renderProxySuspectedRateChart},
		{"warm_cache_suspected_rate.png", renderWarmCacheSuspectedRateChart},
		// Errors
		{"error_rate.png", renderErrorRateChart},
		{"error_share_by_http_protocol.png", renderErrorShareByHTTPProtocolChart},
		{"stall_share_by_http_protocol.png", renderStallShareByHTTPProtocolChart},
		{"partial_share_by_http_protocol.png", renderPartialShareByHTTPProtocolChart},
	}

	// Optionally include the Local Throughput Self-Test chart
	if includeSelfTest {
		baseSet = append(baseSet, struct {
			name string
			fn   func(*uiState) image.Image
		}{name: "local_throughput_selftest.png", fn: renderSelfTestChart})
	}

	// Optionally include Pre‑TTFB stall rate if requested
	if includePreTTFB {
		baseSet = append(baseSet, struct {
			name string
			fn   func(*uiState) image.Image
		}{name: "pretffb_stall_rate.png", fn: renderPreTTFBStallRateChart})
	}

	// Use default chart size from chartSize when state.window is nil.
	_ = chart.ColorBlack // silence unused import if chart not referenced elsewhere

	// Helper to write PNGs
	encodeWrite := func(name string, img image.Image) error {
		if img == nil {
			return nil
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return fmt.Errorf("png encode %s: %w", name, err)
		}
		outPath := filepath.Join(outDir, name)
		if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		return nil
	}

	// Render base set in current axis/scale settings
	for _, item := range baseSet {
		if err := encodeWrite(item.name, item.fn(st)); err != nil {
			return err
		}
	}

	// Action variants: time axis and relative scale for averages (more visual dynamics)
	if !strings.EqualFold(strings.TrimSpace(variants), "none") {
		prevXAxis := st.xAxisMode
		st.xAxisMode = "time"
		if err := encodeWrite("speed_avg_time.png", renderSpeedChart(st)); err != nil {
			return err
		}
		if err := encodeWrite("ttfb_avg_time.png", renderTTFBChart(st)); err != nil {
			return err
		}
		st.xAxisMode = prevXAxis

		prevYScale := st.yScaleMode
		st.yScaleMode = "relative"
		if err := encodeWrite("speed_avg_relative.png", renderSpeedChart(st)); err != nil {
			return err
		}
		if err := encodeWrite("ttfb_avg_relative.png", renderTTFBChart(st)); err != nil {
			return err
		}
		st.yScaleMode = prevYScale
	}

	return nil
}
