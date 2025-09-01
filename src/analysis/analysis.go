package analysis

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// isEnterpriseProxy returns true if the proxy name is recognized as an enterprise/security proxy
// as opposed to a server-side CDN/cache. Names are compared in lowercase.
func isEnterpriseProxy(name string) bool {
	switch name {
	case "zscaler", "bluecoat", "netskope", "paloalto", "forcepoint", "squid":
		return true
	}
	// Treat generic web servers as server-side, not enterprise
	if name == "nginx" || name == "apache" || name == "varnish" {
		return false
	}
	// Known CDNs -> server-side
	switch name {
	case "cloudflare", "cloudfront", "fastly", "akamai", "azurecdn", "cachefly", "google":
		return false
	}
	return false
}

// BatchSummary captures aggregate metrics for one run_tag batch.
type BatchSummary struct {
	RunTag      string  `json:"run_tag"`
	Situation   string  `json:"situation,omitempty"`
	Lines       int     `json:"lines"`
	AvgSpeed    float64 `json:"avg_speed_kbps"`
	MedianSpeed float64 `json:"median_speed_kbps"`
	MinSpeed    float64 `json:"min_speed_kbps,omitempty"`
	MaxSpeed    float64 `json:"max_speed_kbps,omitempty"`
	AvgTTFB     float64 `json:"avg_ttfb_ms"`
	// Cross-line TTFB percentiles
	AvgP25TTFBMs       float64 `json:"avg_ttfb_p25_ms,omitempty"`
	AvgP75TTFBMs       float64 `json:"avg_ttfb_p75_ms,omitempty"`
	MinTTFBMs          float64 `json:"min_ttfb_ms,omitempty"`
	MaxTTFBMs          float64 `json:"max_ttfb_ms,omitempty"`
	AvgBytes           float64 `json:"avg_bytes"`
	ErrorLines         int     `json:"error_lines"`
	AvgFirstRTTGoodput float64 `json:"avg_first_rtt_goodput_kbps"`
	AvgP50Speed        float64 `json:"avg_p50_kbps"`
	AvgP99P50Ratio     float64 `json:"avg_p99_p50_ratio"`
	AvgPlateauCount    float64 `json:"avg_plateau_count"`
	AvgLongestPlateau  float64 `json:"avg_longest_plateau_ms"`
	AvgJitterPct       float64 `json:"avg_jitter_mean_abs_pct"`
	BatchDurationMs    int64   `json:"batch_duration_ms,omitempty"`
	// New: connection setup breakdown averages (ms)
	AvgDNSMs        float64 `json:"avg_dns_ms,omitempty"`
	AvgConnectMs    float64 `json:"avg_connect_ms,omitempty"`
	AvgTLSHandshake float64 `json:"avg_tls_handshake_ms,omitempty"`
	// Legacy-only averages to enable comparison overlays in the UI
	// For DNS, this captures the legacy pre-resolve field dns_time_ms when present
	AvgDNSLegacyMs float64 `json:"avg_dns_legacy_ms,omitempty"`
	// Extended aggregated metrics (averages or rates over successful lines)
	AvgP90Speed float64 `json:"avg_p90_kbps,omitempty"`
	AvgP95Speed float64 `json:"avg_p95_kbps,omitempty"`
	AvgP99Speed float64 `json:"avg_p99_kbps,omitempty"`
	// Cross-line Speed percentiles
	AvgP25Speed           float64 `json:"avg_p25_kbps,omitempty"`
	AvgP75Speed           float64 `json:"avg_p75_kbps,omitempty"`
	AvgSlopeKbpsPerSec    float64 `json:"avg_slope_kbps_per_sec,omitempty"`
	AvgCoefVariationPct   float64 `json:"avg_coef_variation_pct,omitempty"`
	CacheHitRatePct       float64 `json:"cache_hit_rate_pct,omitempty"`
	ProxySuspectedRatePct float64 `json:"proxy_suspected_rate_pct,omitempty"`
	// New: split proxy classifications
	EnterpriseProxyRatePct    float64 `json:"enterprise_proxy_rate_pct,omitempty"`
	ServerProxyRatePct        float64 `json:"server_proxy_rate_pct,omitempty"`
	IPMismatchRatePct         float64 `json:"ip_mismatch_rate_pct,omitempty"`
	PrefetchSuspectedRatePct  float64 `json:"prefetch_suspected_rate_pct,omitempty"`
	WarmCacheSuspectedRatePct float64 `json:"warm_cache_suspected_rate_pct,omitempty"`
	ConnReuseRatePct          float64 `json:"conn_reuse_rate_pct,omitempty"`
	PlateauStableRatePct      float64 `json:"plateau_stable_rate_pct,omitempty"`
	AvgHeadGetTimeRatio       float64 `json:"avg_head_get_time_ratio,omitempty"`
	// Stability & quality
	LowSpeedTimeSharePct float64 `json:"low_speed_time_share_pct,omitempty"` // weighted by transfer time; threshold-controlled
	StallRatePct         float64 `json:"stall_rate_pct,omitempty"`
	PartialBodyRatePct   float64 `json:"partial_body_rate_pct,omitempty"`
	AvgStallElapsedMs    float64 `json:"avg_stall_elapsed_ms,omitempty"`
	// Micro-stalls (derived from speed samples)
	MicroStallRatePct  float64 `json:"micro_stall_rate_pct,omitempty"`  // lines with >=1 micro-stall over all lines
	AvgMicroStallCount float64 `json:"avg_micro_stall_count,omitempty"` // average count per line among all lines
	AvgMicroStallMs    float64 `json:"avg_micro_stall_ms,omitempty"`    // average total ms per line among lines with at least one micro-stall
	// Optional: rate of requests aborted before the first byte due to pre-TTFB stall watchdog
	PreTTFBStallRatePct float64 `json:"pretffb_stall_rate_pct,omitempty"`
	// Measurement quality (unknown true speed) derived from intra-transfer samples (latest line in batch)
	SampleCount                 int     `json:"sample_count,omitempty"`
	CI95RelMoEPct               float64 `json:"ci95_rel_moe_pct,omitempty"`
	RequiredSamplesFor10Pct95CI int     `json:"required_samples_for_10pct_95ci,omitempty"`
	QualityGood                 bool    `json:"quality_good,omitempty"`
	// TTFB percentiles (ms) computed per batch across lines
	AvgP50TTFBMs float64 `json:"avg_ttfb_p50_ms,omitempty"`
	AvgP90TTFBMs float64 `json:"avg_ttfb_p90_ms,omitempty"`
	AvgP95TTFBMs float64 `json:"avg_ttfb_p95_ms,omitempty"`
	AvgP99TTFBMs float64 `json:"avg_ttfb_p99_ms,omitempty"`
	// Local environment baseline (from meta; reflects latest seen in the batch)
	LocalSelfTestKbps float64 `json:"local_selftest_kbps,omitempty"`
	// Host and system diagnostics (best-effort; latest seen in batch)
	Hostname           string  `json:"hostname,omitempty"`
	NumCPU             int     `json:"num_cpu,omitempty"`
	LoadAvg1           float64 `json:"load_avg_1,omitempty"`
	LoadAvg5           float64 `json:"load_avg_5,omitempty"`
	LoadAvg15          float64 `json:"load_avg_15,omitempty"`
	MemTotalBytes      float64 `json:"mem_total_bytes,omitempty"`
	MemFreeOrAvailable float64 `json:"mem_free_or_available_bytes,omitempty"`
	DiskRootTotalBytes float64 `json:"disk_root_total_bytes,omitempty"`
	DiskRootFreeBytes  float64 `json:"disk_root_free_bytes,omitempty"`
	// Calibration rollup
	CalibrationMaxKbps      float64   `json:"calibration_max_kbps,omitempty"`
	CalibrationRangesTarget []float64 `json:"calibration_ranges_target_kbps,omitempty"`
	CalibrationRangesObs    []float64 `json:"calibration_ranges_observed_kbps,omitempty"`
	CalibrationRangesErrPct []float64 `json:"calibration_ranges_error_pct,omitempty"`
	CalibrationSamples      []int     `json:"calibration_samples,omitempty"`
	// Network diagnostics (best-effort): reflect the most recent non-empty values within the batch
	DNSServer        string `json:"dns_server,omitempty"`
	DNSServerNetwork string `json:"dns_server_network,omitempty"`
	NextHop          string `json:"next_hop,omitempty"`
	NextHopSource    string `json:"next_hop_source,omitempty"`
	// Representative URL from this batch (most recent non-empty); useful for tooling like curl copy in the viewer
	SampleURL string `json:"sample_url,omitempty"`
	// Raw count fields (not serialized) retained to enable higher-level aggregation (overall across batches)
	CacheHitLines           int `json:"-"`
	ProxySuspectedLines     int `json:"-"`
	EnterpriseProxyLines    int `json:"-"`
	ServerProxyLines        int `json:"-"`
	IPMismatchLines         int `json:"-"`
	PrefetchSuspectedLines  int `json:"-"`
	WarmCacheSuspectedLines int `json:"-"`
	ConnReuseLines          int `json:"-"`
	PlateauStableLines      int `json:"-"`
	// Per-IP-family breakdown (same metrics as above but limited to that family)
	IPv4 *FamilySummary `json:"ipv4,omitempty"`
	IPv6 *FamilySummary `json:"ipv6,omitempty"`
	// Proxy aggregation (counts / rates)
	ProxyUsedLines         int                `json:"proxy_used_lines,omitempty"`
	ProxyUsingEnvLines     int                `json:"proxy_using_env_lines,omitempty"`
	ProxyNameCounts        map[string]int     `json:"proxy_name_counts,omitempty"`
	ProxyNameRatePct       map[string]float64 `json:"proxy_name_rate_pct,omitempty"`
	EnvProxyUsageRatePct   float64            `json:"env_proxy_usage_rate_pct,omitempty"`
	ClassifiedProxyRatePct float64            `json:"classified_proxy_rate_pct,omitempty"`
	// Protocol/TLS/encoding rollups
	HTTPProtocolCounts         map[string]int     `json:"http_protocol_counts,omitempty"`
	HTTPProtocolRatePct        map[string]float64 `json:"http_protocol_rate_pct,omitempty"`
	AvgSpeedByHTTPProtocolKbps map[string]float64 `json:"avg_speed_by_http_protocol_kbps,omitempty"`
	StallRateByHTTPProtocolPct map[string]float64 `json:"stall_rate_by_http_protocol_pct,omitempty"`
	ErrorRateByHTTPProtocolPct map[string]float64 `json:"error_rate_by_http_protocol_pct,omitempty"`
	// Share of all errors attributed to each HTTP protocol (sums to ~100% when there are errors)
	ErrorShareByHTTPProtocolPct map[string]float64 `json:"error_share_by_http_protocol_pct,omitempty"`
	// Share of all stalls attributed to each HTTP protocol (sums to ~100% when there are stalls)
	StallShareByHTTPProtocolPct map[string]float64 `json:"stall_share_by_http_protocol_pct,omitempty"`
	// Share of all partial body results attributed to each HTTP protocol (sums to ~100% when there are partials)
	PartialShareByHTTPProtocolPct    map[string]float64 `json:"partial_share_by_http_protocol_pct,omitempty"`
	PartialBodyRateByHTTPProtocolPct map[string]float64 `json:"partial_body_rate_by_http_protocol_pct,omitempty"`
	TLSVersionCounts                 map[string]int     `json:"tls_version_counts,omitempty"`
	TLSVersionRatePct                map[string]float64 `json:"tls_version_rate_pct,omitempty"`
	ALPNCounts                       map[string]int     `json:"alpn_counts,omitempty"`
	ALPNRatePct                      map[string]float64 `json:"alpn_rate_pct,omitempty"`
	ChunkedRatePct                   float64            `json:"chunked_rate_pct,omitempty"`
}

// FamilySummary mirrors BatchSummary's metric fields for a single IP family subset.
type FamilySummary struct {
	Lines       int     `json:"lines"`
	AvgSpeed    float64 `json:"avg_speed_kbps"`
	MedianSpeed float64 `json:"median_speed_kbps"`
	MinSpeed    float64 `json:"min_speed_kbps,omitempty"`
	MaxSpeed    float64 `json:"max_speed_kbps,omitempty"`
	AvgTTFB     float64 `json:"avg_ttfb_ms"`
	// Cross-line TTFB percentiles
	AvgP25TTFBMs       float64 `json:"avg_ttfb_p25_ms,omitempty"`
	AvgP75TTFBMs       float64 `json:"avg_ttfb_p75_ms,omitempty"`
	MinTTFBMs          float64 `json:"min_ttfb_ms,omitempty"`
	MaxTTFBMs          float64 `json:"max_ttfb_ms,omitempty"`
	AvgBytes           float64 `json:"avg_bytes"`
	ErrorLines         int     `json:"error_lines"`
	AvgFirstRTTGoodput float64 `json:"avg_first_rtt_goodput_kbps"`
	AvgP50Speed        float64 `json:"avg_p50_kbps"`
	AvgP99P50Ratio     float64 `json:"avg_p99_p50_ratio"`
	AvgPlateauCount    float64 `json:"avg_plateau_count"`
	AvgLongestPlateau  float64 `json:"avg_longest_plateau_ms"`
	AvgJitterPct       float64 `json:"avg_jitter_mean_abs_pct"`
	BatchDurationMs    int64   `json:"batch_duration_ms,omitempty"`
	// New: connection setup breakdown averages (ms)
	AvgDNSMs        float64 `json:"avg_dns_ms,omitempty"`
	AvgConnectMs    float64 `json:"avg_connect_ms,omitempty"`
	AvgTLSHandshake float64 `json:"avg_tls_handshake_ms,omitempty"`
	// Legacy-only averages to enable comparison overlays in the UI
	AvgDNSLegacyMs float64 `json:"avg_dns_legacy_ms,omitempty"`
	AvgP90Speed    float64 `json:"avg_p90_kbps,omitempty"`
	AvgP95Speed    float64 `json:"avg_p95_kbps,omitempty"`
	AvgP99Speed    float64 `json:"avg_p99_kbps,omitempty"`
	// Cross-line Speed percentiles
	AvgP25Speed           float64 `json:"avg_p25_kbps,omitempty"`
	AvgP75Speed           float64 `json:"avg_p75_kbps,omitempty"`
	AvgSlopeKbpsPerSec    float64 `json:"avg_slope_kbps_per_sec,omitempty"`
	AvgCoefVariationPct   float64 `json:"avg_coef_variation_pct,omitempty"`
	CacheHitRatePct       float64 `json:"cache_hit_rate_pct,omitempty"`
	ProxySuspectedRatePct float64 `json:"proxy_suspected_rate_pct,omitempty"`
	// New: split proxy classifications
	EnterpriseProxyRatePct    float64 `json:"enterprise_proxy_rate_pct,omitempty"`
	ServerProxyRatePct        float64 `json:"server_proxy_rate_pct,omitempty"`
	IPMismatchRatePct         float64 `json:"ip_mismatch_rate_pct,omitempty"`
	PrefetchSuspectedRatePct  float64 `json:"prefetch_suspected_rate_pct,omitempty"`
	WarmCacheSuspectedRatePct float64 `json:"warm_cache_suspected_rate_pct,omitempty"`
	ConnReuseRatePct          float64 `json:"conn_reuse_rate_pct,omitempty"`
	PlateauStableRatePct      float64 `json:"plateau_stable_rate_pct,omitempty"`
	AvgHeadGetTimeRatio       float64 `json:"avg_head_get_time_ratio,omitempty"`
	// Stability & quality
	LowSpeedTimeSharePct float64 `json:"low_speed_time_share_pct,omitempty"`
	StallRatePct         float64 `json:"stall_rate_pct,omitempty"`
	PartialBodyRatePct   float64 `json:"partial_body_rate_pct,omitempty"`
	AvgStallElapsedMs    float64 `json:"avg_stall_elapsed_ms,omitempty"`
	// Micro-stalls (derived from speed samples)
	MicroStallRatePct  float64 `json:"micro_stall_rate_pct,omitempty"`  // lines with >=1 micro-stall over all lines in family
	AvgMicroStallCount float64 `json:"avg_micro_stall_count,omitempty"` // average count per line among all lines
	AvgMicroStallMs    float64 `json:"avg_micro_stall_ms,omitempty"`    // average total ms per line among lines with at least one micro-stall
	// Optional: rate of requests aborted before the first byte due to pre-TTFB stall watchdog
	PreTTFBStallRatePct float64 `json:"pretffb_stall_rate_pct,omitempty"`
	// TTFB percentiles (ms) computed per batch across lines in this family
	AvgP50TTFBMs float64 `json:"avg_ttfb_p50_ms,omitempty"`
	AvgP90TTFBMs float64 `json:"avg_ttfb_p90_ms,omitempty"`
	AvgP95TTFBMs float64 `json:"avg_ttfb_p95_ms,omitempty"`
	AvgP99TTFBMs float64 `json:"avg_ttfb_p99_ms,omitempty"`
}

// AnalyzeRecentResults parses the results file and returns the most recent up to MaxBatches batch summaries.
// Thin wrapper over AnalyzeRecentResultsFull.
func AnalyzeRecentResults(path string, schemaVersion, MaxBatches int) ([]BatchSummary, error) {
	return AnalyzeRecentResultsFull(path, schemaVersion, MaxBatches, "")
}

// AnalyzeRecentResultsFull parses the results file and computes extended batch metrics.
// MaxBatches limits how many recent batches are returned (0 or negative -> default 10).
// AnalyzeOptions controls extended calculations.
type AnalyzeOptions struct {
	SituationFilter       string
	LowSpeedThresholdKbps float64 // if >0, compute LowSpeedTimeSharePct using this threshold
	// If >0, detect short transfer pauses ("micro-stalls") using TransferSpeedSamples.
	// Micro‑stalls are brief pauses where transfer resumes later (distinct from hard stall timeouts/aborts).
	// Definition: contiguous gap where cumulative bytes do not increase for at least this many milliseconds.
	// Recommended default: 500 ms.
	MicroStallMinGapMs int64
}

// AnalyzeRecentResultsFullWithOptions parses results and computes extended batch metrics with options.
func AnalyzeRecentResultsFullWithOptions(path string, schemaVersion, MaxBatches int, opts AnalyzeOptions) ([]BatchSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opts.SituationFilter != "" {
		fmt.Printf("[analysis] reading results from %s (schema_version=%d, max_batches=%d, situation=\"%s\")\n", path, schemaVersion, MaxBatches, opts.SituationFilter)
	} else {
		fmt.Printf("[analysis] reading results from %s (schema_version=%d, max_batches=%d, situation=ALL)\n", path, schemaVersion, MaxBatches)
	}
	// Use a dynamic reader to handle long JSONL lines without a fixed max token size.
	// Defensive cap per-line to avoid pathological memory spikes.
	reader := bufio.NewReader(f)
	const MaxLineBytes = 200 * 1024 * 1024 // 200MB; increase here if you truly need larger lines
	type rec struct {
		runTag             string
		situation          string
		ipFamily           string
		proxyName          string
		usingEnvProxy      bool
		timestamp          time.Time
		speed, ttfb, bytes float64
		firstRTT           float64
		url                string
		p50, p90, p95, p99 float64
		plateauCount       float64
		longestPlateau     float64
		jitterPct          float64
		slope              float64
		coefVarPct         float64
		headGetRatio       float64
		cachePresent       bool
		proxySuspected     bool
		proxyNameLower     string
		usingProxyEndpoint bool
		ipMismatch         bool
		prefetchSuspected  bool
		warmCacheSuspected bool
		connReused         bool
		plateauStable      bool
		hasError           bool
		partialBody        bool
		// meta
		localSelfKbps float64
		hostname      string
		numCPU        int
		load1         float64
		load5         float64
		load15        float64
		memTotal      float64
		memFree       float64
		diskTotal     float64
		diskFree      float64
		calibMax      float64
		calibTargets  []float64
		calibObserved []float64
		calibErrPct   []float64
		calibSamples  []int
		// protocol/tls/encoding
		httpProto string
		tlsVer    string
		alpn      string
		chunked   bool
		// stability
		stalled        bool
		stallElapsedMs int64
		preTTFBStall   bool
		sampleLowMs    int64
		sampleTotalMs  int64
		// micro-stalls derived from samples
		microStallCount   int
		microStallTotalMs int64
		microStallPresent bool
		// connection setup timings (ms)
		dnsMs       float64
		dnsLegacyMs float64 // raw legacy dns_time_ms if present
		connMs      float64
		tlsMs       float64
		// network diagnostics
		// measurement quality (from SpeedAnalysis)
		mqSampleCount int
		mqCI95RelMoE  float64
		mqReqN10Pct   int
		mqGood        bool
		// network diagnostics
		dnsServer  string
		dnsNet     string
		nextHop    string
		nextHopSrc string
	}
	// Phase 1: scan the JSONL results file and extract only the typed envelope lines
	// matching the requested schemaVersion. Each valid line becomes a lightweight
	// 'rec' containing only the numeric fields needed for aggregation. We avoid
	// retaining full structs / raw maps to keep memory usage low when the file is large.
	var records []rec
readLoop:
	for {
		// Accumulate one logical line (may span multiple internal buffers)
		var line []byte
		for {
			part, rerr := reader.ReadBytes('\n')
			if len(part) > 0 {
				if len(line)+len(part) > MaxLineBytes {
					return nil, fmt.Errorf("line too large: %d bytes exceeds limit %d in %s (bump MaxLineBytes in src/analysis/analysis.go if needed)", len(line)+len(part), MaxLineBytes, path)
				}
				line = append(line, part...)
			}
			if rerr == nil {
				break // finished one line with newline
			}
			if errors.Is(rerr, io.EOF) {
				// Handle final line without newline
				if len(line) == 0 {
					break readLoop
				}
				break
			}
			if errors.Is(rerr, bufio.ErrBufferFull) {
				// continue accumulating
				continue
			}
			// Other I/O error: warn and stop processing
			fmt.Printf("[analysis] read warning: %v (file=%s)\n", rerr, path)
			if len(line) == 0 {
				break readLoop
			}
			break
		}
		var env monitor.ResultEnvelope
		if err := json.Unmarshal(line, &env); err != nil || env.Meta == nil || env.SiteResult == nil {
			continue
		}
		if env.Meta.SchemaVersion != schemaVersion {
			continue
		}
		if env.Meta.RunTag == "" { // require explicit run_tag; skip otherwise
			continue
		}
		if opts.SituationFilter != "" && !strings.EqualFold(env.Meta.Situation, opts.SituationFilter) {
			continue
		}
		sr := env.SiteResult
		var ts time.Time
		if env.Meta.TimestampUTC != "" {
			if parsed, perr := time.Parse(time.RFC3339Nano, env.Meta.TimestampUTC); perr == nil {
				ts = parsed
			}
		}
		bs := rec{runTag: env.Meta.RunTag, situation: env.Meta.Situation, ipFamily: sr.IPFamily, proxyName: sr.ProxyName, usingEnvProxy: sr.UsingEnvProxy, timestamp: ts, speed: sr.TransferSpeedKbps, ttfb: float64(sr.TraceTTFBMs), bytes: float64(sr.TransferSizeBytes), firstRTT: sr.FirstRTTGoodputKbps, url: sr.URL}
		// capture meta self-test baseline if present
		if env.Meta.LocalSelfTestKbps > 0 {
			bs.localSelfKbps = env.Meta.LocalSelfTestKbps
		}
		// capture host/system diagnostics (latest wins later)
		if env.Meta.Hostname != "" {
			bs.hostname = env.Meta.Hostname
		}
		if env.Meta.NumCPU > 0 {
			bs.numCPU = env.Meta.NumCPU
		}
		if env.Meta.LoadAvg1 > 0 {
			bs.load1 = env.Meta.LoadAvg1
			bs.load5 = env.Meta.LoadAvg5
			bs.load15 = env.Meta.LoadAvg15
		}
		if env.Meta.MemTotalBytes > 0 {
			bs.memTotal = float64(env.Meta.MemTotalBytes)
		}
		if env.Meta.MemFreeOrAvailable > 0 {
			bs.memFree = float64(env.Meta.MemFreeOrAvailable)
		}
		if env.Meta.DiskRootTotalBytes > 0 {
			bs.diskTotal = float64(env.Meta.DiskRootTotalBytes)
		}
		if env.Meta.DiskRootFreeBytes > 0 {
			bs.diskFree = float64(env.Meta.DiskRootFreeBytes)
		}
		// capture calibration if present
		if env.Meta.Calibration != nil {
			if env.Meta.Calibration.MaxKbps > 0 {
				bs.calibMax = env.Meta.Calibration.MaxKbps
			}
			if len(env.Meta.Calibration.Ranges) > 0 {
				for _, p := range env.Meta.Calibration.Ranges {
					bs.calibTargets = append(bs.calibTargets, p.TargetKbps)
					bs.calibObserved = append(bs.calibObserved, p.ObservedKbps)
					bs.calibErrPct = append(bs.calibErrPct, p.ErrorPct)
					bs.calibSamples = append(bs.calibSamples, p.Samples)
				}
			}
		}
		// Track error presence without storing the raw line to reduce memory usage.
		if bytes.Contains(line, []byte("tcp_error")) || bytes.Contains(line, []byte("http_error")) {
			bs.hasError = true
		}
		// detect partial body/incomplete transfers independent of SpeedAnalysis presence
		if sr.ContentLengthMismatch {
			bs.partialBody = true
		} else if sr.HTTPError != "" {
			he := strings.ToLower(strings.TrimSpace(sr.HTTPError))
			if strings.Contains(he, "partial_body") {
				bs.partialBody = true
			}
		}
		if sa := sr.SpeedAnalysis; sa != nil {
			bs.p50 = sa.P50Kbps
			if sa.P99Kbps > 0 {
				bs.p99 = sa.P99Kbps
			}
			// measurement quality
			if sa.SampleCount > 0 {
				bs.mqSampleCount = sa.SampleCount
			}
			if sa.CI95RelMoEPct > 0 {
				bs.mqCI95RelMoE = sa.CI95RelMoEPct
			}
			if sa.RequiredSamplesFor10Pct95CI > 0 {
				bs.mqReqN10Pct = sa.RequiredSamplesFor10Pct95CI
			}
			if sa.QualityGood {
				bs.mqGood = true
			}
			bs.plateauCount = float64(sa.PlateauCount)
			bs.longestPlateau = float64(sa.LongestPlateauMs)
			if sa.JitterMeanAbsPct > 0 {
				bs.jitterPct = sa.JitterMeanAbsPct * 100 // store as percent
			}
			bs.p90 = sa.P90Kbps
			bs.p95 = sa.P95Kbps
			bs.slope = sa.SlopeKbpsPerSec
			if sa.CoefVariation > 0 {
				bs.coefVarPct = sa.CoefVariation * 100
			}
			bs.plateauStable = sa.PlateauStable
		}
		// detect pre-TTFB stall marker set by monitor when optional env flag is enabled
		if sr.HTTPError != "" {
			he := strings.ToLower(strings.TrimSpace(sr.HTTPError))
			if strings.Contains(he, "stall_pre_ttfb") {
				bs.preTTFBStall = true
			}
		}
		// trace timings
		// Setup timings (prefer httptrace-derived fields; fallback to legacy scalars if missing)
		if sr.TraceDNSMs > 0 {
			bs.dnsMs = float64(sr.TraceDNSMs)
		} else if sr.DNSTimeMs > 0 {
			bs.dnsMs = float64(sr.DNSTimeMs)
		}
		// Always capture legacy dns_time_ms separately for overlay comparisons
		if sr.DNSTimeMs > 0 {
			bs.dnsLegacyMs = float64(sr.DNSTimeMs)
		}
		if sr.TraceConnectMs > 0 {
			bs.connMs = float64(sr.TraceConnectMs)
		} else if sr.TCPTimeMs > 0 {
			bs.connMs = float64(sr.TCPTimeMs)
		} else if sr.HTTPConnectTimeMs > 0 {
			bs.connMs = float64(sr.HTTPConnectTimeMs)
		}
		if sr.TraceTLSMs > 0 {
			bs.tlsMs = float64(sr.TraceTLSMs)
		} else if sr.SSLHandshakeTimeMs > 0 {
			bs.tlsMs = float64(sr.SSLHandshakeTimeMs)
		}
		// stalls
		if sr.TransferStalled {
			bs.stalled = true
		}
		if sr.StallElapsedMs > 0 {
			bs.stallElapsedMs = sr.StallElapsedMs
		}
		// low-speed time share based on samples and configured threshold
		if (opts.LowSpeedThresholdKbps > 0 || opts.MicroStallMinGapMs > 0) && len(sr.TransferSpeedSamples) > 0 {
			// Each sample approximates one interval; use monitor.SpeedSampleInterval
			intervalMs := int64(monitor.SpeedSampleInterval / time.Millisecond)
			var lowCount int64
			// For micro-stalls, detect contiguous spans where cumulative bytes do not increase
			// (i.e., Bytes stays the same) and the span duration >= MicroStallMinGapMs.
			var microCnt int
			var microTotal int64
			if opts.LowSpeedThresholdKbps > 0 {
				for _, s := range sr.TransferSpeedSamples {
					if s.Speed > 0 && s.Speed < opts.LowSpeedThresholdKbps {
						lowCount++
					}
				}
			}
			if opts.MicroStallMinGapMs > 0 {
				// Walk samples and accumulate run-length of zero-byte progress.
				// We rely on cumulative Bytes; treat non-increasing as no progress.
				var runStartIdx = -1
				for i := 1; i < len(sr.TransferSpeedSamples); i++ {
					prev := sr.TransferSpeedSamples[i-1]
					cur := sr.TransferSpeedSamples[i]
					noProgress := cur.Bytes <= prev.Bytes
					if noProgress {
						if runStartIdx == -1 {
							runStartIdx = i - 1
						}
					}
					if !noProgress || i == len(sr.TransferSpeedSamples)-1 {
						if runStartIdx != -1 {
							// End the run at i-1 if progressed again, or at i if last element also no-progress.
							endIdx := i - 1
							if noProgress && i == len(sr.TransferSpeedSamples)-1 {
								endIdx = i
							}
							startMs := sr.TransferSpeedSamples[runStartIdx].TimeMs
							endMs := sr.TransferSpeedSamples[endIdx].TimeMs
							dur := endMs - startMs
							if dur >= opts.MicroStallMinGapMs {
								microCnt++
								microTotal += dur
							}
							runStartIdx = -1
						}
					}
				}
				if microCnt > 0 {
					bs.microStallCount = microCnt
					bs.microStallTotalMs = microTotal
					bs.microStallPresent = true
				}
			}
			bs.sampleTotalMs = int64(len(sr.TransferSpeedSamples)) * intervalMs
			bs.sampleLowMs = lowCount * intervalMs
		}
		// boolean / ratio fields from SiteResult
		bs.cachePresent = sr.CachePresent
		bs.proxySuspected = sr.ProxySuspected
		if sr.ProxyName != "" {
			bs.proxyNameLower = strings.ToLower(strings.TrimSpace(sr.ProxyName))
		}
		if sr.ProxyRemoteIsProxy || (sr.UsingEnvProxy && sr.EnvProxyURL != "") {
			bs.usingProxyEndpoint = true
		}
		bs.ipMismatch = sr.IPMismatch
		bs.prefetchSuspected = sr.PrefetchSuspected
		bs.warmCacheSuspected = sr.WarmCacheSuspected
		bs.connReused = sr.ConnectionReusedSecond
		bs.headGetRatio = sr.HeadGetTimeRatio
		// protocol/tls/encoding telemetry
		bs.httpProto = sr.HTTPProtocol
		bs.tlsVer = sr.TLSVersion
		bs.alpn = sr.ALPN
		bs.chunked = sr.Chunked
		// network diagnostics
		bs.dnsServer = strings.TrimSpace(sr.DNSServer)
		bs.dnsNet = strings.TrimSpace(sr.DNSServerNetwork)
		bs.nextHop = strings.TrimSpace(sr.NextHop)
		bs.nextHopSrc = strings.TrimSpace(sr.NextHopSource)
		records = append(records, bs)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no records")
	}
	// Phase 2: group records by run_tag. We preserve the first-seen order of unique
	// run_tags in 'order' then later sort it lexicographically (timestamps sort
	// correctly) so we can truncate to the last MaxBatches batches deterministically.
	batches := map[string][]rec{}
	var order []string
	debugOn := os.Getenv("ANALYSIS_DEBUG") != ""
	for _, r := range records {
		if r.runTag == "" { // should not happen (filtered earlier) but guard regardless
			continue
		}
		if _, ok := batches[r.runTag]; !ok {
			order = append(order, r.runTag)
			if debugOn {
				fmt.Printf("[analysis debug] discovered new batch tag: %s\n", r.runTag)
			}
		}
		batches[r.runTag] = append(batches[r.runTag], r)
	}
	if debugOn {
		for _, tag := range order {
			fmt.Printf("[analysis debug] batch %s raw line count=%d\n", tag, len(batches[tag]))
		}
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("no batches")
	}
	// Sort batch tags so chronological order (timestamp-based tags) is guaranteed,
	// then trim to the last MaxBatches requested batches (keeping most recent activity).
	sort.Strings(order)
	if MaxBatches <= 0 {
		MaxBatches = 10
	}
	if len(order) > MaxBatches {
		order = order[len(order)-MaxBatches:]
	}
	avg := func(a []float64) float64 {
		if len(a) == 0 {
			return 0
		}
		s := 0.0
		for _, v := range a {
			s += v
		}
		return s / float64(len(a))
	}
	minVal := func(a []float64) float64 {
		if len(a) == 0 {
			return 0
		}
		m := a[0]
		for _, v := range a[1:] {
			if v < m {
				m = v
			}
		}
		return m
	}
	maxVal := func(a []float64) float64 {
		if len(a) == 0 {
			return 0
		}
		m := a[0]
		for _, v := range a[1:] {
			if v > m {
				m = v
			}
		}
		return m
	}
	median := func(a []float64) float64 {
		if len(a) == 0 {
			return 0
		}
		cp := append([]float64(nil), a...)
		sort.Float64s(cp)
		return cp[len(cp)/2]
	}
	percentile := func(a []float64, p float64) float64 {
		if len(a) == 0 {
			return 0
		}
		if p <= 0 {
			return a[0]
		}
		if p >= 100 {
			return a[len(a)-1]
		}
		cp := append([]float64(nil), a...)
		sort.Float64s(cp)
		// nearest-rank method
		idx := int(math.Ceil(p/100*float64(len(cp)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(cp) {
			idx = len(cp) - 1
		}
		return cp[idx]
	}
	// Phase 3: aggregate each batch.
	var summaries []BatchSummary
	for _, tag := range order {
		recs := batches[tag]
		proxyNameCounts := map[string]int{}
		proxyUsingEnv := 0
		proxyClassified := 0
		// capture situation for this batch (prefer first non-empty)
		batchSituation := ""

		// protocol/tls/encoding aggregators
		protoCounts := map[string]int{}
		protoSpeedSum := map[string]float64{}
		protoSpeedCnt := map[string]int{}
		protoStallCnt := map[string]int{}
		protoErrorCnt := map[string]int{}
		protoPartialCnt := map[string]int{}
		tlsCounts := map[string]int{}
		alpnCounts := map[string]int{}
		chunkedTrue := 0

		buildFamily := func(filter string) *FamilySummary {
			var speeds, ttfbs, bytesVals, firsts, p50s, p90s, p95s, p99s, ratios, plateauCounts, longest, jitters []float64
			var slopes, coefVars, headGetRatios []float64
			var dnsTimes, dnsLegacyTimes, connTimes, tlsTimes []float64
			var cacheCnt, proxyCnt, entProxyCnt, srvProxyCnt, ipMismatchCnt, prefetchCnt, warmCacheCnt, reuseCnt, plateauStableCnt int
			var errorLines int
			var lowMsSum, totalMsSum int64
			var stallCnt int
			var preTTFBCnt int
			var partialCnt int
			var stallTimeMsSum int64
			// micro-stalls accumulators
			var microLinesWith int
			var microCountSum int
			var microMsSum int64
			var minTS, maxTS time.Time
			for _, r := range recs {
				if filter != "" && r.ipFamily != filter { // skip if filtering by family
					continue
				}
				if !r.timestamp.IsZero() {
					if minTS.IsZero() || r.timestamp.Before(minTS) {
						minTS = r.timestamp
					}
					if maxTS.IsZero() || r.timestamp.After(maxTS) {
						maxTS = r.timestamp
					}
				}
				if r.speed > 0 {
					speeds = append(speeds, r.speed)
				}
				if r.ttfb > 0 {
					ttfbs = append(ttfbs, r.ttfb)
				}
				if r.bytes > 0 {
					bytesVals = append(bytesVals, r.bytes)
				}
				if r.firstRTT > 0 {
					firsts = append(firsts, r.firstRTT)
				}
				if r.p50 > 0 {
					p50s = append(p50s, r.p50)
				}
				if r.p90 > 0 {
					p90s = append(p90s, r.p90)
				}
				if r.p95 > 0 {
					p95s = append(p95s, r.p95)
				}
				if r.p99 > 0 {
					p99s = append(p99s, r.p99)
				}
				if r.p50 > 0 && r.p99 > 0 {
					ratios = append(ratios, r.p99/r.p50)
				}
				if r.plateauCount > 0 {
					plateauCounts = append(plateauCounts, r.plateauCount)
				}
				if r.longestPlateau > 0 {
					longest = append(longest, r.longestPlateau)
				}
				if r.jitterPct > 0 {
					jitters = append(jitters, r.jitterPct)
				}
				if r.slope != 0 {
					slopes = append(slopes, r.slope)
				}
				if r.coefVarPct > 0 {
					coefVars = append(coefVars, r.coefVarPct)
				}
				if r.headGetRatio > 0 {
					headGetRatios = append(headGetRatios, r.headGetRatio)
				}
				// timings
				if r.dnsMs > 0 {
					dnsTimes = append(dnsTimes, r.dnsMs)
				}
				if r.connMs > 0 {
					connTimes = append(connTimes, r.connMs)
				}
				if r.tlsMs > 0 {
					tlsTimes = append(tlsTimes, r.tlsMs)
				}
				if r.dnsLegacyMs > 0 {
					dnsLegacyTimes = append(dnsLegacyTimes, r.dnsLegacyMs)
				}
				if r.cachePresent {
					cacheCnt++
				}
				if r.proxySuspected {
					proxyCnt++
				}
				// classify enterprise vs server-side
				if r.proxyNameLower != "" {
					if isEnterpriseProxy(r.proxyNameLower) {
						entProxyCnt++
					} else {
						srvProxyCnt++
					}
				} else if r.usingProxyEndpoint {
					// No name, but using explicit proxy endpoint (from env) -> enterprise bucket
					entProxyCnt++
				}
				if r.ipMismatch {
					ipMismatchCnt++
				}
				if r.prefetchSuspected {
					prefetchCnt++
				}
				if r.warmCacheSuspected {
					warmCacheCnt++
				}
				if r.connReused {
					reuseCnt++
				}
				if r.plateauStable {
					plateauStableCnt++
				}
				if r.hasError {
					errorLines++
				}
				// stability accumulators
				if r.sampleTotalMs > 0 {
					totalMsSum += r.sampleTotalMs
					lowMsSum += r.sampleLowMs
				}
				if r.stalled {
					stallCnt++
					if r.stallElapsedMs > 0 {
						stallTimeMsSum += r.stallElapsedMs
					}
				}
				if r.microStallPresent {
					microLinesWith++
					microCountSum += r.microStallCount
					if r.microStallTotalMs > 0 {
						microMsSum += r.microStallTotalMs
					}
				}
				if r.preTTFBStall {
					preTTFBCnt++
				}
				if r.partialBody {
					partialCnt++
				}
			}
			// Count lines that passed filter
			lineCount := 0
			for _, r := range recs {
				if filter == "" || r.ipFamily == filter {
					lineCount++
				}
			}
			if lineCount == 0 {
				return nil
			}
			pct := func(c int) float64 { return float64(c) / float64(lineCount) * 100 }
			var durationMs int64
			if !minTS.IsZero() && !maxTS.IsZero() && maxTS.After(minTS) {
				durationMs = maxTS.Sub(minTS).Milliseconds()
			}
			fs := &FamilySummary{
				Lines: lineCount, AvgSpeed: avg(speeds), MedianSpeed: median(speeds), AvgTTFB: avg(ttfbs), AvgBytes: avg(bytesVals), ErrorLines: errorLines,
				AvgFirstRTTGoodput: avg(firsts), AvgP50Speed: avg(p50s), AvgP99P50Ratio: avg(ratios), AvgPlateauCount: avg(plateauCounts), AvgLongestPlateau: avg(longest), AvgJitterPct: avg(jitters),
				AvgP90Speed: avg(p90s), AvgP95Speed: avg(p95s), AvgP99Speed: avg(p99s), AvgSlopeKbpsPerSec: avg(slopes), AvgCoefVariationPct: avg(coefVars),
				CacheHitRatePct: pct(cacheCnt), ProxySuspectedRatePct: pct(proxyCnt), EnterpriseProxyRatePct: pct(entProxyCnt), ServerProxyRatePct: pct(srvProxyCnt), IPMismatchRatePct: pct(ipMismatchCnt), PrefetchSuspectedRatePct: pct(prefetchCnt), WarmCacheSuspectedRatePct: pct(warmCacheCnt), ConnReuseRatePct: pct(reuseCnt), PlateauStableRatePct: pct(plateauStableCnt), AvgHeadGetTimeRatio: avg(headGetRatios),
				BatchDurationMs: durationMs,
				AvgDNSMs:        avg(dnsTimes),
				AvgDNSLegacyMs:  avg(dnsLegacyTimes),
				AvgConnectMs:    avg(connTimes),
				AvgTLSHandshake: avg(tlsTimes),
				MinSpeed:        minVal(speeds),
				MaxSpeed:        maxVal(speeds),
				// stability & quality
				LowSpeedTimeSharePct: func() float64 {
					if totalMsSum <= 0 {
						return 0
					}
					v := float64(lowMsSum) / float64(totalMsSum) * 100
					if math.IsNaN(v) || math.IsInf(v, 0) {
						return 0
					}
					return v
				}(),
				StallRatePct: func() float64 {
					if lineCount == 0 {
						return 0
					}
					return float64(stallCnt) / float64(lineCount) * 100
				}(),
				MicroStallRatePct: func() float64 {
					if lineCount == 0 {
						return 0
					}
					return float64(microLinesWith) / float64(lineCount) * 100
				}(),
				PreTTFBStallRatePct: func() float64 {
					if lineCount == 0 {
						return 0
					}
					return float64(preTTFBCnt) / float64(lineCount) * 100
				}(),
				PartialBodyRatePct: pct(partialCnt),
				AvgStallElapsedMs: func() float64 {
					if stallCnt == 0 {
						return 0
					}
					return float64(stallTimeMsSum) / float64(stallCnt)
				}(),
				AvgMicroStallCount: func() float64 {
					if lineCount == 0 {
						return 0
					}
					return float64(microCountSum) / float64(lineCount)
				}(),
				AvgMicroStallMs: func() float64 {
					if microLinesWith == 0 {
						return 0
					}
					return float64(microMsSum) / float64(microLinesWith)
				}(),
			}
			// TTFB percentiles per family in ms
			fs.AvgP50TTFBMs = percentile(ttfbs, 50)
			fs.AvgP90TTFBMs = percentile(ttfbs, 90)
			fs.AvgP95TTFBMs = percentile(ttfbs, 95)
			fs.AvgP99TTFBMs = percentile(ttfbs, 99)
			fs.AvgP25TTFBMs = percentile(ttfbs, 25)
			fs.AvgP75TTFBMs = percentile(ttfbs, 75)
			// Speed percentiles per family
			fs.AvgP25Speed = percentile(speeds, 25)
			fs.AvgP75Speed = percentile(speeds, 75)
			// Min/Max TTFB
			fs.MinTTFBMs = minVal(ttfbs)
			fs.MaxTTFBMs = maxVal(ttfbs)
			return fs
		}
		var speeds, ttfbs, bytesVals, firsts, p50s, p90s, p95s, p99s, ratios, plateauCounts, longest, jitters []float64
		var slopes, coefVars, headGetRatios []float64
		var dnsTimesAll, dnsLegacyTimesAll, connTimesAll, tlsTimesAll []float64
		var cacheCnt, proxyCnt, entProxyCntAll, srvProxyCntAll, ipMismatchCnt, prefetchCnt, warmCacheCnt, reuseCnt, plateauStableCnt int
		var errorLines int
		var lowMsSumAll, totalMsSumAll int64
		var stallCntAll int
		var preTTFBCntAll int
		var partialCntAll int
		var stallTimeMsSumAll int64
		// micro-stalls (overall)
		var microLinesWithAll int
		var microCountSumAll int
		var microMsSumAll int64
		var minTS, maxTS time.Time
		for _, r := range recs {
			if batchSituation == "" && r.situation != "" {
				batchSituation = r.situation
			}
			if !r.timestamp.IsZero() {
				if minTS.IsZero() || r.timestamp.Before(minTS) {
					minTS = r.timestamp
				}
				if maxTS.IsZero() || r.timestamp.After(maxTS) {
					maxTS = r.timestamp
				}
			}
			if r.speed > 0 {
				speeds = append(speeds, r.speed)
			}
			// protocol speed/stall/error/partial aggregations
			// Count missing protocol explicitly as "(unknown)" so mix charts can account for 100% without a synthetic remainder.
			{
				key := r.httpProto
				if key == "" {
					key = "(unknown)"
				}
				protoCounts[key]++
				if r.speed > 0 {
					protoSpeedSum[key] += r.speed
					protoSpeedCnt[key]++
				}
				if r.stalled {
					protoStallCnt[key]++
				}
				if r.hasError {
					protoErrorCnt[key]++
				}
				if r.partialBody {
					protoPartialCnt[key]++
				}
			}
			if r.tlsVer != "" {
				tlsCounts[r.tlsVer]++
			}
			if r.alpn != "" {
				alpnCounts[r.alpn]++
			}
			if r.chunked {
				chunkedTrue++
			}
			if r.proxyName != "" {
				proxyNameCounts[r.proxyName]++
				proxyClassified++
			}
			if r.usingEnvProxy {
				proxyUsingEnv++
			}
			if r.ttfb > 0 {
				ttfbs = append(ttfbs, r.ttfb)
			}
			if r.bytes > 0 {
				bytesVals = append(bytesVals, r.bytes)
			}
			if r.firstRTT > 0 {
				firsts = append(firsts, r.firstRTT)
			}
			if r.p50 > 0 {
				p50s = append(p50s, r.p50)
			}
			if r.p90 > 0 {
				p90s = append(p90s, r.p90)
			}
			if r.p95 > 0 {
				p95s = append(p95s, r.p95)
			}
			if r.p99 > 0 {
				p99s = append(p99s, r.p99)
			}
			if r.p50 > 0 && r.p99 > 0 {
				ratios = append(ratios, r.p99/r.p50)
			}
			if r.plateauCount > 0 {
				plateauCounts = append(plateauCounts, r.plateauCount)
			}
			if r.longestPlateau > 0 {
				longest = append(longest, r.longestPlateau)
			}
			if r.jitterPct > 0 {
				jitters = append(jitters, r.jitterPct)
			}
			if r.slope != 0 {
				slopes = append(slopes, r.slope)
			}
			if r.coefVarPct > 0 {
				coefVars = append(coefVars, r.coefVarPct)
			}
			if r.headGetRatio > 0 {
				headGetRatios = append(headGetRatios, r.headGetRatio)
			}
			// timings overall
			if r.dnsMs > 0 {
				dnsTimesAll = append(dnsTimesAll, r.dnsMs)
			}
			if r.connMs > 0 {
				connTimesAll = append(connTimesAll, r.connMs)
			}
			if r.tlsMs > 0 {
				tlsTimesAll = append(tlsTimesAll, r.tlsMs)
			}
			if r.dnsLegacyMs > 0 {
				dnsLegacyTimesAll = append(dnsLegacyTimesAll, r.dnsLegacyMs)
			}
			if r.cachePresent {
				cacheCnt++
			}
			if r.proxySuspected {
				proxyCnt++
			}
			if r.proxyNameLower != "" {
				if isEnterpriseProxy(r.proxyNameLower) {
					entProxyCntAll++
				} else {
					srvProxyCntAll++
				}
			} else if r.usingProxyEndpoint {
				entProxyCntAll++
			}
			if r.ipMismatch {
				ipMismatchCnt++
			}
			if r.prefetchSuspected {
				prefetchCnt++
			}
			if r.warmCacheSuspected {
				warmCacheCnt++
			}
			if r.connReused {
				reuseCnt++
			}
			if r.plateauStable {
				plateauStableCnt++
			}
			if r.hasError {
				errorLines++
			}
			// stability accumulators (overall)
			if r.sampleTotalMs > 0 {
				totalMsSumAll += r.sampleTotalMs
				lowMsSumAll += r.sampleLowMs
			}
			if r.stalled {
				stallCntAll++
				if r.stallElapsedMs > 0 {
					stallTimeMsSumAll += r.stallElapsedMs
				}
			}
			if r.microStallPresent {
				microLinesWithAll++
				microCountSumAll += r.microStallCount
				if r.microStallTotalMs > 0 {
					microMsSumAll += r.microStallTotalMs
				}
			}
			if r.preTTFBStall {
				preTTFBCntAll++
			}
			if r.partialBody {
				partialCntAll++
			}
		}
		recCount := len(recs)
		den := float64(recCount)
		pct := func(c int) float64 {
			if recCount == 0 {
				return 0
			}
			return float64(c) / den * 100
		}
		var durationMs int64
		if !minTS.IsZero() && !maxTS.IsZero() && maxTS.After(minTS) {
			durationMs = maxTS.Sub(minTS).Milliseconds()
		}
		// Capture most recent non-empty diagnostics across the batch
		latestDNS, latestDNSNet := "", ""
		latestHop, latestHopSrc := "", ""
		latestURL := ""
		for i := len(recs) - 1; i >= 0; i-- {
			r := recs[i]
			if latestDNS == "" && r.dnsServer != "" {
				latestDNS = r.dnsServer
			}
			if latestDNSNet == "" && r.dnsNet != "" {
				latestDNSNet = r.dnsNet
			}
			if latestHop == "" && r.nextHop != "" {
				latestHop = r.nextHop
			}
			if latestHopSrc == "" && r.nextHopSrc != "" {
				latestHopSrc = r.nextHopSrc
			}
			// capture a representative URL for tooling
			if latestURL == "" && strings.TrimSpace(r.url) != "" {
				latestURL = r.url
			}
			if latestDNS != "" && latestDNSNet != "" && latestHop != "" && latestHopSrc != "" {
				// keep scanning further for URL if still empty
				if latestURL != "" {
					break
				}
			}
		}
		summary := BatchSummary{
			RunTag: tag, Lines: recCount,
			AvgSpeed: avg(speeds), MedianSpeed: median(speeds), MinSpeed: minVal(speeds), MaxSpeed: maxVal(speeds), AvgTTFB: avg(ttfbs), MinTTFBMs: minVal(ttfbs), MaxTTFBMs: maxVal(ttfbs), AvgBytes: avg(bytesVals), ErrorLines: errorLines,
			AvgFirstRTTGoodput: avg(firsts), AvgP50Speed: avg(p50s), AvgP99P50Ratio: avg(ratios), AvgPlateauCount: avg(plateauCounts), AvgLongestPlateau: avg(longest), AvgJitterPct: avg(jitters),
			AvgP90Speed: avg(p90s), AvgP95Speed: avg(p95s), AvgP99Speed: avg(p99s), AvgSlopeKbpsPerSec: avg(slopes), AvgCoefVariationPct: avg(coefVars),
			CacheHitRatePct: pct(cacheCnt), ProxySuspectedRatePct: pct(proxyCnt), IPMismatchRatePct: pct(ipMismatchCnt), PrefetchSuspectedRatePct: pct(prefetchCnt), WarmCacheSuspectedRatePct: pct(warmCacheCnt), ConnReuseRatePct: pct(reuseCnt), PlateauStableRatePct: pct(plateauStableCnt), AvgHeadGetTimeRatio: avg(headGetRatios),
			BatchDurationMs: durationMs,
			AvgDNSMs:        avg(dnsTimesAll),
			AvgDNSLegacyMs:  avg(dnsLegacyTimesAll),
			AvgConnectMs:    avg(connTimesAll),
			AvgTLSHandshake: avg(tlsTimesAll),
			CacheHitLines:   cacheCnt, ProxySuspectedLines: proxyCnt, EnterpriseProxyLines: entProxyCntAll, ServerProxyLines: srvProxyCntAll, IPMismatchLines: ipMismatchCnt, PrefetchSuspectedLines: prefetchCnt, WarmCacheSuspectedLines: warmCacheCnt, ConnReuseLines: reuseCnt, PlateauStableLines: plateauStableCnt,
			// stability & quality (overall)
			LowSpeedTimeSharePct: func() float64 {
				if totalMsSumAll <= 0 {
					return 0
				}
				v := float64(lowMsSumAll) / float64(totalMsSumAll) * 100
				if math.IsNaN(v) || math.IsInf(v, 0) {
					return 0
				}
				return v
			}(),
			StallRatePct: func() float64 {
				if recCount == 0 {
					return 0
				}
				return float64(stallCntAll) / float64(recCount) * 100
			}(),
			MicroStallRatePct: func() float64 {
				if recCount == 0 {
					return 0
				}
				return float64(microLinesWithAll) / float64(recCount) * 100
			}(),
			AvgStallElapsedMs: func() float64 {
				if stallCntAll == 0 {
					return 0
				}
				return float64(stallTimeMsSumAll) / float64(stallCntAll)
			}(),
			AvgMicroStallCount: func() float64 {
				if recCount == 0 {
					return 0
				}
				return float64(microCountSumAll) / float64(recCount)
			}(),
			AvgMicroStallMs: func() float64 {
				if microLinesWithAll == 0 {
					return 0
				}
				return float64(microMsSumAll) / float64(microLinesWithAll)
			}(),
			PartialBodyRatePct: func() float64 {
				if recCount == 0 {
					return 0
				}
				return float64(partialCntAll) / float64(recCount) * 100
			}(),
			PreTTFBStallRatePct: func() float64 {
				if recCount == 0 {
					return 0
				}
				return float64(preTTFBCntAll) / float64(recCount) * 100
			}(),
		}
		// Attach diagnostics
		summary.DNSServer = latestDNS
		summary.DNSServerNetwork = latestDNSNet
		summary.NextHop = latestHop
		summary.NextHopSource = latestHopSrc
		summary.SampleURL = latestURL
		// Set LocalSelfTestKbps from the most recent non-zero value in this batch
		for i := len(recs) - 1; i >= 0; i-- {
			if recs[i].localSelfKbps > 0 {
				summary.LocalSelfTestKbps = recs[i].localSelfKbps
				break
			}
		}
		// Attach calibration & system metrics from the most recent record carrying them
		for i := len(recs) - 1; i >= 0; i-- {
			r := recs[i]
			if r.hostname != "" {
				summary.Hostname = r.hostname
				summary.NumCPU = r.numCPU
				summary.LoadAvg1 = r.load1
				summary.LoadAvg5 = r.load5
				summary.LoadAvg15 = r.load15
			}
			// attach measurement quality (latest)
			if r.mqSampleCount > 0 || r.mqCI95RelMoE > 0 || r.mqReqN10Pct > 0 || r.mqGood {
				summary.SampleCount = r.mqSampleCount
				summary.CI95RelMoEPct = r.mqCI95RelMoE
				summary.RequiredSamplesFor10Pct95CI = r.mqReqN10Pct
				summary.QualityGood = r.mqGood
			}
			if r.memTotal > 0 {
				summary.MemTotalBytes = r.memTotal
				summary.MemFreeOrAvailable = r.memFree
			}
			if r.diskTotal > 0 {
				summary.DiskRootTotalBytes = r.diskTotal
				summary.DiskRootFreeBytes = r.diskFree
			}
			if r.calibMax > 0 || len(r.calibTargets) > 0 {
				summary.CalibrationMaxKbps = r.calibMax
				if len(r.calibTargets) > 0 {
					summary.CalibrationRangesTarget = append([]float64(nil), r.calibTargets...)
					summary.CalibrationRangesObs = append([]float64(nil), r.calibObserved...)
					summary.CalibrationRangesErrPct = append([]float64(nil), r.calibErrPct...)
					if len(r.calibSamples) == len(r.calibTargets) {
						summary.CalibrationSamples = append([]int(nil), r.calibSamples...)
					}
				}
				break
			}
		}
		// Protocol/TLS/ALPN/chunked rollups
		if recCount > 0 {
			if len(protoCounts) > 0 {
				summary.HTTPProtocolCounts = protoCounts
				summary.HTTPProtocolRatePct = map[string]float64{}
				summary.AvgSpeedByHTTPProtocolKbps = map[string]float64{}
				summary.StallRateByHTTPProtocolPct = map[string]float64{}
				summary.ErrorRateByHTTPProtocolPct = map[string]float64{}
				summary.ErrorShareByHTTPProtocolPct = map[string]float64{}
				summary.StallShareByHTTPProtocolPct = map[string]float64{}
				summary.PartialShareByHTTPProtocolPct = map[string]float64{}
				summary.PartialBodyRateByHTTPProtocolPct = map[string]float64{}
				for k, c := range protoCounts {
					summary.HTTPProtocolRatePct[k] = float64(c) / den * 100
					if n := protoSpeedCnt[k]; n > 0 {
						summary.AvgSpeedByHTTPProtocolKbps[k] = protoSpeedSum[k] / float64(n)
					}
					if c > 0 {
						summary.StallRateByHTTPProtocolPct[k] = float64(protoStallCnt[k]) / float64(c) * 100
						summary.ErrorRateByHTTPProtocolPct[k] = float64(protoErrorCnt[k]) / float64(c) * 100
						summary.PartialBodyRateByHTTPProtocolPct[k] = float64(protoPartialCnt[k]) / float64(c) * 100
					}
				}
				// Compute shares so values sum to ~100% across protocols when totals exist
				if errorLines > 0 {
					for k, e := range protoErrorCnt {
						if e > 0 {
							summary.ErrorShareByHTTPProtocolPct[k] = float64(e) / float64(errorLines) * 100
						}
					}
				}
				if stallCntAll > 0 {
					for k, s := range protoStallCnt {
						if s > 0 {
							summary.StallShareByHTTPProtocolPct[k] = float64(s) / float64(stallCntAll) * 100
						}
					}
				}
				if partialCntAll > 0 {
					for k, p := range protoPartialCnt {
						if p > 0 {
							summary.PartialShareByHTTPProtocolPct[k] = float64(p) / float64(partialCntAll) * 100
						}
					}
				}
			}
			if len(tlsCounts) > 0 {
				summary.TLSVersionCounts = tlsCounts
				summary.TLSVersionRatePct = map[string]float64{}
				for k, c := range tlsCounts {
					summary.TLSVersionRatePct[k] = float64(c) / den * 100
				}
			}
			if len(alpnCounts) > 0 {
				summary.ALPNCounts = alpnCounts
				summary.ALPNRatePct = map[string]float64{}
				for k, c := range alpnCounts {
					summary.ALPNRatePct[k] = float64(c) / den * 100
				}
			}
			summary.ChunkedRatePct = float64(chunkedTrue) / den * 100
		}
		// TTFB percentiles overall in ms
		summary.AvgP50TTFBMs = percentile(ttfbs, 50)
		summary.AvgP90TTFBMs = percentile(ttfbs, 90)
		summary.AvgP95TTFBMs = percentile(ttfbs, 95)
		summary.AvgP99TTFBMs = percentile(ttfbs, 99)
		summary.AvgP25TTFBMs = percentile(ttfbs, 25)
		summary.AvgP75TTFBMs = percentile(ttfbs, 75)
		// Speed percentiles overall
		summary.AvgP25Speed = percentile(speeds, 25)
		summary.AvgP75Speed = percentile(speeds, 75)
		// Set split proxy rates
		if recCount > 0 {
			summary.EnterpriseProxyRatePct = float64(entProxyCntAll) / float64(recCount) * 100
			summary.ServerProxyRatePct = float64(srvProxyCntAll) / float64(recCount) * 100
		}
		if batchSituation != "" {
			summary.Situation = batchSituation
		}
		// Situation is expected to be provided by upstream logic populating BatchSummary
		// Fill proxy aggregation
		if len(proxyNameCounts) > 0 {
			summary.ProxyNameCounts = proxyNameCounts
			summary.ProxyNameRatePct = map[string]float64{}
			for k, v := range proxyNameCounts {
				summary.ProxyNameRatePct[k] = float64(v) / float64(recCount) * 100
			}
		}
		if recCount > 0 {
			summary.ProxyUsingEnvLines = proxyUsingEnv
			summary.EnvProxyUsageRatePct = float64(proxyUsingEnv) / float64(recCount) * 100
			summary.ProxyUsedLines = 0
			for _, v := range proxyNameCounts {
				summary.ProxyUsedLines += v
			}
			summary.ClassifiedProxyRatePct = float64(proxyClassified) / float64(recCount) * 100
		}
		// Add per-family subsets only if present
		if fam := buildFamily("ipv4"); fam != nil {
			summary.IPv4 = fam
		}
		if fam := buildFamily("ipv6"); fam != nil {
			summary.IPv6 = fam
		}
		summaries = append(summaries, summary)
		if debugOn {
			// Compose protocol mix string if available
			mix := ""
			if len(summary.HTTPProtocolRatePct) > 0 {
				// stable order
				ks := make([]string, 0, len(summary.HTTPProtocolRatePct))
				for k := range summary.HTTPProtocolRatePct {
					ks = append(ks, k)
				}
				sort.Strings(ks)
				var parts []string
				sum := 0.0
				for _, k := range ks {
					v := summary.HTTPProtocolRatePct[k]
					parts = append(parts, fmt.Sprintf("%s=%.1f%%", k, v))
					sum += v
				}
				if sum < 99.9 {
					parts = append(parts, fmt.Sprintf("remainder=%.1f%%", 100.0-sum))
				}
				mix = " proto_mix=[" + strings.Join(parts, ", ") + "]"
			}
			// Quick ALPN/TLS known-rate snapshot to help spot environments that omit ALPN/TLS metadata.
			alpnKnownCnt := 0
			for _, c := range alpnCounts {
				alpnKnownCnt += c
			}
			tlsKnownCnt := 0
			for _, c := range tlsCounts {
				tlsKnownCnt += c
			}
			alpnKnownPct := 0.0
			tlsKnownPct := 0.0
			if recCount > 0 {
				alpnKnownPct = float64(alpnKnownCnt) / float64(recCount) * 100
				tlsKnownPct = float64(tlsKnownCnt) / float64(recCount) * 100
			}
			fmt.Printf("[analysis debug] summary %s lines=%d avg_speed=%.1f avg_ttfb=%.0f errors=%d p50=%.1f ratio=%.2f jitter=%.1f%% slope=%.2f cov%%=%.1f cache_hit=%.1f%% reuse=%.1f%% stalls=%.1f%% avg_stall=%.0fms micro_stalls=%.1f%% avg_micro_ms=%.0f alpn_known=%.1f%% tls_known=%.1f%%%s\n",
				summary.RunTag,
				summary.Lines,
				summary.AvgSpeed,
				summary.AvgTTFB,
				summary.ErrorLines,
				summary.AvgP50Speed,
				summary.AvgP99P50Ratio,
				summary.AvgJitterPct,
				summary.AvgSlopeKbpsPerSec,
				summary.AvgCoefVariationPct,
				summary.CacheHitRatePct,
				summary.ConnReuseRatePct,
				summary.StallRatePct,
				summary.AvgStallElapsedMs,
				summary.MicroStallRatePct,
				summary.AvgMicroStallMs,
				alpnKnownPct,
				tlsKnownPct,
				mix,
			)
		}
	}
	return summaries, nil
}

// Backwards-compatible wrapper for callers without options
func AnalyzeRecentResultsFull(path string, schemaVersion, MaxBatches int, situationFilter string) ([]BatchSummary, error) {
	// Choose a sensible default threshold for low-speed share (1,000 kbps) without breaking callers.
	return AnalyzeRecentResultsFullWithOptions(path, schemaVersion, MaxBatches, AnalyzeOptions{SituationFilter: situationFilter, LowSpeedThresholdKbps: 1000, MicroStallMinGapMs: 500})
}

// CompareLastVsPrevious returns delta percentages for speed and TTFB of last batch vs previous average.
func CompareLastVsPrevious(summaries []BatchSummary) (speedDeltaPct, ttfbDeltaPct float64, prevAvgSpeed, prevAvgTTFB float64) {
	if len(summaries) < 2 {
		return 0, 0, 0, 0
	}
	last := summaries[len(summaries)-1]
	for i := 0; i < len(summaries)-1; i++ {
		prevAvgSpeed += summaries[i].AvgSpeed
		prevAvgTTFB += summaries[i].AvgTTFB
	}
	prevCount := float64(len(summaries) - 1)
	prevAvgSpeed /= prevCount
	prevAvgTTFB /= prevCount
	if prevAvgSpeed > 0 {
		speedDeltaPct = (last.AvgSpeed - prevAvgSpeed) / prevAvgSpeed * 100
	}
	if prevAvgTTFB > 0 {
		ttfbDeltaPct = (last.AvgTTFB - prevAvgTTFB) / prevAvgTTFB * 100
	}
	if math.IsNaN(speedDeltaPct) {
		speedDeltaPct = 0
	}
	if math.IsNaN(ttfbDeltaPct) {
		ttfbDeltaPct = 0
	}
	return
}
