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

// BatchSummary captures aggregate metrics for one run_tag batch.
type BatchSummary struct {
	RunTag             string  `json:"run_tag"`
	Situation          string  `json:"situation,omitempty"`
	Lines              int     `json:"lines"`
	AvgSpeed           float64 `json:"avg_speed_kbps"`
	MedianSpeed        float64 `json:"median_speed_kbps"`
	AvgTTFB            float64 `json:"avg_ttfb_ms"`
	AvgBytes           float64 `json:"avg_bytes"`
	ErrorLines         int     `json:"error_lines"`
	AvgFirstRTTGoodput float64 `json:"avg_first_rtt_goodput_kbps"`
	AvgP50Speed        float64 `json:"avg_p50_kbps"`
	AvgP99P50Ratio     float64 `json:"avg_p99_p50_ratio"`
	AvgPlateauCount    float64 `json:"avg_plateau_count"`
	AvgLongestPlateau  float64 `json:"avg_longest_plateau_ms"`
	AvgJitterPct       float64 `json:"avg_jitter_mean_abs_pct"`
	BatchDurationMs    int64   `json:"batch_duration_ms,omitempty"`
	// Extended aggregated metrics (averages or rates over successful lines)
	AvgP90Speed               float64 `json:"avg_p90_kbps,omitempty"`
	AvgP95Speed               float64 `json:"avg_p95_kbps,omitempty"`
	AvgP99Speed               float64 `json:"avg_p99_kbps,omitempty"`
	AvgSlopeKbpsPerSec        float64 `json:"avg_slope_kbps_per_sec,omitempty"`
	AvgCoefVariationPct       float64 `json:"avg_coef_variation_pct,omitempty"`
	CacheHitRatePct           float64 `json:"cache_hit_rate_pct,omitempty"`
	ProxySuspectedRatePct     float64 `json:"proxy_suspected_rate_pct,omitempty"`
	IPMismatchRatePct         float64 `json:"ip_mismatch_rate_pct,omitempty"`
	PrefetchSuspectedRatePct  float64 `json:"prefetch_suspected_rate_pct,omitempty"`
	WarmCacheSuspectedRatePct float64 `json:"warm_cache_suspected_rate_pct,omitempty"`
	ConnReuseRatePct          float64 `json:"conn_reuse_rate_pct,omitempty"`
	PlateauStableRatePct      float64 `json:"plateau_stable_rate_pct,omitempty"`
	AvgHeadGetTimeRatio       float64 `json:"avg_head_get_time_ratio,omitempty"`
	// Raw count fields (not serialized) retained to enable higher-level aggregation (overall across batches)
	CacheHitLines           int `json:"-"`
	ProxySuspectedLines     int `json:"-"`
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
}

// FamilySummary mirrors BatchSummary's metric fields for a single IP family subset.
type FamilySummary struct {
	Lines                     int     `json:"lines"`
	AvgSpeed                  float64 `json:"avg_speed_kbps"`
	MedianSpeed               float64 `json:"median_speed_kbps"`
	AvgTTFB                   float64 `json:"avg_ttfb_ms"`
	AvgBytes                  float64 `json:"avg_bytes"`
	ErrorLines                int     `json:"error_lines"`
	AvgFirstRTTGoodput        float64 `json:"avg_first_rtt_goodput_kbps"`
	AvgP50Speed               float64 `json:"avg_p50_kbps"`
	AvgP99P50Ratio            float64 `json:"avg_p99_p50_ratio"`
	AvgPlateauCount           float64 `json:"avg_plateau_count"`
	AvgLongestPlateau         float64 `json:"avg_longest_plateau_ms"`
	AvgJitterPct              float64 `json:"avg_jitter_mean_abs_pct"`
	BatchDurationMs           int64   `json:"batch_duration_ms,omitempty"`
	AvgP90Speed               float64 `json:"avg_p90_kbps,omitempty"`
	AvgP95Speed               float64 `json:"avg_p95_kbps,omitempty"`
	AvgP99Speed               float64 `json:"avg_p99_kbps,omitempty"`
	AvgSlopeKbpsPerSec        float64 `json:"avg_slope_kbps_per_sec,omitempty"`
	AvgCoefVariationPct       float64 `json:"avg_coef_variation_pct,omitempty"`
	CacheHitRatePct           float64 `json:"cache_hit_rate_pct,omitempty"`
	ProxySuspectedRatePct     float64 `json:"proxy_suspected_rate_pct,omitempty"`
	IPMismatchRatePct         float64 `json:"ip_mismatch_rate_pct,omitempty"`
	PrefetchSuspectedRatePct  float64 `json:"prefetch_suspected_rate_pct,omitempty"`
	WarmCacheSuspectedRatePct float64 `json:"warm_cache_suspected_rate_pct,omitempty"`
	ConnReuseRatePct          float64 `json:"conn_reuse_rate_pct,omitempty"`
	PlateauStableRatePct      float64 `json:"plateau_stable_rate_pct,omitempty"`
	AvgHeadGetTimeRatio       float64 `json:"avg_head_get_time_ratio,omitempty"`
}

// AnalyzeRecentResults parses the results file and returns the most recent up to MaxBatches batch summaries.
// Thin wrapper over AnalyzeRecentResultsFull.
func AnalyzeRecentResults(path string, schemaVersion, MaxBatches int) ([]BatchSummary, error) {
	return AnalyzeRecentResultsFull(path, schemaVersion, MaxBatches, "")
}

// AnalyzeRecentResultsFull parses the results file and computes extended batch metrics.
// MaxBatches limits how many recent batches are returned (0 or negative -> default 10).
func AnalyzeRecentResultsFull(path string, schemaVersion, MaxBatches int, situationFilter string) ([]BatchSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if situationFilter != "" {
		fmt.Printf("[analysis] reading results from %s (schema_version=%d, max_batches=%d, situation=\"%s\")\n", path, schemaVersion, MaxBatches, situationFilter)
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
		p50, p90, p95, p99 float64
		plateauCount       float64
		longestPlateau     float64
		jitterPct          float64
		slope              float64
		coefVarPct         float64
		headGetRatio       float64
		cachePresent       bool
		proxySuspected     bool
		ipMismatch         bool
		prefetchSuspected  bool
		warmCacheSuspected bool
		connReused         bool
		plateauStable      bool
		hasError           bool
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
		if situationFilter != "" && !strings.EqualFold(env.Meta.Situation, situationFilter) {
			continue
		}
		sr := env.SiteResult
		var ts time.Time
		if env.Meta.TimestampUTC != "" {
			if parsed, perr := time.Parse(time.RFC3339Nano, env.Meta.TimestampUTC); perr == nil {
				ts = parsed
			}
		}
		bs := rec{runTag: env.Meta.RunTag, situation: env.Meta.Situation, ipFamily: sr.IPFamily, proxyName: sr.ProxyName, usingEnvProxy: sr.UsingEnvProxy, timestamp: ts, speed: sr.TransferSpeedKbps, ttfb: float64(sr.TraceTTFBMs), bytes: float64(sr.TransferSizeBytes), firstRTT: sr.FirstRTTGoodputKbps}
		// Track error presence without storing the raw line to reduce memory usage.
		if bytes.Contains(line, []byte("tcp_error")) || bytes.Contains(line, []byte("http_error")) {
			bs.hasError = true
		}
		if sa := sr.SpeedAnalysis; sa != nil {
			bs.p50 = sa.P50Kbps
			if sa.P99Kbps > 0 {
				bs.p99 = sa.P99Kbps
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
		// boolean / ratio fields from SiteResult
		bs.cachePresent = sr.CachePresent
		bs.proxySuspected = sr.ProxySuspected
		bs.ipMismatch = sr.IPMismatch
		bs.prefetchSuspected = sr.PrefetchSuspected
		bs.warmCacheSuspected = sr.WarmCacheSuspected
		bs.connReused = sr.ConnectionReusedSecond
		bs.headGetRatio = sr.HeadGetTimeRatio
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
	median := func(a []float64) float64 {
		if len(a) == 0 {
			return 0
		}
		cp := append([]float64(nil), a...)
		sort.Float64s(cp)
		return cp[len(cp)/2]
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

		buildFamily := func(filter string) *FamilySummary {
			var speeds, ttfbs, bytesVals, firsts, p50s, p90s, p95s, p99s, ratios, plateauCounts, longest, jitters []float64
			var slopes, coefVars, headGetRatios []float64
			var cacheCnt, proxyCnt, ipMismatchCnt, prefetchCnt, warmCacheCnt, reuseCnt, plateauStableCnt int
			var errorLines int
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
				if r.cachePresent {
					cacheCnt++
				}
				if r.proxySuspected {
					proxyCnt++
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
			return &FamilySummary{
				Lines: lineCount, AvgSpeed: avg(speeds), MedianSpeed: median(speeds), AvgTTFB: avg(ttfbs), AvgBytes: avg(bytesVals), ErrorLines: errorLines,
				AvgFirstRTTGoodput: avg(firsts), AvgP50Speed: avg(p50s), AvgP99P50Ratio: avg(ratios), AvgPlateauCount: avg(plateauCounts), AvgLongestPlateau: avg(longest), AvgJitterPct: avg(jitters),
				AvgP90Speed: avg(p90s), AvgP95Speed: avg(p95s), AvgP99Speed: avg(p99s), AvgSlopeKbpsPerSec: avg(slopes), AvgCoefVariationPct: avg(coefVars),
				CacheHitRatePct: pct(cacheCnt), ProxySuspectedRatePct: pct(proxyCnt), IPMismatchRatePct: pct(ipMismatchCnt), PrefetchSuspectedRatePct: pct(prefetchCnt), WarmCacheSuspectedRatePct: pct(warmCacheCnt), ConnReuseRatePct: pct(reuseCnt), PlateauStableRatePct: pct(plateauStableCnt), AvgHeadGetTimeRatio: avg(headGetRatios),
				BatchDurationMs: durationMs,
			}
		}
		var speeds, ttfbs, bytesVals, firsts, p50s, p90s, p95s, p99s, ratios, plateauCounts, longest, jitters []float64
		var slopes, coefVars, headGetRatios []float64
		var cacheCnt, proxyCnt, ipMismatchCnt, prefetchCnt, warmCacheCnt, reuseCnt, plateauStableCnt int
		var errorLines int
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
			if r.cachePresent {
				cacheCnt++
			}
			if r.proxySuspected {
				proxyCnt++
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
		summary := BatchSummary{
			RunTag: tag, Lines: recCount,
			AvgSpeed: avg(speeds), MedianSpeed: median(speeds), AvgTTFB: avg(ttfbs), AvgBytes: avg(bytesVals), ErrorLines: errorLines,
			AvgFirstRTTGoodput: avg(firsts), AvgP50Speed: avg(p50s), AvgP99P50Ratio: avg(ratios), AvgPlateauCount: avg(plateauCounts), AvgLongestPlateau: avg(longest), AvgJitterPct: avg(jitters),
			AvgP90Speed: avg(p90s), AvgP95Speed: avg(p95s), AvgP99Speed: avg(p99s), AvgSlopeKbpsPerSec: avg(slopes), AvgCoefVariationPct: avg(coefVars),
			CacheHitRatePct: pct(cacheCnt), ProxySuspectedRatePct: pct(proxyCnt), IPMismatchRatePct: pct(ipMismatchCnt), PrefetchSuspectedRatePct: pct(prefetchCnt), WarmCacheSuspectedRatePct: pct(warmCacheCnt), ConnReuseRatePct: pct(reuseCnt), PlateauStableRatePct: pct(plateauStableCnt), AvgHeadGetTimeRatio: avg(headGetRatios),
			BatchDurationMs: durationMs,
			CacheHitLines:   cacheCnt, ProxySuspectedLines: proxyCnt, IPMismatchLines: ipMismatchCnt, PrefetchSuspectedLines: prefetchCnt, WarmCacheSuspectedLines: warmCacheCnt, ConnReuseLines: reuseCnt, PlateauStableLines: plateauStableCnt,
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
			fmt.Printf("[analysis debug] summary %s lines=%d avg_speed=%.1f avg_ttfb=%.0f errors=%d p50=%.1f ratio=%.2f jitter=%.1f%% slope=%.2f cov%%=%.1f cache_hit=%.1f%% reuse=%.1f%%\n", summary.RunTag, summary.Lines, summary.AvgSpeed, summary.AvgTTFB, summary.ErrorLines, summary.AvgP50Speed, summary.AvgP99P50Ratio, summary.AvgJitterPct, summary.AvgSlopeKbpsPerSec, summary.AvgCoefVariationPct, summary.CacheHitRatePct, summary.ConnReuseRatePct)
		}
	}
	return summaries, nil
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
