// Internet Monitor main entrypoint.
//
// Two modes:
//  1. Analyze-only mode (default): parse existing monitor_results.jsonl batches, summarize, compute deltas & alerts, optionally emit JSON report.
//  2. Collection mode (enable with --analyze-only=false): perform active measurements across configured sites for N iterations, writing JSONL lines;
//     after each iteration a rolling analysis (of up to last 10 batches or iterations so far) is executed and alerts generated.
//
// Design notes:
// - Batch identity: run_tag (timestamp base + optional _i<iteration>). Legacy lines missing run_tag are upgraded via timestamp derived tags.
// - Alert JSON: always includes an alerts array (may be empty). Automatic naming at repo root if not specified.
// - analyze-only mode never tries to load sites, so you can inspect historical results on a host lacking the original sites list.
// - Dependency direction: main -> analysis package for aggregation; monitor package for collection only.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	"github.com/iafilius/InternetQualityMonitor/src/monitor"
	"github.com/iafilius/InternetQualityMonitor/src/types"
)

// repeatValue returns a slice containing v repeated n times (used to weight per-batch averages
// back into a line-weighted overall average when constructing an overall aggregate across batches).
func repeatValue(v float64, n int) []float64 {
	if n <= 0 {
		return nil
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		out[i] = v
	}
	return out
}

// StripJSONC loads a JSONC file (lines beginning with // are ignored) and returns raw JSON bytes.
// StripJSONC loads a JSONC file (full-line // comments) and returns raw JSON bytes suitable for unmarshalling.
func StripJSONC(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Do NOT remove inline // because of URLs (http://). JSONC style here only uses full-line comments.
		out = append(out, []byte(line+"\n")...)
	}
	return out, scanner.Err()
}

// loadSites reads the JSONC sites list into a slice of Site definitions.
func loadSites(path string) ([]types.Site, error) {
	b, err := StripJSONC(path)
	if err != nil {
		return nil, err
	}
	var sites []types.Site
	if err := json.Unmarshal(b, &sites); err != nil {
		return nil, err
	}
	return sites, nil
}

func main() {
	sitesPath := flag.String("sites", "./sites.jsonc", "Path to sites JSONC file")
	iterations := flag.Int("iterations", 1, "Number of passes over the sites list")
	parallel := flag.Int("parallel", 1, "Maximum concurrent site monitors")
	outFile := flag.String("out", monitor.DefaultResultsFile, "Output JSONL file")
	logLevel := flag.String("log-level", "info", "Log level (debug|info|warn|error)")
	httpTimeout := flag.Duration("http-timeout", 120*time.Second, "Per-request total timeout (including body transfer)")
	stallTimeout := flag.Duration("stall-timeout", 20*time.Second, "Abort transfer if no progress for this long")
	siteTimeout := flag.Duration("site-timeout", 120*time.Second, "Optional overall timeout per site (DNS + all IP probes). 0 disables.")
	maxIPsPerSite := flag.Int("max-ips-per-site", 0, "If >0 limit number of IPs probed per site (e.g. 2 for first v4+v6). 0 = all")
	situation := flag.String("situation", "Unknown", "Label describing current network/context situation (e.g. Office, Home, VPN, Travel). Added to meta for later comparative analysis")
	speedDropAlert := flag.Float64("speed-drop-alert", 30, "Speed drop alert threshold percent")
	ttfbIncreaseAlert := flag.Float64("ttfb-increase-alert", 50, "TTFB increase alert threshold percent")
	errorRateAlert := flag.Float64("error-rate-alert", 20, "Error rate alert threshold percent")
	jitterAlert := flag.Float64("jitter-alert", 25, "Jitter alert threshold percent")
	p99p50RatioAlert := flag.Float64("p99p50-ratio-alert", 2.0, "p99/p50 ratio alert threshold")
	progressInterval := flag.Duration("progress-interval", 5*time.Second, "Interval for progress logging of worker pool (0 disables)")
	progressSites := flag.Bool("progress-sites", true, "Include currently active site names in progress log (may increase verbosity)")
	progressResolveIP := flag.Bool("progress-resolve-ip", true, "Resolve and append first IP(s) for active sites in progress output")
	ipFanout := flag.Bool("ip-fanout", true, "If true, pre-resolve all site IPs and randomize site/IP tasks to spread load")
	alertsJSON := flag.String("alerts-json", "", "Path to write structured alert JSON report (optional)")
	analyzeOnly := flag.Bool("analyze-only", false, "If true, perform analysis on existing results file and exit (default true for now)")
	analysisBatches := flag.Int("analysis-batches", 10, "Max number of recent batches to analyze when --analyze-only is set")
	finalAnalysisBatches := flag.Int("final-analysis-batches", 0, "If >0 in collection mode, after all iterations perform a final full analysis over last N batches")
	flag.Parse()

	// Hostname placeholder expansion for --out. Users can specify patterns like
	// monitor_results_{host}.jsonl and we substitute the current machine hostname.
	if hn, herr := os.Hostname(); herr == nil && hn != "" {
		// sanitize hostname: lowercase, replace any char not alnum, dash, underscore with '-'
		orig := hn
		hn = strings.ToLower(hn)
		var b strings.Builder
		for _, r := range hn {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				b.WriteRune(r)
			} else {
				b.WriteByte('-')
			}
		}
		sanitized := b.String()
		if strings.Contains(*outFile, "{host}") || strings.Contains(*outFile, "%HOST%") || strings.Contains(*outFile, "$HOST") {
			path := *outFile
			path = strings.ReplaceAll(path, "{host}", sanitized)
			path = strings.ReplaceAll(path, "%HOST%", sanitized)
			path = strings.ReplaceAll(path, "$HOST", sanitized)
			*outFile = path
			fmt.Printf("[init] expanded output path with hostname (orig=%s sanitized=%s): %s\n", orig, sanitized, *outFile)
		}
	}

	monitor.SetLogLevel(*logLevel)
	monitor.SetHTTPTimeout(*httpTimeout)
	monitor.SetStallTimeout(*stallTimeout)
	monitor.SetSiteTimeout(*siteTimeout)
	monitor.SetMaxIPsPerSite(*maxIPsPerSite)
	monitor.SetSituation(*situation)

	// Only load sites if we are going to collect (not in analyze-only mode)
	var sites []types.Site
	if !*analyzeOnly {
		var err error
		sites, err = loadSites(*sitesPath)
		if err != nil {
			fmt.Printf("load sites: %v\n", err)
			os.Exit(1)
		}
		if len(sites) == 0 {
			fmt.Println("no sites loaded")
			os.Exit(1)
		}
	}

	// Init async writer
	monitor.InitResultWriter(*outFile)
	defer monitor.CloseResultWriter()

	// ANALYSIS ONLY MODE (skip collection)
	if *analyzeOnly {
		defaultAlerts := false
		if *alertsJSON == "" {
			defaultAlerts = true
			fmt.Println("[init] alerts-json not provided; will emit analysis report at repo root: alerts_<last_run_tag>.json")
		}
		batches := *analysisBatches
		if batches < 1 {
			batches = 1
		}
		summaries, err := analysis.AnalyzeRecentResultsFull(*outFile, monitor.SchemaVersion, batches, *situation)
		if err != nil {
			fmt.Printf("[analysis] %v\n", err)
			os.Exit(1)
		}
		for _, s := range summaries {
			line := fmt.Sprintf("[batch %s] (per-batch) lines=%d dur=%dms avg_speed=%.1f median=%.1f ttfb=%.0f bytes=%.0f errors=%d first_rtt=%.1f p50=%.1f p99/p50=%.2f jitter=%.1f%% slope=%.2f cov%%=%.1f cache_hit=%.1f%% reuse=%.1f%% plateaus=%.1f longest_ms=%.0f", s.RunTag, s.Lines, s.BatchDurationMs, s.AvgSpeed, s.MedianSpeed, s.AvgTTFB, s.AvgBytes, s.ErrorLines, s.AvgFirstRTTGoodput, s.AvgP50Speed, s.AvgP99P50Ratio, s.AvgJitterPct, s.AvgSlopeKbpsPerSec, s.AvgCoefVariationPct, s.CacheHitRatePct, s.ConnReuseRatePct, s.AvgPlateauCount, s.AvgLongestPlateau)
			if s.EnvProxyUsageRatePct > 0 {
				line += fmt.Sprintf(" env_proxy=%.1f%%", s.EnvProxyUsageRatePct)
			}
			if s.ClassifiedProxyRatePct > 0 {
				line += fmt.Sprintf(" proxy_classified=%.1f%%", s.ClassifiedProxyRatePct)
				if len(s.ProxyNameCounts) > 0 {
					// show top 1-2 names
					var top []string
					for name, cnt := range s.ProxyNameCounts {
						top = append(top, fmt.Sprintf("%s:%d", name, cnt))
					}
					if len(top) > 2 {
						top = top[:2]
					}
					line += " [" + strings.Join(top, ",") + "]"
				}
			}
			if s.IPv4 != nil {
				line += fmt.Sprintf(" v4(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", s.IPv4.Lines, s.IPv4.AvgSpeed, s.IPv4.AvgTTFB, s.IPv4.AvgP50Speed)
			}
			if s.IPv6 != nil {
				line += fmt.Sprintf(" v6(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", s.IPv6.Lines, s.IPv6.AvgSpeed, s.IPv6.AvgTTFB, s.IPv6.AvgP50Speed)
			}
			fmt.Println(line)
		}
		// Overall aggregation across all returned batches in analyze-only mode
		if len(summaries) > 1 {
			var totalLines int
			var speeds, ttfbs, bytesVals, firsts, p50s, ratios, jitterPct, slopes, coefVars, plateauCounts, longest []float64
			var cacheCnt, reuseCnt int
			// Per-family accumulators
			var v4Lines, v6Lines int
			var v4SpeedSum, v4TTFBSum, v4P50Sum float64
			var v6SpeedSum, v6TTFBSum, v6P50Sum float64
			for _, s := range summaries {
				if s.Lines == 0 {
					continue
				}
				totalLines += s.Lines
				if s.AvgSpeed > 0 {
					speeds = append(speeds, repeatValue(s.AvgSpeed, s.Lines)...)
				}
				if s.AvgTTFB > 0 {
					ttfbs = append(ttfbs, repeatValue(s.AvgTTFB, s.Lines)...)
				}
				if s.AvgBytes > 0 {
					bytesVals = append(bytesVals, repeatValue(s.AvgBytes, s.Lines)...)
				}
				if s.AvgFirstRTTGoodput > 0 {
					firsts = append(firsts, repeatValue(s.AvgFirstRTTGoodput, s.Lines)...)
				}
				if s.AvgP50Speed > 0 {
					p50s = append(p50s, repeatValue(s.AvgP50Speed, s.Lines)...)
				}
				if s.AvgP99P50Ratio > 0 {
					ratios = append(ratios, repeatValue(s.AvgP99P50Ratio, s.Lines)...)
				}
				if s.AvgJitterPct > 0 {
					jitterPct = append(jitterPct, repeatValue(s.AvgJitterPct, s.Lines)...)
				}
				if s.AvgSlopeKbpsPerSec != 0 {
					slopes = append(slopes, repeatValue(s.AvgSlopeKbpsPerSec, s.Lines)...)
				}
				if s.AvgCoefVariationPct > 0 {
					coefVars = append(coefVars, repeatValue(s.AvgCoefVariationPct, s.Lines)...)
				}
				if s.AvgPlateauCount > 0 {
					plateauCounts = append(plateauCounts, repeatValue(s.AvgPlateauCount, s.Lines)...)
				}
				if s.AvgLongestPlateau > 0 {
					longest = append(longest, repeatValue(s.AvgLongestPlateau, s.Lines)...)
				}
				cacheCnt += int(s.CacheHitRatePct / 100.0 * float64(s.Lines))
				reuseCnt += int(s.ConnReuseRatePct / 100.0 * float64(s.Lines))
				if s.IPv4 != nil && s.IPv4.Lines > 0 {
					v4Lines += s.IPv4.Lines
					v4SpeedSum += s.IPv4.AvgSpeed * float64(s.IPv4.Lines)
					v4TTFBSum += s.IPv4.AvgTTFB * float64(s.IPv4.Lines)
					v4P50Sum += s.IPv4.AvgP50Speed * float64(s.IPv4.Lines)
				}
				if s.IPv6 != nil && s.IPv6.Lines > 0 {
					v6Lines += s.IPv6.Lines
					v6SpeedSum += s.IPv6.AvgSpeed * float64(s.IPv6.Lines)
					v6TTFBSum += s.IPv6.AvgTTFB * float64(s.IPv6.Lines)
					v6P50Sum += s.IPv6.AvgP50Speed * float64(s.IPv6.Lines)
				}
			}
			ov := func(a []float64) float64 {
				if len(a) == 0 {
					return 0
				}
				sum := 0.0
				for _, v := range a {
					sum += v
				}
				return sum / float64(len(a))
			}
			cacheRate := 0.0
			reuseRate := 0.0
			if totalLines > 0 {
				cacheRate = float64(cacheCnt) / float64(totalLines) * 100
				reuseRate = float64(reuseCnt) / float64(totalLines) * 100
			}
			line := fmt.Sprintf("[overall across %d batches] lines=%d avg_speed=%.1f avg_ttfb=%.0f avg_bytes=%.0f first_rtt=%.1f p50=%.1f p99/p50=%.2f jitter=%.1f%% slope=%.2f cov%%=%.1f plateaus=%.1f longest_ms=%.0f cache_hit=%.1f%% reuse=%.1f%%", len(summaries), totalLines, ov(speeds), ov(ttfbs), ov(bytesVals), ov(firsts), ov(p50s), ov(ratios), ov(jitterPct), ov(slopes), ov(coefVars), ov(plateauCounts), ov(longest), cacheRate, reuseRate)
			if v4Lines > 0 {
				line += fmt.Sprintf(" v4(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", v4Lines, v4SpeedSum/float64(v4Lines), v4TTFBSum/float64(v4Lines), v4P50Sum/float64(v4Lines))
			}
			if v6Lines > 0 {
				line += fmt.Sprintf(" v6(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", v6Lines, v6SpeedSum/float64(v6Lines), v6TTFBSum/float64(v6Lines), v6P50Sum/float64(v6Lines))
			}
			fmt.Println(line)
		}
		if len(summaries) == 0 {
			fmt.Println("[analysis] no batches found")
			return
		}
		if len(summaries) == 1 {
			last := summaries[0]
			fmt.Printf("[batch-compare %s] only one batch available\n", last.RunTag)
			if defaultAlerts || *alertsJSON != "" {
				path := *alertsJSON
				if path == "" {
					path = deriveDefaultAlertsPath(last.RunTag)
				}
				writeAlertJSON(path, monitor.SchemaVersion, last, nil, nil, *speedDropAlert, *ttfbIncreaseAlert, *errorRateAlert, *jitterAlert, *p99p50RatioAlert, 1)
			}
			return
		}
		// compute aggregates vs previous batches
		last := summaries[len(summaries)-1]
		var prevAggAvgSpeed, prevAggAvgTTFB float64
		for i := 0; i < len(summaries)-1; i++ {
			prevAggAvgSpeed += summaries[i].AvgSpeed
			prevAggAvgTTFB += summaries[i].AvgTTFB
		}
		prevCount := float64(len(summaries) - 1)
		prevAggAvgSpeed /= prevCount
		prevAggAvgTTFB /= prevCount
		speedDeltaPct := 0.0
		if prevAggAvgSpeed > 0 {
			speedDeltaPct = (last.AvgSpeed - prevAggAvgSpeed) / prevAggAvgSpeed * 100
		}
		ttfbDeltaPct := 0.0
		if prevAggAvgTTFB > 0 {
			ttfbDeltaPct = (last.AvgTTFB - prevAggAvgTTFB) / prevAggAvgTTFB * 100
		}
		classify := func(p float64, invert bool) string {
			v := p
			if invert {
				v = -p
			}
			if v > 10 {
				return "improved"
			}
			if v < -10 {
				return "degraded"
			}
			return "stable"
		}
		fmt.Printf("[batch-compare current=%s prev_batches=%d] avg_speed=%.1f (%.1f%% %s vs %.1f) avg_ttfb=%.0f (%.1f%% %s vs %.0f)\n", last.RunTag, int(prevCount), last.AvgSpeed, speedDeltaPct, classify(speedDeltaPct, false), prevAggAvgSpeed, last.AvgTTFB, ttfbDeltaPct, classify(ttfbDeltaPct, true), prevAggAvgTTFB)
		alerts := []string{}
		if *speedDropAlert > 0 && speedDeltaPct < 0 && -speedDeltaPct >= *speedDropAlert {
			alerts = append(alerts, fmt.Sprintf("speed_drop %.1f%% >= %.1f%%", -speedDeltaPct, *speedDropAlert))
		}
		if *ttfbIncreaseAlert > 0 && ttfbDeltaPct > 0 && ttfbDeltaPct >= *ttfbIncreaseAlert {
			alerts = append(alerts, fmt.Sprintf("ttfb_increase %.1f%% >= %.1f%%", ttfbDeltaPct, *ttfbIncreaseAlert))
		}
		errorRate := 0.0
		if last.Lines > 0 {
			errorRate = float64(last.ErrorLines) / float64(last.Lines) * 100
		}
		if *errorRateAlert > 0 && errorRate >= *errorRateAlert {
			alerts = append(alerts, fmt.Sprintf("error_rate %.1f%% >= %.1f%%", errorRate, *errorRateAlert))
		}
		if *jitterAlert > 0 && last.AvgJitterPct >= *jitterAlert {
			alerts = append(alerts, fmt.Sprintf("jitter %.1f%% >= %.1f%%", last.AvgJitterPct, *jitterAlert))
		}
		if *p99p50RatioAlert > 0 && last.AvgP99P50Ratio >= *p99p50RatioAlert {
			alerts = append(alerts, fmt.Sprintf("p99_p50_ratio %.2f >= %.2f", last.AvgP99P50Ratio, *p99p50RatioAlert))
		}
		if len(alerts) == 0 {
			fmt.Println("[alert none] thresholds not exceeded")
		} else {
			for _, a := range alerts {
				fmt.Printf("[alert %s] batch=%s\n", a, last.RunTag)
			}
		}
		if defaultAlerts || *alertsJSON != "" {
			path := *alertsJSON
			if path == "" {
				path = deriveDefaultAlertsPath(last.RunTag)
			}
			writeAlertJSON(path, monitor.SchemaVersion, last, &struct{ PrevSpeed, PrevTTFB, SpeedDelta, TTFBDelta, ErrorRate float64 }{prevAggAvgSpeed, prevAggAvgTTFB, speedDeltaPct, ttfbDeltaPct, errorRate}, alerts, *speedDropAlert, *ttfbIncreaseAlert, *errorRateAlert, *jitterAlert, *p99p50RatioAlert, len(summaries))
		}
		return
	}

	baseRunTag := time.Now().UTC().Format("20060102_150405")
	defaultAlerts := false
	if *alertsJSON == "" { // user did not supply a path; enable automatic alerts JSON per iteration (repo root preferred)
		defaultAlerts = true
		fmt.Println("[init] alerts-json not provided; will emit per-iteration alert reports at repo root: alerts_<run_tag>.json")
	}
	fmt.Printf("[init] sites=%d iterations=%d parallel=%d out=%s run_tag_base=%s situation=%s go=%s/%s\n", len(sites), *iterations, *parallel, *outFile, baseRunTag, *situation, runtime.GOOS, runtime.GOARCH)

	for it := 0; it < *iterations; it++ {
		iterTag := baseRunTag
		if *iterations > 1 {
			iterTag = fmt.Sprintf("%s_i%d", baseRunTag, it+1)
		}
		monitor.SetRunTag(iterTag)
		fmt.Printf("[iteration %d/%d] run_tag=%s\n", it+1, *iterations, iterTag)

		if *ipFanout {
			// --- IP fanout mode ---
			type ipTask struct {
				site      types.Site
				ip        string
				dnsIPs    []string
				dnsTimeMs int64
				fallback  bool
			}
			var tasks []ipTask
			for _, s := range sites {
				u, err := url.Parse(s.URL)
				if err != nil {
					fmt.Printf("[dns %s] parse error: %v\n", s.Name, err)
					continue
				}
				host := u.Hostname()
				startDNS := time.Now()
				ips, derr := net.LookupIP(host)
				dnsDur := time.Since(startDNS)
				if derr != nil || len(ips) == 0 {
					fmt.Printf("[dns %s] failed: %v\n", s.Name, derr)
					tasks = append(tasks, ipTask{site: s, fallback: true})
					continue
				}
				if *maxIPsPerSite > 0 && len(ips) > *maxIPsPerSite { // apply same limiting logic
					var selected []net.IP
					var v4, v6 net.IP
					for _, ip := range ips {
						if ip.To4() != nil && v4 == nil {
							v4 = ip
						}
						if ip.To4() == nil && v6 == nil {
							v6 = ip
						}
						if v4 != nil && v6 != nil {
							break
						}
					}
					if v4 != nil {
						selected = append(selected, v4)
					}
					if v6 != nil && (*maxIPsPerSite > 1 || v4 == nil) {
						selected = append(selected, v6)
					}
					if len(selected) == 0 {
						selected = ips[:*maxIPsPerSite]
					}
					ips = selected
				}
				var dnsStrs []string
				for _, ip := range ips {
					dnsStrs = append(dnsStrs, ip.String())
				}
				for _, ip := range ips {
					tasks = append(tasks, ipTask{site: s, ip: ip.String(), dnsIPs: dnsStrs, dnsTimeMs: dnsDur.Milliseconds()})
				}
			}
			if len(tasks) == 0 {
				fmt.Println("[ip-fanout] no tasks generated")
			}
			// Debug: print queue before shuffle
			if monitor.GetLogLevel() == monitor.LevelDebug && len(tasks) > 0 {
				pre := make([]string, len(tasks))
				for i, t := range tasks {
					label := t.site.Name
					if t.ip != "" {
						label += "(" + t.ip + ")"
					}
					pre[i] = label
				}
				monitor.Debugf("[ip-fanout] task order before shuffle: %s", strings.Join(pre, ","))
			}
			rand.Shuffle(len(tasks), func(i, j int) { tasks[i], tasks[j] = tasks[j], tasks[i] })
			if monitor.GetLogLevel() == monitor.LevelDebug && len(tasks) > 0 {
				post := make([]string, len(tasks))
				for i, t := range tasks {
					label := t.site.Name
					if t.ip != "" {
						label += "(" + t.ip + ")"
					}
					post[i] = label
				}
				monitor.Debugf("[ip-fanout] task order after shuffle: %s", strings.Join(post, ","))
			}
			workCh := make(chan ipTask)
			var wg sync.WaitGroup
			workerCount := *parallel
			if workerCount < 1 {
				workerCount = 1
			}
			var inFlight int32
			var completed int32
			totalTasks := len(tasks)
			activeSites := make([]string, workerCount)
			var activeMu sync.Mutex
			stopProgress := make(chan struct{})
			if *progressInterval > 0 {
				go func(iter int) {
					ticker := time.NewTicker(*progressInterval)
					defer ticker.Stop()
					lastComp := int32(0)
					lastChange := time.Now()
					warned := false
					for {
						select {
						case <-stopProgress:
							return
						case <-ticker.C:
							inF := atomic.LoadInt32(&inFlight)
							comp := atomic.LoadInt32(&completed)
							remaining := totalTasks - int(comp) - int(inF)
							if remaining < 0 {
								remaining = 0
							}
							if comp != lastComp {
								lastComp = comp
								lastChange = time.Now()
								warned = false
							}
							if *progressSites {
								activeMu.Lock()
								names := []string{}
								for _, n := range activeSites {
									if n != "" {
										names = append(names, n)
									}
								}
								activeMu.Unlock()
								fmt.Printf("[iteration %d progress] workers_busy=%d/%d remaining=%d done=%d/%d active=[%s]\n", iter, inF, workerCount, remaining, comp, totalTasks, strings.Join(names, ","))
							} else {
								fmt.Printf("[iteration %d progress] workers_busy=%d/%d remaining=%d done=%d/%d\n", iter, inF, workerCount, remaining, comp, totalTasks)
							}
							// Simple stall heuristic: only one task left (remaining==0, comp<total), one worker busy for >2 progress intervals without completion
							if !warned && remaining == 0 && int(comp) < totalTasks && inF == 1 {
								stuckFor := time.Since(lastChange)
								if stuckFor >= 2**progressInterval { // two intervals with no forward progress
									fmt.Printf("[iteration %d warn] potential stuck final task (no completion for %s); if persistent consider lowering --site-timeout or adding retry logic.\n", iter, stuckFor.Truncate(time.Second))
									warned = true
								}
							}
						}
					}
				}(it + 1)
			}
			for w := 0; w < workerCount; w++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					for task := range workCh {
						atomic.AddInt32(&inFlight, 1)
						if *progressSites {
							activeMu.Lock()
							name := task.site.Name
							if task.ip != "" {
								name = name + "(" + task.ip + ")"
							}
							activeSites[workerID] = name
							activeMu.Unlock()
						}
						// Execute with one retry on failure conditions (tcp/http/ssl error fields present)
						runOnce := func() *monitor.SiteResult {
							// capture result by temporarily wrapping writer? Simpler: rely on log-level warn detection not result object.
							// For minimal intrusion we add a lightweight in-memory capture by re-running logic is complex; instead, we do a retry only if context times out or TLS/connect errors appear in logs would already have ended quickly.
							if task.fallback {
								monitor.MonitorSite(task.site)
							} else {
								monitor.MonitorSiteIP(task.site, task.ip, task.dnsIPs, task.dnsTimeMs)
							}
							return nil
						}
						runOnce()
						// Simple heuristic: if site-timeout >0 and elapsed close to timeout, skip retry.
						// We don't have direct status; adding a retry unconditionally for fallback or first attempt on IP tasks with no bytes (cannot check). Keeping it conservative: retry only fallback tasks.
						if task.fallback {
							monitor.Debugf("[retry] re-running fallback site %s", task.site.Name)
							runOnce()
						}
						if *progressSites {
							activeMu.Lock()
							activeSites[workerID] = ""
							activeMu.Unlock()
						}
						atomic.AddInt32(&inFlight, -1)
						atomic.AddInt32(&completed, 1)
					}
				}(w)
			}
			for _, t := range tasks {
				workCh <- t
			}
			close(workCh)
			wg.Wait()
			if *progressInterval > 0 {
				close(stopProgress)
			}
			fmt.Printf("[iteration %d] complete (ip-fanout tasks=%d)\n", it+1, len(tasks))
		} else {
			// Original per-site mode
			workCh := make(chan types.Site)
			var wg sync.WaitGroup
			workerCount := *parallel
			if workerCount < 1 {
				workerCount = 1
			}
			var inFlight int32
			var completed int32
			totalSites := len(sites)
			activeSites := make([]string, workerCount)
			var activeMu sync.Mutex
			stopProgress := make(chan struct{})
			if *progressInterval > 0 {
				go func(iter int) {
					ticker := time.NewTicker(*progressInterval)
					defer ticker.Stop()
					for {
						select {
						case <-stopProgress:
							return
						case <-ticker.C:
							inF := atomic.LoadInt32(&inFlight)
							comp := atomic.LoadInt32(&completed)
							remaining := totalSites - int(comp) - int(inF)
							if remaining < 0 {
								remaining = 0
							}
							if *progressSites {
								activeMu.Lock()
								names := []string{}
								for _, n := range activeSites {
									if n != "" {
										names = append(names, n)
									}
								}
								activeMu.Unlock()
								fmt.Printf("[iteration %d progress] workers_busy=%d/%d remaining=%d done=%d/%d active=[%s]\n", iter, inF, workerCount, remaining, comp, totalSites, strings.Join(names, ","))
							} else {
								fmt.Printf("[iteration %d progress] workers_busy=%d/%d remaining=%d done=%d/%d\n", iter, inF, workerCount, remaining, comp, totalSites)
							}
						}
					}
				}(it + 1)
			}
			for w := 0; w < workerCount; w++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					for site := range workCh {
						atomic.AddInt32(&inFlight, 1)
						if *progressSites {
							ipSuffix := ""
							if *progressResolveIP {
								if u, err := url.Parse(site.URL); err == nil {
									host := u.Hostname()
									resCh := make(chan []string, 1)
									go func(h string) {
										ips, _ := net.LookupIP(h)
										var out []string
										for _, ip := range ips {
											out = append(out, ip.String())
											if len(out) >= 2 {
												break
											}
										}
										resCh <- out
									}(host)
									select {
									case ips := <-resCh:
										if len(ips) > 0 {
											ipSuffix = "(" + strings.Join(ips, "/") + ")"
										}
									case <-time.After(1 * time.Second):
										ipSuffix = "(dns-timeout)"
									}
								}
							}
							activeMu.Lock()
							activeSites[workerID] = site.Name + ipSuffix
							activeMu.Unlock()
						}
						monitor.MonitorSite(site)
						if *progressSites {
							activeMu.Lock()
							activeSites[workerID] = ""
							activeMu.Unlock()
						}
						atomic.AddInt32(&inFlight, -1)
						atomic.AddInt32(&completed, 1)
					}
				}(w)
			}
			for _, s := range sites {
				workCh <- s
			}
			close(workCh)
			wg.Wait()
			if *progressInterval > 0 {
				close(stopProgress)
			}
			fmt.Printf("[iteration %d] complete\n", it+1)
		}

		// Run analysis after each iteration (consider last N batches up to iterations so far, capped at 10)
		batchesToParse := *iterations
		if batchesToParse > 10 {
			batchesToParse = 10
		}
		fmt.Printf("[iteration %d analysis] performing rolling analysis over last %d batch(es) including current iteration\n", it+1, batchesToParse)
		alertsPath := *alertsJSON
		if defaultAlerts { // derive unique filename incorporating the iteration tag, prefer repo root if running inside src
			alertsPath = deriveDefaultAlertsPath(iterTag)
		}
		performAnalysis(*outFile, monitor.SchemaVersion, batchesToParse, *speedDropAlert, *ttfbIncreaseAlert, *errorRateAlert, *jitterAlert, *p99p50RatioAlert, alertsPath, *situation)
	}

	// Optional final full analysis after all iterations if requested
	if *finalAnalysisBatches > 0 {
		fmt.Printf("[final analysis] requested --final-analysis-batches=%d; performing analysis over last %d batch(es)\n", *finalAnalysisBatches, *finalAnalysisBatches)
		performAnalysis(*outFile, monitor.SchemaVersion, *finalAnalysisBatches, *speedDropAlert, *ttfbIncreaseAlert, *errorRateAlert, *jitterAlert, *p99p50RatioAlert, *alertsJSON, *situation)
	}

}

// performAnalysis uses the analysis package and prints summaries & alerts.
// performAnalysis loads up to n recent batches from path and evaluates alert conditions comparing newest vs aggregate of previous.
// Used in collection mode after each iteration.
func performAnalysis(path string, schemaVersion, n int, speedDropThresh, ttfbIncreaseThresh, errorRateThresh, jitterThresh, ratioThresh float64, alertsJSONPath string, situationFilter string) {
	fmt.Printf("[analysis start] evaluating up to last %d batch(es) from %s\n", n, path)
	summaries, err := analysis.AnalyzeRecentResultsFull(path, schemaVersion, n, situationFilter)
	if err != nil {
		fmt.Printf("[analysis] %v\n", err)
		return
	}
	for _, s := range summaries {
		line := fmt.Sprintf("[batch %s] (per-batch) lines=%d dur=%dms avg_speed=%.1f median=%.1f ttfb=%.0f bytes=%.0f errors=%d first_rtt_kbps=%.1f p50=%.1f p99/p50=%.2f plateaus=%.1f longest_ms=%.0f jitter=%.1f%%",
			s.RunTag, s.Lines, s.BatchDurationMs, s.AvgSpeed, s.MedianSpeed, s.AvgTTFB, s.AvgBytes, s.ErrorLines, s.AvgFirstRTTGoodput, s.AvgP50Speed, s.AvgP99P50Ratio, s.AvgPlateauCount, s.AvgLongestPlateau, s.AvgJitterPct)
		if s.IPv4 != nil {
			line += fmt.Sprintf(" v4(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", s.IPv4.Lines, s.IPv4.AvgSpeed, s.IPv4.AvgTTFB, s.IPv4.AvgP50Speed)
		}
		if s.IPv6 != nil {
			line += fmt.Sprintf(" v6(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", s.IPv6.Lines, s.IPv6.AvgSpeed, s.IPv6.AvgTTFB, s.IPv6.AvgP50Speed)
		}
		fmt.Println(line)
	}
	if len(summaries) == 0 {
		return
	}
	// Overall multi-batch aggregation (line-weighted) for context in collection mode analysis
	if len(summaries) > 1 {
		var totalLines int
		var speeds, ttfbs, bytesVals, firsts, p50s, ratios, jitterPct, slopes, coefVars, plateauCounts, longest []float64
		var cacheCnt, reuseCnt int
		var v4Lines, v6Lines int
		var v4SpeedSum, v4TTFBSum, v4P50Sum float64
		var v6SpeedSum, v6TTFBSum, v6P50Sum float64
		for _, s := range summaries {
			if s.Lines == 0 {
				continue
			}
			totalLines += s.Lines
			if s.AvgSpeed > 0 {
				speeds = append(speeds, repeatValue(s.AvgSpeed, s.Lines)...)
			}
			if s.AvgTTFB > 0 {
				ttfbs = append(ttfbs, repeatValue(s.AvgTTFB, s.Lines)...)
			}
			if s.AvgBytes > 0 {
				bytesVals = append(bytesVals, repeatValue(s.AvgBytes, s.Lines)...)
			}
			if s.AvgFirstRTTGoodput > 0 {
				firsts = append(firsts, repeatValue(s.AvgFirstRTTGoodput, s.Lines)...)
			}
			if s.AvgP50Speed > 0 {
				p50s = append(p50s, repeatValue(s.AvgP50Speed, s.Lines)...)
			}
			if s.AvgP99P50Ratio > 0 {
				ratios = append(ratios, repeatValue(s.AvgP99P50Ratio, s.Lines)...)
			}
			if s.AvgJitterPct > 0 {
				jitterPct = append(jitterPct, repeatValue(s.AvgJitterPct, s.Lines)...)
			}
			if s.AvgSlopeKbpsPerSec != 0 {
				slopes = append(slopes, repeatValue(s.AvgSlopeKbpsPerSec, s.Lines)...)
			}
			if s.AvgCoefVariationPct > 0 {
				coefVars = append(coefVars, repeatValue(s.AvgCoefVariationPct, s.Lines)...)
			}
			if s.AvgPlateauCount > 0 {
				plateauCounts = append(plateauCounts, repeatValue(s.AvgPlateauCount, s.Lines)...)
			}
			if s.AvgLongestPlateau > 0 {
				longest = append(longest, repeatValue(s.AvgLongestPlateau, s.Lines)...)
			}
			cacheCnt += int(s.CacheHitRatePct / 100.0 * float64(s.Lines))
			reuseCnt += int(s.ConnReuseRatePct / 100.0 * float64(s.Lines))
			if s.IPv4 != nil && s.IPv4.Lines > 0 {
				v4Lines += s.IPv4.Lines
				v4SpeedSum += s.IPv4.AvgSpeed * float64(s.IPv4.Lines)
				v4TTFBSum += s.IPv4.AvgTTFB * float64(s.IPv4.Lines)
				v4P50Sum += s.IPv4.AvgP50Speed * float64(s.IPv4.Lines)
			}
			if s.IPv6 != nil && s.IPv6.Lines > 0 {
				v6Lines += s.IPv6.Lines
				v6SpeedSum += s.IPv6.AvgSpeed * float64(s.IPv6.Lines)
				v6TTFBSum += s.IPv6.AvgTTFB * float64(s.IPv6.Lines)
				v6P50Sum += s.IPv6.AvgP50Speed * float64(s.IPv6.Lines)
			}
		}
		ov := func(a []float64) float64 {
			if len(a) == 0 {
				return 0
			}
			sum := 0.0
			for _, v := range a {
				sum += v
			}
			return sum / float64(len(a))
		}
		cacheRate := 0.0
		reuseRate := 0.0
		if totalLines > 0 {
			cacheRate = float64(cacheCnt) / float64(totalLines) * 100
			reuseRate = float64(reuseCnt) / float64(totalLines) * 100
		}
		line := fmt.Sprintf("[overall across %d batches] lines=%d avg_speed=%.1f avg_ttfb=%.0f avg_bytes=%.0f first_rtt=%.1f p50=%.1f p99/p50=%.2f jitter=%.1f%% slope=%.2f cov%%=%.1f plateaus=%.1f longest_ms=%.0f cache_hit=%.1f%% reuse=%.1f%%", len(summaries), totalLines, ov(speeds), ov(ttfbs), ov(bytesVals), ov(firsts), ov(p50s), ov(ratios), ov(jitterPct), ov(slopes), ov(coefVars), ov(plateauCounts), ov(longest), cacheRate, reuseRate)
		if v4Lines > 0 {
			line += fmt.Sprintf(" v4(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", v4Lines, v4SpeedSum/float64(v4Lines), v4TTFBSum/float64(v4Lines), v4P50Sum/float64(v4Lines))
		}
		if v6Lines > 0 {
			line += fmt.Sprintf(" v6(lines=%d spd=%.1f ttfb=%.0f p50=%.1f)", v6Lines, v6SpeedSum/float64(v6Lines), v6TTFBSum/float64(v6Lines), v6P50Sum/float64(v6Lines))
		}
		fmt.Println(line)
	}
	if len(summaries) == 1 {
		fmt.Printf("[batch-compare %s] only one batch available\n", summaries[0].RunTag)
		if alertsJSONPath != "" {
			writeAlertJSON(alertsJSONPath, schemaVersion, summaries[0], nil, nil, speedDropThresh, ttfbIncreaseThresh, errorRateThresh, jitterThresh, ratioThresh, 1)
		}
		return
	}
	last := summaries[len(summaries)-1]
	var prevAggAvgSpeed, prevAggAvgTTFB float64
	for i := 0; i < len(summaries)-1; i++ {
		prevAggAvgSpeed += summaries[i].AvgSpeed
		prevAggAvgTTFB += summaries[i].AvgTTFB
	}
	prevCount := float64(len(summaries) - 1)
	prevAggAvgSpeed /= prevCount
	prevAggAvgTTFB /= prevCount
	speedDeltaPct := 0.0
	if prevAggAvgSpeed > 0 {
		speedDeltaPct = (last.AvgSpeed - prevAggAvgSpeed) / prevAggAvgSpeed * 100
	}
	ttfbDeltaPct := 0.0
	if prevAggAvgTTFB > 0 {
		ttfbDeltaPct = (last.AvgTTFB - prevAggAvgTTFB) / prevAggAvgTTFB * 100
	}
	classify := func(p float64, invert bool) string {
		v := p
		if invert {
			v = -p
		}
		if v > 10 {
			return "improved"
		}
		if v < -10 {
			return "degraded"
		}
		return "stable"
	}
	fmt.Printf("[batch-compare current=%s prev_batches=%d] avg_speed=%.1f (%.1f%% %s vs %.1f) avg_ttfb=%.0f (%.1f%% %s vs %.0f)\n", last.RunTag, int(prevCount), last.AvgSpeed, speedDeltaPct, classify(speedDeltaPct, false), prevAggAvgSpeed, last.AvgTTFB, ttfbDeltaPct, classify(ttfbDeltaPct, true), prevAggAvgTTFB)
	alerts := []string{}
	if speedDropThresh > 0 && speedDeltaPct < 0 && -speedDeltaPct >= speedDropThresh {
		alerts = append(alerts, fmt.Sprintf("speed_drop %.1f%% >= %.1f%%", -speedDeltaPct, speedDropThresh))
	}
	if ttfbIncreaseThresh > 0 && ttfbDeltaPct > 0 && ttfbDeltaPct >= ttfbIncreaseThresh {
		alerts = append(alerts, fmt.Sprintf("ttfb_increase %.1f%% >= %.1f%%", ttfbDeltaPct, ttfbIncreaseThresh))
	}
	errorRate := 0.0
	if last.Lines > 0 {
		errorRate = float64(last.ErrorLines) / float64(last.Lines) * 100
	}
	if errorRateThresh > 0 && errorRate >= errorRateThresh {
		alerts = append(alerts, fmt.Sprintf("error_rate %.1f%% >= %.1f%%", errorRate, errorRateThresh))
	}
	if jitterThresh > 0 && last.AvgJitterPct >= jitterThresh {
		alerts = append(alerts, fmt.Sprintf("jitter %.1f%% >= %.1f%%", last.AvgJitterPct, jitterThresh))
	}
	if ratioThresh > 0 && last.AvgP99P50Ratio >= ratioThresh {
		alerts = append(alerts, fmt.Sprintf("p99_p50_ratio %.2f >= %.2f", last.AvgP99P50Ratio, ratioThresh))
	}
	if len(alerts) == 0 {
		fmt.Println("[alert none] thresholds not exceeded")
	} else {
		for _, a := range alerts {
			fmt.Printf("[alert %s] batch=%s\n", a, last.RunTag)
		}
	}
	if alertsJSONPath != "" {
		writeAlertJSON(alertsJSONPath, schemaVersion, last, &struct{ PrevSpeed, PrevTTFB, SpeedDelta, TTFBDelta, ErrorRate float64 }{prevAggAvgSpeed, prevAggAvgTTFB, speedDeltaPct, ttfbDeltaPct, errorRate}, alerts, speedDropThresh, ttfbIncreaseThresh, errorRateThresh, jitterThresh, ratioThresh, len(summaries))
	}
}

// writeAlertJSON persists a structured alert report capturing the latest batch summary, optional comparison, thresholds & alerts.
type alertThresholds struct {
	SpeedDropPct    float64 `json:"speed_drop_pct"`
	TTFBIncreasePct float64 `json:"ttfb_increase_pct"`
	ErrorRatePct    float64 `json:"error_rate_pct"`
	JitterPct       float64 `json:"jitter_pct"`
	P99P50Ratio     float64 `json:"p99_p50_ratio"`
}
type lastBatchSummary struct {
	Lines               int     `json:"lines"`
	AvgSpeedKbps        float64 `json:"avg_speed_kbps"`
	MedianSpeedKbps     float64 `json:"median_speed_kbps"`
	AvgTTFBMs           float64 `json:"avg_ttfb_ms"`
	AvgBytes            float64 `json:"avg_bytes"`
	ErrorLines          int     `json:"error_lines"`
	ErrorRatePct        float64 `json:"error_rate_pct"`
	FirstRTTGoodputKbps float64 `json:"first_rtt_goodput_kbps"`
	P50Kbps             float64 `json:"p50_kbps"`
	P99P50Ratio         float64 `json:"p99_p50_ratio"`
	PlateauCount        float64 `json:"plateau_count"`
	LongestPlateauMs    float64 `json:"longest_plateau_ms"`
	JitterMeanAbsPct    float64 `json:"jitter_mean_abs_pct"`
}
type comparisonSummary struct {
	PrevAvgSpeedKbps float64 `json:"prev_avg_speed_kbps"`
	PrevAvgTTFBMs    float64 `json:"prev_avg_ttfb_ms"`
	SpeedDeltaPct    float64 `json:"speed_delta_pct"`
	TTFBDeltaPct     float64 `json:"ttfb_delta_pct"`
	ErrorRatePct     float64 `json:"error_rate_pct"`
}
type alertReport struct {
	GeneratedAt      string             `json:"generated_at"`
	SchemaVersion    int                `json:"schema_version"`
	RunTag           string             `json:"run_tag"`
	BatchesCompared  int                `json:"batches_compared"`
	LastBatchSummary lastBatchSummary   `json:"last_batch_summary"`
	Comparison       *comparisonSummary `json:"comparison,omitempty"`
	SingleBatch      bool               `json:"single_batch,omitempty"`
	Alerts           []string           `json:"alerts"`
	Thresholds       alertThresholds    `json:"thresholds"`
}

func writeAlertJSON(path string, schemaVersion int, last analysis.BatchSummary, comp *struct{ PrevSpeed, PrevTTFB, SpeedDelta, TTFBDelta, ErrorRate float64 }, alerts []string, speedDrop, ttfbInc, errRate, jitter, ratio float64, batchesCompared int) {
	if alerts == nil {
		alerts = []string{}
	}
	errRatePct := 0.0
	if last.Lines > 0 {
		errRatePct = float64(last.ErrorLines) / float64(last.Lines) * 100
	}
	rep := alertReport{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		SchemaVersion:   schemaVersion,
		RunTag:          last.RunTag,
		BatchesCompared: batchesCompared,
		LastBatchSummary: lastBatchSummary{
			Lines:               last.Lines,
			AvgSpeedKbps:        last.AvgSpeed,
			MedianSpeedKbps:     last.MedianSpeed,
			AvgTTFBMs:           last.AvgTTFB,
			AvgBytes:            last.AvgBytes,
			ErrorLines:          last.ErrorLines,
			ErrorRatePct:        errRatePct,
			FirstRTTGoodputKbps: last.AvgFirstRTTGoodput,
			P50Kbps:             last.AvgP50Speed,
			P99P50Ratio:         last.AvgP99P50Ratio,
			PlateauCount:        last.AvgPlateauCount,
			LongestPlateauMs:    last.AvgLongestPlateau,
			JitterMeanAbsPct:    last.AvgJitterPct,
		},
		Alerts:     alerts,
		Thresholds: alertThresholds{SpeedDropPct: speedDrop, TTFBIncreasePct: ttfbInc, ErrorRatePct: errRate, JitterPct: jitter, P99P50Ratio: ratio},
	}
	if comp != nil {
		rep.Comparison = &comparisonSummary{PrevAvgSpeedKbps: comp.PrevSpeed, PrevAvgTTFBMs: comp.PrevTTFB, SpeedDeltaPct: comp.SpeedDelta, TTFBDeltaPct: comp.TTFBDelta, ErrorRatePct: comp.ErrorRate}
	} else {
		rep.SingleBatch = true
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		fmt.Printf("[analysis] write alerts json error: %v\n", err)
	} else {
		fmt.Printf("[analysis] wrote alert report JSON: %s\n", path)
	}
}

// deriveDefaultAlertsPath returns a path for the alert JSON at the repo root when running from the src directory.
// deriveDefaultAlertsPath returns an alerts_<run_tag>.json path; if CWD is src/, write to parent repo root.
func deriveDefaultAlertsPath(runTag string) string {
	name := fmt.Sprintf("alerts_%s.json", runTag)
	cwd, err := os.Getwd()
	if err != nil {
		return name
	}
	base := filepath.Base(cwd)
	if base == "src" { // assume repository root is parent
		parent := filepath.Dir(cwd)
		return filepath.Join(parent, name)
	}
	return filepath.Join(cwd, name)
}
