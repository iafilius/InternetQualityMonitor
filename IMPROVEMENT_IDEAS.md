# Monitoring Improvement Ideas & Speed Pattern Definitions

This document captures ideas for extracting richer telemetry (with or without a transparent proxy) and the current speed pattern heuristics implemented / proposed.

## 1. Connection & DNS
- Fine‑grained phase timings via `httptrace`: DNSStart/Done, ConnectStart/Done, TLSHandshakeStart/Done, GotFirstResponseByte.
- Record DNS server IP, answer count, A vs AAAA, per‑RR latency, cache indicator.
- Resolve all returned IPs; optionally test each (multi-homing/CDN variance); annotate chosen vs fastest.
- TCP RTT estimate (SYN timing) or light ICMP/TCP ping before transfer; store min/avg.

## 2. TLS / Security
- TLS version, cipher suite, ALPN (h2 vs http/1.1), session resumption reused?, key exchange type.
- Certificate: issuer CN, SAN count, days to expiry, OCSP stapling presence.
- MITM / proxy clues: unexpected issuer, downgraded TLS version, missing ALPN, added headers (Via, X-Forwarded-For).

## 3. HTTP Layer
- Status code & redirect chain with per-hop timing.
- Key headers: Server, Via, Age, Cache-Control, Content-Length, Content-Encoding, ETag, Last-Modified.
- Separate metrics: TTFB vs transfer duration.
- Compression ratio: uncompressed_estimate / wire_size if Content-Encoding present.
- Chunked vs fixed length detection.

## 4. Throughput & Stability Metrics
- Existing: average, stddev, pattern detection.
- Add: median, min, max, p50, p90, p95, p99, IQR, coefficient of variation.
	- p50 (median): typical sustained speed; robust against outliers; good baseline.
	- p90: 90% of samples are at or below this; gap between p50 and p90 shows higher-end burst capacity.
	- p95: highlights occasional higher spikes; large p95 - p50 indicates intermittent bursts (maybe congestion relief moments).
	- p99: tail of distribution; if p99 >> p95 the very top speeds are rare spikes (bufferbloat recovery, transient caching, TCP window growth spurts).
	- Interpretation patterns:
		* Narrow spread (p99/p50 < 1.2) => very stable link.
		* Moderate spread (1.2–1.8) => normal WAN variability.
		* High spread (>1.8) with high stddev => volatile; possible congestion, policing, or shared medium contention.
		* If slope positive but p90 ~ p50 (little headroom) => slow ramp but quickly plateaus (maybe high RTT / small initcwnd).
		* High p99 with low median => short opportunistic bursts (possibly queue draining or short-lived cross-traffic gaps).
- Rolling jitter: mean absolute percent change between consecutive samples.
- Plateau detection: consecutive samples within ±X% threshold (count & durations).
- Linear regression slope on (time, speed) for ramp/decline classification.
- Goodput in first RTT window (approx initial congestion window behavior).

## 5. Advanced Transfer Scenarios
- Two-phase test: small object (latency) + large object (throughput plateau).
- Parallel fetches (N identical downloads) for fairness / per-flow throttling detection.
- Range requests: verify `Accept-Ranges`; compare partial vs full speed.
- Warm cache test: immediate repeat request diff.

## 6. Proxy / Caching Detection
- Compare DNS resolved IP(s) vs `conn.RemoteAddr()`; mismatch suggests interception.
- Headers: Via, X-Cache, Age; detect cache hit (Age > 0 or X-Cache: HIT).
- Inject custom header (e.g., `X-Probe: <rand>`); confirm unmodified echo/absence.
- Timing difference HEAD vs GET; large discrepancy may indicate proxy prefetching.

## 7. Path & Geography
- GeoIP ASN + ISP/Org (ASN DB).
- Infer hop count from initial TTL (64/128/255 heuristics) minus observed TTL if captured (requires raw socket or pcap/traceroute).
- Optional asynchronous traceroute; store path signature hash to detect changes.

## 8. Environment & Host Context
- Local interface, IP, MTU.
- Active congestion control algorithm (`/proc/sys/net/ipv4/tcp_congestion_control`).
- System load averages, CPU steal %, network namespace identifier.
- Tool version + build hash for reproducibility.

## 9. Robustness & Error Handling
- Unified error taxonomy: dns_error, tcp_error, tls_error, http_error, read_error.
- Retry policy with backoff for transient categories; record attempt count.
- Capture partial metrics even on failure (e.g., DNS + TCP times when TLS fails).

## 10. Data Model Enhancements
- `schema_version` field.
- Embed configuration snapshot (sample_interval_ms, parallel_downloads, user_agent, extended_tests_enabled).
- Executable hash (SHA256), build timestamp.

## 11. Anomaly Flags (Booleans)
- `possible_proxy`
- `cache_present`
- `volatility_high`
- `ramp_slow`
- `decline_detected`
- `mid_dip`
- `plateau_stable`

## 12. Optional Stretch Goals
- QUIC/HTTP3 probe for latency/throughput comparison.
- Passive loss inference: detect long read stalls > threshold.
- DNS over HTTPS vs classic DNS comparative timing.

---

## Current / Proposed Speed Pattern Heuristics
(Implemented or suggested in `monitor.go`)

| Pattern Key (description) | Trigger Logic (simplified) |
|---------------------------|----------------------------|
| slow start until max speed | first < 0.5 * max |
| good speed at begin but slow in the end | last < 0.5 * max |
| highly volatile speed measurement over whole window | stddev > 0.5 * mean |
| stable speed throughout transfer | stddev < 0.1 * mean |
| fast start, reaches max speed quickly | first > 0.8 * max |
| fast end, maintains speed until finish | last > 0.8 * max |
| mid-transfer dip: speed drops in the middle | mid < 0.5 * max & first,last > 0.7 * max |
| slow start, then speed recovers mid-transfer | first < 0.5 * max & mid > 0.8 * max |
| gradual decline: speed decreases throughout | monotonic decreasing & first > last |
| gradual increase: speed increases throughout | monotonic increasing & last > first |

### Potential Additional Patterns
- Oscillating: alternating up/down beyond a % threshold.
- Early plateau: reaches ≥0.9 * max within first 20% time and stays ±10%.
- Late surge: last 20% includes new max > 1.1 * previous max.
- Multi-phase: two distinct plateaus separated by dip > X%.

## Implementation Ordering Suggestion
1. Add config + httptrace instrumentation.
2. Extend schema with version + config snapshot + basic TLS/meta.
3. Add percentile & regression-based stability stats.
4. Introduce anomaly flags & refined pattern detection.
5. Add proxy/cache detection logic (headers, repeat request).
6. Add multi-IP and ASN/Org enrichment.
7. Parallel / range / warm cache tests.
8. (Optional) Traceroute + QUIC.

## Notes
- Keep additional tests optional (config flags) to control runtime cost.
- Persist raw samples; derived metrics can be recomputed offline.
- Document schema changes with version bumps.

---

## TODO / Bugs

- Viewer: Screen not updated when filtered batches == 1
	- Repro:
		1) Open viewer and load a results file with at least two situations, where one situation has only 1 batch.
		2) Select that situation from the Situation drop-down (Batch X-axis mode).
		3) Observe: table updates, but sometimes the chart image doesn’t change (appears stale) even though filteredSummaries returns 1.
	- Notes:
		- We already pad X-axis ranges and duplicate the single point for go-chart, and we refresh canvases/overlays.
		- Likely a repaint race or image cache edge when dimensions don’t change. Possible fix: force a two-step image swap (set Image=nil and Refresh, then set new image and Refresh) or swap to a 1px different MinSize before setting back.
		- Also check Time axis path for single timestamp and verify legend/series changes trigger a repaint.

### Backlog / Sizing & Font Uniformity

1. Chart Font Uniformity Test & Enforcement
	- Add a lightweight test in `cmd/iqmviewer/main_test.go` that invokes the custom renderers (detailed Host/IP and batch Host/IP timing charts) and inspects chosen font sizes (e.g., by wrapping `loadDynamicFontFace` or exposing selected size via a debug hook) to ensure they do not regress below a minimum readable threshold (e.g., 14pt for medium bars, 20pt for large bars).
	- Provide a central mapping for (barHeight -> fontSize) to avoid duplicate switch statements; simplifies future global adjustments.
	- Consider an environment var override (e.g., `IQM_VIEWER_FONT_SCALE=1.2`) for quick user scaling.

2. User-Selectable Sizing Modes
	- Add a dropdown or settings dialog (Compact / Normal / Large / Huge) that influences bar height & gap scaling factors across all custom charts for consistent look.
	- Persist preference in existing viewer prefs.

3. Scroll vs. Compress Strategy
	- For > 40 batches, optionally allow a vertical scroll container instead of shrinking bar heights; preserves legibility for large historical windows.
	- Add toggle: "Auto Compress" vs "Scroll".

4. Legend / Phase Key Panel
	- Provide a small legend panel (DNS/TCP/TLS/Wait/Transfer/Stall colors) reused by both detailed and batch Host/IP charts; reduces need for repeated inline labels when bars become very wide.

5. Export Font Consistency
	- Ensure export re-render path uses same sizing logic but can optionally upscale font slightly (e.g., +2pt) for high-DPI clarity.
	- Add integration test: export all charts to a temp dir and validate PNG dimensions & presence; future enhancement could parse PNG text chunk to confirm watermark.

6. Performance Optimization (Single-Pass Aggregation)
	- Replace per-batch file rescans with a single streaming pass building structures for all batches, then compute both detailed and batch aggregate timing charts. Improves load time for large result sets.

7. Accessibility / High Contrast Mode
	- Offer alt color palette for color-blind accessibility (e.g., ColorBrewer Set2 or Tol palette) selectable via settings.

8. Optional Global Font Override
	- Config field to specify a TTF path; load once and propagate to all chart renderers for uniform typography.

9. Unit Tests for Sizing Regression
	- Store representative synthetic batch counts (e.g., 4, 8, 16, 32, 40) and assert computed bar height & font size pairs against expected golden values.

10. Watermark & Title Scaling
	- Scale watermark and title text proportionally to base font to avoid tiny watermark on very tall charts.


