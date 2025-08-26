# Internet Monitor

This project monitors various aspects of internet connectivity for a list of HTTP(S) sites hosted in different countries. It supports local monitoring (with Zscaler client) and remote monitoring over SSH (unmodified internet).

## TL;DR
Quick network performance + proxy/cache heuristics monitor + batch analyzer.

The binary has TWO modes now:
- Collection mode (default): actively probe all sites (optionally via per-IP task fanout) and append new lines, then analyze.
- Analyze-only: read existing `monitor_results.jsonl` batches, print summaries / deltas, emit alert JSON. Enable with `--analyze-only=true`.

Recent changes:
- Per-IP-family aggregation: batch JSON summaries now include `ipv4` / `ipv6` objects with the same metrics (averages & rates) restricted to that family. Console lines append succinct `v4(...)/v6(...)` segments when present.
- High-resolution speed fallback: ultra-fast tiny transfers (<1ms) now compute non-zero speeds (previously rounded to 0 when duration in whole ms was 0).
- Expanded proxy / CDN / enterprise security proxy detection: new fields `proxy_name`, `proxy_source`, `proxy_indicators` classify common CDNs (cloudfront, fastly, akamai, cloudflare, azurecdn, cachefly, google) plus enterprise proxies (zscaler, bluecoat, netskope, paloalto, forcepoint, varnish, squid) and record raw header tokens used for detection.
 - Environment proxy awareness & usage tracking: fields `env_proxy_url`, `env_proxy_bypassed`, `using_env_proxy` indicate proxy configuration and whether a proxy transport path was actually used; `proxy_remote_ip` / `proxy_remote_is_proxy` record the proxy endpoint address.
 - Origin IP candidate: `origin_ip_candidate` provides a best-effort origin server IP (direct connections: equals `remote_ip`; proxied: first DNS IP) to retain geographic/ASN context when tunneling through a proxy.
 - TLS certificate heuristics: `tls_cert_subject`, `tls_cert_issuer` captured for corporate proxy MITM detection (zscaler, bluecoat, netskope, paloalto, forcepoint, etc.).
 - Batch proxy aggregation metrics: analysis now reports `env_proxy_usage_rate_pct`, `classified_proxy_rate_pct`, per `proxy_name_counts` & `proxy_name_rate_pct` maps; console adds `env_proxy=` and `proxy_classified=` percentages plus top proxy names for quick scan.
 - Overall multi-batch aggregation line: when more than one batch is analyzed, an additional `overall across <N> batches` line is printed, showing line-weighted aggregate metrics (including IPv4/IPv6 splits) across all displayed batches. Individual batch lines are now marked with `(per-batch)` for clarity.
- Console output units: analysis lines now include explicit units for clarity (kbps, ms, B, kbps/s).

First time (no results yet) you likely want to collect data (this is now the default mode):
```bash
go run ./src/main.go --analyze-only=false --iterations 1 --parallel 2
```

Subsequent (analyze latest 10 batches only):
```bash
go run ./src/main.go
```

Collect 3 new batches (interleaving analysis after each) with 5 workers:
```bash
go run ./src/main.go --analyze-only=false --parallel 5 --iterations 3
```

Specify a custom output file for results & then analyze it:
```bash
go run ./src/main.go --analyze-only=false --out results_$(date +%Y%m%d).jsonl
go run ./src/main.go --out results_$(date +%Y%m%d).jsonl  # analyze only
```

Pretty-print last result line:
```bash
tail -n 1 monitor_results.jsonl | jq '.'
```

What you get per site (JSON line):
- Phase timings: DNS / TCP / TLS / TTFB / connect
- Throughput stats: p50/p90/p95/p99, stddev, CoV, jitter, slope, plateaus
- Patterns + human-readable insights
- Cache/proxy indicators (Age, X-Cache, Via, IP mismatch, warm HEAD, range GET)
- Geo & ASN enrichment
- First RTT goodput

Key object: `speed_analysis` (stats, patterns, plateaus, insights)

Exit after iterations; appends continuously to the output JSONL (default `monitor_results.jsonl`) via an async single-writer queue.


## Getting started (beginners)

Prerequisite: Go 1.22 or newer (see `go.mod`). If `go version` fails or shows an older version, install/update Go using one of the options below.

macOS (Homebrew):

```bash
brew update
brew install go
go version
```

Ubuntu/Debian:
- Easiest (Snap, usually latest stable):

```bash
sudo snap install go --classic
go version
```

- APT (may be older on some releases):

```bash
sudo apt-get update
sudo apt-get install -y golang-go
go version
```

- Official tarball (recommended if you need the very latest):
   1) Find the latest version at https://go.dev/dl/
   2) Download the tarball matching your CPU/arch (example below uses amd64 and 1.22.x):

```bash
cd /tmp
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz   # replace with the latest
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
go version
```

Windows:
- Using winget (Windows 10/11):

```powershell
winget install GoLang.Go
go version
```

- Using Chocolatey:

```powershell
choco install golang -y
go version
```

- Or download the MSI installer from https://go.dev/dl/ and follow the wizard (adds Go to PATH). Reopen your terminal and run `go version` to verify.

Quick repo smoke test after installing Go:

```bash
go build ./...
go test ./...
```

If both commands succeed, you’re ready to run the monitor.

Fedora:

```bash
sudo dnf install -y golang
go version
```

Arch Linux:

```bash
sudo pacman -Syu --needed go
go version
```

Nix / NixOS:
- One-off shell with Go available:

```bash
nix-shell -p go
# inside the shell
go version
```

- Or install into your user profile (persistent):

```bash
nix profile install nixpkgs#go
go version
```


## Features
Core timing & network phases:
- DNS resolution time, TCP connect time, TLS handshake time
- HTTP connect + granular phase timings via httptrace (DNS, connect, TLS, time-to-conn, TTFB)

Transfer performance:
- Full transfer time, size, instantaneous sampled speeds (100ms interval)
- Statistical speed analysis: min / max / average / stddev / coefficient of variation
- Percentiles: p50, p90, p95, p99
- Linear regression slope (kbps/s) to detect ramp-up or decline
- Jitter (mean absolute percent change between consecutive samples)
- Pattern heuristics (slow start, mid-transfer dip, gradual increase/decline, volatility, plateau etc.)
- Plateau detection (segments within ±10% of median throughput) with count, longest duration, stability flag
- First RTT goodput estimation (bytes delivered within 1 RTT and derived kbps)

Caching / proxy / CDN heuristics:
- Detects cache indicators (Age header, X-Cache HIT, Via)
- Prefetch suspicion (GET much faster than HEAD)
- IP mismatch (resolved DNS IPs vs remote connection IP)
- Secondary Range GET timing + header inspection
- Warm HEAD probe (connection reuse / cache speedup)
- Probe header echo detection

Geolocation & ASN enrichment:
- Country verification (configured vs GeoIP detected) using GeoLite2 then legacy GeoIP fallback
- ASN number & organization lookup

Output enrichment:
- Human-readable insights summarizing stability, variability, patterns, plateaus, slope, jitter
- All results appended as JSON Lines (JSONL) for easy streaming / ingestion

Operational conveniences:
- JSONC sites configuration (comments allowed)
- Parallel monitoring with bounded concurrency (--parallel)
- Asynchronous single-writer result queue (low contention, durable append)
- Multiple iterations (--iterations)

## Usage
1. Add sites to `sites.jsonc`
2. Run the monitor from your local PC or via SSH

Windows users
- If you have Git Bash or WSL installed, you can run the existing `.sh` scripts directly.
- Alternatively, use the provided PowerShell runner `monitor_core.ps1`, which mirrors the `.sh` behavior (collection + analysis steps):

```powershell
# PowerShell
./monitor_core.ps1 -Situation "Home_CorporateLaptop_CorpProxy_SequencedTest" -Parallel 2 -Iterations 1 -AnalysisBatches 15

# Or via env vars
$env:SITUATION = "Home_WiFi"; $env:PARALLEL = "2"; ./monitor_core.ps1
```

PowerShell prerequisites: Go on PATH; PowerShell 7+ recommended. The Go binary itself remains cross‑platform.

PowerShell scenario wrappers (Windows)
- For each Bash wrapper listed below, a PowerShell equivalent exists with the same basename and a `.ps1` extension.
- They call `monitor_core.ps1` and behave identically: a Monitor (collection) phase followed by an Analysis phase for the same `SITUATION`.

Examples:

```powershell
# Run the corporate-at-home scenario wrapper (PowerShell)
./monitor_atHomeCorpLaptop.ps1

# Increase the analysis window to 25 batches for a one-off run
$env:ANALYSIS_BATCHES = "25"; ./monitor_atHomeCorpLaptop.ps1
```

Available curated PowerShell wrappers:

| Script | Intended Situation | Proxy State | Concurrency Mode | Default PARALLEL | Default ITERATIONS | Notes |
|--------|--------------------|-------------|------------------|------------------|--------------------|-------|
| `monitor_atHomeCorpLaptop.ps1` | Corporate laptop at home | Corporate proxy enabled | Sequential | 1 | 1 | Baseline for controlled home + corp proxy path |
| `monitor_atHomeCorpLaptopNoCorpProxy.ps1` | Corporate laptop at home | Corporate proxy disabled | Sequential | 1 | 1 | Contrast vs proxy-enabled to isolate proxy impact |
| `monitor_atOfficeCorpLaptop.ps1` | Corporate laptop in office | Corporate proxy enabled | Sequential | 1 | 1 | On‑prem baseline |
| `monitor_atOfficeCorpLaptopNoCorpProxy.ps1` | Corporate laptop in office | Proxy disabled | Sequential | 1 | 1 | Office direct path comparison |
| `monitor_atHomePrivateLaptop.ps1` | Private (non‑corp) laptop at home | No corporate proxy | Sequential | 1 | 1 | Clean consumer environment |

Tip: Copy any of the above to a new filename (e.g., `monitor_HotelWifi.ps1`) and adjust the `Situation` default at the top to create your own repeatable scenario.

### Scenario Wrapper Scripts (Repeatable Situations)

For consistent, comparable batches, use the provided wrapper scripts instead of manually exporting environment variables each time. Each wrapper sets a descriptive `SITUATION` label and then execs `monitor_core.sh`, which performs the collection using a single persistent results file (`monitor_results.jsonl` by default). All situations append to the same file; the `meta.situation` field lets you later filter / compare.

Available curated wrappers:

| Script | Intended Situation | Proxy State | Concurrency Mode | Default PARALLEL | Default ITERATIONS | Notes |
|--------|--------------------|-------------|------------------|------------------|--------------------|-------|
| `monitor_atHomeCorpLaptop.sh` | Corporate laptop at home | Corporate proxy enabled | Sequential | 1 | 1 | Baseline for controlled home + corp proxy path |
| `monitor_atHomeCorpLaptopNoCorpProxy.sh` | Corporate laptop at home | Corporate proxy disabled | Sequential | 1 | 1 | Contrast vs proxy-enabled to isolate proxy impact |
| `monitor_atOfficeCorpLaptop.sh` | Corporate laptop in office | Corporate proxy enabled | Sequential | 1 | 1 | On‑prem baseline |
| `monitor_atOfficeCorpLaptopNoCorpProxy.sh` | Corporate laptop in office | Proxy disabled | Sequential | 1 | 1 | Office direct path comparison |
| `monitor_atHomePrivateLaptop.sh` | Private (non‑corp) laptop at home | No corporate proxy | Sequential | 1 | 1 | Clean consumer environment |
| `monitor_bulk_example.sh` | Private laptop stress / capacity test | No corporate proxy | Parallel | 8 | 1 | Higher load; watch impact on local link |

Template / examples to clone & adapt:
`monitor_scenario7.sh`, `monitor_scenario8.sh`, `monitor_scenario9.sh` – kept intentionally simple so you can copy, rename, and set a custom `SITUATION` (e.g. `Hotel_WiFi_VPNOn`, `MobileHotspot`, `Home_ISP_Failover`). Create as many as you need; all improvements in `monitor_core.sh` automatically apply.

Quick start with a wrapper:
```bash
./monitor_atHomeCorpLaptop.sh
./monitor_atHomeCorpLaptopNoCorpProxy.sh
./monitor_bulk_example.sh   # high parallel example
```

What happens when you run a wrapper
- The core runner (Bash: `monitor_core.sh`, PowerShell: `monitor_core.ps1`) performs two phases:
   1) Monitor/collection phase: collect a fresh batch and append to the results file
   2) Analysis phase: summarize the most recent batches for the same `SITUATION`
- After a successful monitor phase, the analysis runs automatically and prints per‑batch lines and an overall aggregate across your most recent batches.
- Control the analysis window using the environment variable `ANALYSIS_BATCHES` (default: 15). Examples:

```bash
ANALYSIS_BATCHES=25 ./monitor_atHomeCorpLaptop.sh
```

```powershell
$env:ANALYSIS_BATCHES = "25"; ./monitor_atHomeCorpLaptop.ps1
```

The monitor banner prints the selected parameters (parallel, iterations, situation, log level, sites, output path, analysis batches) so runs are self-describing in logs.

## Charts overview & interpretations

TTFB (Avg) and TTFB Percentiles (ms)
- TTFB is the time to first byte for a request. Avg TTFB shows the mean per batch (Overall/IPv4/IPv6).
- TTFB Percentiles show P50/P90/P95/P99 per batch. Expect P99 ≥ P95 ≥ P90 ≥ P50. Larger gaps mean heavier tail latency (e.g., slow DNS/TLS, cold caches, backend spikes).

Speed Percentiles
- P50/P90/P95/P99 of transfer speed. Wide gaps indicate jitter or unstable throughput.

Error Rate, Jitter, CoV
- Error Rate: percentage of requests with errors.
- Jitter (%): mean absolute relative change between consecutive sample speeds in a transfer; higher = more erratic.
- Coefficient of Variation (%): stddev/mean of speeds; higher = less consistent.

Plateau metrics
- Plateau Count: number of intra-transfer stable segments.
- Longest Plateau (ms): the longest such segment; long values can indicate stalls.
- Plateau Stable Rate (%): fraction of time spent in stable plateaus (smoother throughput).

Cache/Proxy signals
- Cache Hit Rate (%): fraction likely served from caches.
- Proxy Suspected Rate (%): requests likely traversing proxies.
- Warm Cache Suspected Rate (%): requests likely benefiting from warm caches.

Diagnostics (tail, deltas, and SLA)
- Tail Heaviness (P99/P50 Speed): Ratio of P99 to P50 throughput. Values > 2 suggest a heavy tail (more extreme slowdowns vs median). Useful to spot jittery or bursty networks.
- TTFB Tail Heaviness (P95/P50): Ratio of tail to median latency per batch. Values close to 1.0 indicate a tight latency distribution; higher values mean heavier tail latency and more outliers/spikes.
- Family Delta – Speed (IPv6−IPv4): Difference in average transfer speed between IPv6 and IPv4. Positive means IPv6 faster; negative means IPv4 faster.
- Family Delta – TTFB (IPv4−IPv6): Difference in average TTFB between IPv4 and IPv6. Positive means IPv4 slower (higher latency); negative means IPv6 slower.
- Family Delta – Speed % (IPv6 vs IPv4): Percent difference vs IPv4 baseline: (IPv6−IPv4)/IPv4 × 100%. Positive means IPv6 faster.
- Family Delta – TTFB % (IPv6 vs IPv4): Percent difference vs IPv6 baseline: (IPv4−IPv6)/IPv6 × 100%. Positive means IPv6 lower latency.
- SLA Compliance – Speed: Estimated percent of requests that meet or exceed the P50 speed target. Approximated from percentiles; higher is better. Threshold is user‑configurable.
- SLA Compliance – TTFB: Estimated percent of requests that meet or beat the P95 TTFB target (i.e., P95 ≤ threshold). Approximated from percentiles; higher is better. Threshold is user‑configurable.
- SLA Compliance Delta – Speed (pp): IPv6 compliance minus IPv4 compliance, in percentage points. Positive means IPv6 meets the speed SLA more often.
- SLA Compliance Delta – TTFB (pp): IPv6 compliance minus IPv4 compliance, in percentage points. Positive means IPv6 meets the TTFB SLA more often.
 - TTFB P95−P50 Gap: Difference between tail and median latency (P95 minus P50) per batch. Larger gaps indicate heavier tail latency and more outliers/spikes.

TTFB Tail Heaviness (P95/P50)
- What it shows: The ratio of P95 TTFB to P50 TTFB per batch (Overall/IPv4/IPv6).
- How to read: ~1.0 means the tail is close to median (tight distribution). Higher ratios mean heavier tails and greater latency variability.
- Why it matters: Complements the absolute P95−P50 Gap by giving a dimensionless view that is comparable across sites and situations.

### Viewer controls and exports

- Situation filter: Use the Situation dropdown in the toolbar to scope charts and the table to a single scenario or All.
- Titles: Chart titles are kept clean and do not include the situation label.
- Watermark: The active Situation is shown in a subtle bottom-right on-image watermark (e.g., "Situation: Home_WiFi"). This watermark is embedded into exported PNGs so context is preserved when sharing.
- X-Axis modes: Batch, RunTag, or Time. Y-Scale: Absolute (zero baseline) or Relative (nice bounds).
- SLA thresholds (configurable): Two toolbar fields let you set corporate‑friendly defaults or your own targets:
   - SLA P50 Speed (kbps): default 10,000 kbps (≈10 Mbps). Used by the SLA Compliance – Speed chart and hover labels.
   - SLA P95 TTFB (ms): default 200 ms. Used by the SLA Compliance – TTFB chart and hover labels.
   Values are persisted across sessions. Chart titles reflect the current thresholds and units.
- Exports: Individual export items mirror the on‑screen order. "Export All (One Image)" stitches charts together in the same order shown in the UI, maintaining the watermark per chart.

Rolling overlays (Avg Speed & Avg TTFB)
- Rolling window N: default 7 (persisted). Smooths out short-term noise.
- Rolling Mean (μ): toggle to show a smoothed trend line across the last N batches.
- ±1σ Band: independent toggle to show a translucent band between μ−σ and μ+σ. Legend shows a single entry “Rolling μ±1σ (N)” per chart when enabled.
- Help dialogs on the Speed/TTFB charts include a short hint on what the band means and how changing N affects smoothing and band width.

Stability & quality (viewer)
- Low‑Speed Time Share (%): time spent below the Low‑Speed Threshold; highlights choppiness even when averages look fine.
- Stall Rate (%): share of requests that stalled; good as a reliability/quality symptom.
- Avg Stall Time (ms): average stalled time for stalled requests; higher means longer buffering events.
- Stalled Requests Count: quick absolute count derived as round(Lines × Stall Rate%). Has a dedicated export option.

Low‑Speed Threshold control
- Toolbar control “Low‑Speed Threshold (kbps)” sets the cutoff for Low‑Speed Time Share. Default 1000 kbps; persisted. Changing it re‑analyzes data on the fly. Stall metrics are independent of this threshold.

See also: the dedicated viewer docs in `README_iqmviewer.md` for a compact, feature‑focused overview and troubleshooting notes.


Analyzing only recent batches for a specific situation:
```bash
go run ./src/main.go --out monitor_results.jsonl --analysis-batches 5 --situation Home_CorporateLaptop_CorpProxy_SequencedTest
```

Ad‑hoc custom run without a wrapper (still allowed):
```bash
SITUATION="Hotel_WiFi" PARALLEL=2 ITERATIONS=2 ./monitor_core.sh
```

Filtering results by situation with jq:
```bash
grep '"Home_CorporateLaptop_NoCorpProxy_SequentialTest"' monitor_results.jsonl | tail -n 3 | jq '.site_result.name, .site_result.transfer_speed_kbps'
```

Comparing two situations’ average speeds (last line of each situation):
```bash
last_home_proxy=$(grep '"Home_CorporateLaptop_CorpProxy_SequencedTest"' monitor_results.jsonl | tail -n 1)
last_home_noproxy=$(grep '"Home_CorporateLaptop_NoCorpProxy_SequentialTest"' monitor_results.jsonl | tail -n 1)
echo "$last_home_proxy" | jq '.meta.situation, .site_result.transfer_speed_kbps'
echo "---" 
echo "$last_home_noproxy" | jq '.meta.situation, .site_result.transfer_speed_kbps'
```

### Note: Situation-scoped analysis and cross-situation comparisons

- The built-in analysis phase groups and aggregates batches by the exact `SITUATION` label. Batches with different labels are not co-aggregated nor compared programmatically.
- Cross-situation comparison (e.g., corporate laptop vs private laptop) is not implemented and may never be. Workaround: compare the printed analysis outputs manually and keep test conditions identical.
- Tips for fair comparisons:
   - Use the same `SITES`, `PARALLEL`, `ITERATIONS`, and `ANALYSIS_BATCHES` for both scenarios.
   - Run each scenario wrapper back-to-back so the time window is similar, then compare the per-batch and `overall across` lines.
   - Optionally export results to separate files via different `OUT_BASENAME` values for side-by-side inspection.

Field note (anecdotal): In one setup, a 15-year-old ThinkPad T430 (Linux, i7‑3840QM) measured significantly better throughput and TTFB than a modern Mac M2 using a corporate proxy—about 3x in sequential and parallel (8x) modes. If proxying is part of your environment, it’s worth investigating its impact on speed and TTFB.

Guidelines for creating a new wrapper:
1. Copy one of the `monitor_scenario*.sh` files to a meaningful name, e.g. `monitor_hotelWifi.sh`.
2. Edit the banner comment to describe location/device/proxy state.
3. Set a stable `SITUATION` string (avoid spaces; use underscores for parsing ease).
4. Optionally adjust `PARALLEL`, `ITERATIONS`, or `OUT_BASENAME` (if you want to isolate output).
5. Run it and later analyze by passing `--situation <label>` to the analyzer.

Rationale: Re-using identical labels provides clean before/after / environment-to-environment comparisons and enables simple grep/jq pipelines without extra bookkeeping.

### Command Line

From repository root (module directory):

```bash
go run ./src/main.go [--analyze-only=(true|false)] [--analysis-batches N] \\
   [--sites <path>] [--iterations N] [--parallel M] [--out <file>] [--log-level level]
```

Flags:
- `--analyze-only` (bool, default `false`): When true, no new measurements are collected; existing result batches are summarized & compared.
- `--analysis-batches` (int, default `10`): Maximum recent batches to parse when analyzing only (caps work; older batches ignored beyond this window).
- `--sites` (string, default `./sites.jsonc` when collecting): Path to JSONC site list (ignored in analyze-only mode).
- `--iterations` (int, default `1`): Sequential passes over the site list (collection mode only).
- `--parallel` (int, default `1`): Maximum concurrent site monitors (collection mode only).
- `--out` (string, default `monitor_results.jsonl`): Output JSON Lines file (each line = root object `{meta, site_result}`). Both modes read this path.
- `--http-timeout` (duration, default `120s`): Overall timeout per individual HTTP request (HEAD / GET / range / warm HEAD) including body transfer.
- `--stall-timeout` (duration, default `20s`): Abort an in-progress body transfer if no additional bytes arrive within this window (marks line with `transfer_stalled`).
- `--site-timeout` (duration, default `120s`): Overall budget per site (sequential mode) or per (site,IP) task (fanout) including DNS and all probes; aborts remaining steps if exceeded.
- `--max-ips-per-site` (int, default `0` = unlimited): Limit probed IPs per site (first IPv4 + first IPv6 typical when set to 2) to prevent long multi-IP sites monopolizing workers.
- `--ip-fanout` (bool, default `true`): Pre-resolve all sites, build one task per selected IP, shuffle for fairness, then process concurrently. Disable with `--ip-fanout=false` to use classic per-site sequential IP iteration.
- Progress logging controls (collection mode):
   - `--progress-interval` (duration, default `5s`): Emit periodic worker status (0 disables).
   - `--progress-sites` (bool, default `true`): Show active site/IP labels in progress lines.
   - `--progress-resolve-ip` (bool, default `true`): In non-fanout mode, attempt short-timeout DNS to display first 1–2 IPs inline.
- `--situation` (string, default `Unknown`): Arbitrary label describing the current network context (e.g. `Home`, `Office`, `VPN`, `Hotel`). Stored in each result's `meta.situation` to segment and compare batches later.
- Alert thresholds (percentages unless noted) to emit `[alert ...]` lines comparing the newest batch vs aggregate of prior batches:
   - `--speed-drop-alert` (default `30`): Trigger if average speed decreased by at least this percent.
   - `--ttfb-increase-alert` (default `50`): Trigger if average TTFB increased by at least this percent.
   - `--error-rate-alert` (default `20`): Trigger if error lines (tcp/http) exceed this percentage of batch lines.
   - `--jitter-alert` (default `25`): Trigger if average jitter (mean absolute % change) exceeds this percent.
   - `--p99p50-ratio-alert` (default `2.0`): Trigger if p99/p50 throughput ratio equals or exceeds this value.
   - `--alerts-json <path>`: If set, writes a structured JSON alert report summarizing latest batch, deltas, thresholds, and triggered alerts.

Examples:
```bash
# Single pass, default sites file
go run ./src/main.go

# Three passes over custom file
go run ./src/main.go --sites ./sites.jsonc --iterations 3

# Parallel monitoring with 5 workers writing to a custom file
go run ./src/main.go --parallel 5 --out fast_run.jsonl

# Disable IP fanout (process each site's IPs sequentially inside its worker slot)
go run ./src/main.go --ip-fanout=false --parallel 4

# Verbose run (detailed phase logging + progress + queue counters every 3s)
go run ./src/main.go --parallel 2 --log-level debug --progress-interval 3s

# Collect then write JSON alert report explicitly named
go run ./src/main.go --analyze-only=false --parallel 4 --iterations 2 \
   --speed-drop-alert 25 --ttfb-increase-alert 40 --error-rate-alert 10 \
   --jitter-alert 20 --p99p50-ratio-alert 1.8 --alerts-json alerts_latest.json

# Inspect alert JSON
jq '.' alerts_latest.json
```

### Watching Output

The program appends JSON objects to `monitor_results.jsonl` (opened once; writes via queue):

```bash
tail -f monitor_results.jsonl | jq '.name, .transfer_speed_kbps'

# Last record pretty
tail -n 1 monitor_results.jsonl | jq '.'

# Filter for a site and show latest
grep '"name":"Google US"' monitor_results.jsonl | tail -n 1 | jq '.'
```

### Output Structure (Field Groups)
<details>
<summary>Expand field groups</summary>

Identity & config:
- `name`, `url`, `country_configured`, `country_geoip`

Geo / ASN:
- `asn_number`, `asn_org`

DNS / connection / TLS / httptrace:
- `dns_time_ms`, `dns_ips` (array of resolved IP strings), `tcp_time_ms`, `ssl_handshake_time_ms`
- `http_connect_time_ms`, `trace_dns_ms`, `trace_connect_ms`, `trace_tls_ms`, `trace_time_to_conn_ms`, `trace_ttfb_ms`

Headers / proxy / cache signals:
- `header_via`, `header_x_cache`, `header_age`
- `cache_present`, `proxy_suspected`, `prefetch_suspected`, `ip_mismatch`
- `proxy_name`, `proxy_source`, `proxy_indicators` (classification + hints: via/x-cache/server or specialized headers like X-Zscaler-*)
 - `env_proxy_url`, `env_proxy_bypassed`, `using_env_proxy`
 - `proxy_remote_ip`, `proxy_remote_is_proxy`, `origin_ip_candidate`
 - `tls_cert_subject`, `tls_cert_issuer`
- `head_time_ms`, `head_status`, `head_error`, `head_get_time_ratio`
- `second_get_status`, `second_get_time_ms`, `second_get_header_age`, `second_get_x_cache`, `second_get_content_range`, `second_get_cache_present`
- `warm_head_time_ms`, `warm_head_speedup`, `warm_cache_suspected`

Probe / connection reuse:
- `probe_header_value`, `probe_echoed`, `dial_count`, `connection_reused_second_get`, `remote_ip`, `ip_family` (ipv4|ipv6), `ip_index` (order among selected IPs), `resolved_ip`

Transfer stats:
- `transfer_time_ms`, `transfer_size_bytes`, `transfer_speed_kbps`
- `transfer_speed_samples` (array of `{time_ms, bytes, speed_kbps}`)
- `content_length_header`, `content_length_mismatch`
- `first_rtt_bytes`, `first_rtt_goodput_kbps`
- `transfer_stalled` (bool) & `stall_elapsed_ms` when a stall timeout aborts body download

Speed analysis object (`speed_analysis`):
- `average_kbps`, `stddev_kbps`, `coef_variation`
- `min_kbps`, `max_kbps`, `p50_kbps`, `p90_kbps`, `p95_kbps`, `p99_kbps`
- `slope_kbps_per_sec`, `jitter_mean_abs_pct`
- `patterns` (array of pattern strings)
- Plateau metrics: `plateau_count`, `longest_plateau_ms`, `plateau_stable`, `plateau_segments` (array of `{start_ms,end_ms,duration_ms,avg_kbps}`)
- `insights` (array of human-readable summary strings)

Errors:
- `dns_error`, `tcp_error`, `ssl_error`, `http_error`, `second_get_error` (present only on failures)

</details>

### Interpreting Key Metrics
<details>
<summary>Expand key metrics guidance</summary>
- Low `coef_variation` (< 0.15) + high `plateau_stable` suggests steady throughput.
- Large gap between `p99_kbps` and `p50_kbps` indicates bursty peaks.
- Positive `slope_kbps_per_sec` implies ramp-up (e.g. congestion window growth / server warmup); negative indicates throughput decay.
- `jitter_mean_abs_pct` > 0.15 (15%) indicates unstable delivery.
- Multiple long plateau segments with gaps may show adaptive bitrate shifts or shaping.
</details>

### Alert JSON Report

When `--alerts-json` is provided, a JSON file is written after analysis (analysis now fully centralized in `src/analysis`).

If you do NOT provide `--alerts-json`:
- In analyze-only mode: an alert report for the LAST batch is written: `alerts_<last_run_tag>.json` (repo root).
- In collection mode: a per-iteration report is written: `alerts_<run_tag>.json` (repo root).

```
alerts_<run_tag>.json
```

Examples: `alerts_20250818_093154.json`, `alerts_20250818_093154_i2.json` (2nd iteration) or in analyze-only mode just the newest batch tag.

Files are placed at the repository root even if you run from `src/` (the code detects `src` CWD and writes to parent). Provide an explicit `--alerts-json` path if you want to control location/name or consolidate across iterations.

Example schema (multi-batch comparison):

```
{
   "generated_at": "2025-08-18T12:34:56.123456Z",
   "schema_version": 3,
   "run_tag": "20250818_123456",
   "batches_compared": 5,
   "last_batch_summary": {
      "lines": 42,
      "avg_speed_kbps": 18500.4,
      "median_speed_kbps": 18120.7,
      "avg_ttfb_ms": 210.0,
      "avg_bytes": 52428800,
      "error_lines": 1,
      "error_rate_pct": 2.38,
      "first_rtt_goodput_kbps": 950.2,
      "p50_kbps": 18200.3,
      "p99_p50_ratio": 1.35,
      "plateau_count": 2,
      "longest_plateau_ms": 3400,
      "jitter_mean_abs_pct": 8.4
   },
   "comparison": {  // omitted and replaced by "single_batch": true when only one batch exists
      "prev_avg_speed_kbps": 19200.1,
      "prev_avg_ttfb_ms": 180.0,
      "speed_delta_pct": -3.65,
      "ttfb_delta_pct": 16.7
   },
   "alerts": [
      "ttfb_increase 16.7% >= 15.0%"
   ],
   "thresholds": {
      "speed_drop_pct": 30,
      "ttfb_increase_pct": 50,
      "error_rate_pct": 20,
      "jitter_pct": 25,
      "p99_p50_ratio": 2
    }
}

Single-batch schema (no comparison yet):

```
{
   "generated_at": "2025-08-18T12:34:56.123456Z",
   "schema_version": 3,
   "run_tag": "20250818_123456",
   "batches_compared": 1,
   "last_batch_summary": { ... },
   "single_batch": true,
   "alerts": [],
   "thresholds": { ... }
}
```
```

If only one batch exists, `single_batch: true` is included and no deltas are computed. The `alerts` field is always an array (may be empty `[]` when no thresholds are exceeded).

Implementation notes:
- Analysis & aggregation logic lives in `analysis.AnalyzeRecentResultsFull`, replacing older duplicated logic that previously lived inside `main.go`.
- Extended metrics (first RTT goodput, p50, p90, p95, p99, p99/p50 ratio, plateau stats, jitter, slope, coefficient of variation %, head/get ratio, cache & proxy related rates) are averaged or rate-derived per batch across site lines with data.

You can feed this JSON into automation or monitoring systems (e.g. ship as an event, create Grafana annotations, or trigger CI gates). Combine with cron to run periodically and inspect `alerts` array length for gating decisions.

### Batch Summary (Per run_tag) Field Glossary
<details>
<summary>Expand batch summary glossary</summary>
For each batch the analyzer outputs a line with the following aggregated fields (JSON names in parentheses):

Core:
- Average speed (avg_speed_kbps) / Median speed (median_speed_kbps)
- Average TTFB ms (avg_ttfb_ms)
- Average transferred bytes (avg_bytes)
- Error line count (error_lines) – lines containing tcp_error or http_error

Latency & initial delivery:
- First RTT goodput kbps (avg_first_rtt_goodput_kbps)
- HEAD/GET time ratio (avg_head_get_time_ratio) – mean HEAD latency divided by initial GET latency

Throughput distribution:
- p50/p90/p95/p99 averages (avg_p50_kbps, avg_p90_kbps, avg_p95_kbps, avg_p99_kbps)
- p99/p50 ratio (avg_p99_p50_ratio) – burstiness indicator ( >2 often volatile )

Variability & dynamics:
- Jitter mean absolute % (avg_jitter_mean_abs_pct)
- Coefficient of variation % (avg_coef_variation_pct)
- Slope kbps/s (avg_slope_kbps_per_sec) – linear regression gradient over samples

Plateaus & stability:
- Plateau count (avg_plateau_count)
- Longest plateau ms (avg_longest_plateau_ms)
- Stable plateau rate % (plateau_stable_rate_pct)

Caching / proxy / reuse rates (% of lines where condition true):
- Cache hit rate (cache_hit_rate_pct)
- Proxy suspected rate (proxy_suspected_rate_pct)
- IP mismatch rate (ip_mismatch_rate_pct)
- Prefetch suspected rate (prefetch_suspected_rate_pct)
- Warm cache suspected rate (warm_cache_suspected_rate_pct)
- Connection reuse rate (conn_reuse_rate_pct)

Use these to correlate: e.g. a rise in `ip_mismatch_rate_pct` plus degraded `avg_speed_kbps` may indicate path changes; increasing `avg_head_get_time_ratio` with stable speed might highlight control plane latency growth.
</details>

Per-family batch objects (`ipv4`, `ipv6`): each, when present, mirrors the core metric names (e.g. `avg_speed_kbps`, `avg_ttfb_ms`, `avg_p50_kbps`, rates like `cache_hit_rate_pct`) restricted to that IP family. They are omitted if a family has zero lines in the batch. Alert JSON currently reports only the combined batch (family-level alerts not yet emitted).

### Example Batch Summary Console Lines
<details>
<summary>Show example console line</summary>

A typical per-batch analyzer line (fields may be omitted when zero) now looks like:

```
[batch 20250818_131129] (per-batch) lines=42 dur=33500ms avg_speed=18450.7 median=18210.0 ttfb=210 bytes=52428800 errors=1 first_rtt=950.2 p50=18200.3 p99/p50=1.35 jitter=8.4% slope=120.5 cov%=9.8 cache_hit=40.0% reuse=35.0% plateaus=2.0 longest_ms=3400 v4(lines=30 spd=19010.4 ttfb=205 p50=18800.1) v6(lines=12 spd=16880.2 ttfb=225 p50=16750.0)
```

When more than one batch is in scope (rolling or analyze-only with >1), a line-weighted overall line follows:

```
[overall across 5 batches] lines=210 avg_speed=18620.3 avg_ttfb=205 avg_bytes=52400000 first_rtt=955.1 p50=18310.4 p99/p50=1.37 jitter=8.6% slope=118.2 cov%=9.5 plateaus=1.9 longest_ms=3600 cache_hit=39.2% reuse=34.1% v4(lines=150 spd=19120.5 ttfb=198 p50=18850.2) v6(lines=60 spd=17110.7 ttfb=223 p50=16780.0)
```

Interpretation:
* `(per-batch)` lines summarize a single run_tag batch (one iteration or ip-fanout group).
* `overall across` line aggregates all batches displayed (line-weighted) for a quick broader trend view; use this to observe slow drift vs previous collection windows.

Field order is optimized for quick visual scanning: core throughput & latency first, variability & stability next, then rates and IP-family splits.
</details>

### last_batch_summary JSON (Extended Schema)
<details>
<summary>Show extended JSON schema</summary>

`last_batch_summary` in the alert report always includes the core fields; extended fields are present when data exists (non-zero or at least one contributing line):

```
{
   "lines": 42,
   "avg_speed_kbps": 18450.7,
   "median_speed_kbps": 18210.0,
   "avg_ttfb_ms": 210.0,
   "avg_bytes": 52428800,
   "error_lines": 1,
   "error_rate_pct": 2.38,             // derived during alert JSON generation
   "avg_first_rtt_goodput_kbps": 950.2,
   "avg_p50_kbps": 18200.3,
   "avg_p90_kbps": 18340.1,            // optional
   "avg_p95_kbps": 18390.6,            // optional
   "avg_p99_kbps": 18550.9,            // optional
   "avg_p99_p50_ratio": 1.35,
   "avg_plateau_count": 2.0,
   "avg_longest_plateau_ms": 3400,
   "avg_jitter_mean_abs_pct": 8.4,
   "avg_slope_kbps_per_sec": 120.5,    // optional
   "avg_coef_variation_pct": 9.8,      // optional
   "avg_head_get_time_ratio": 0.62,    // optional
   "cache_hit_rate_pct": 40.0,         // optional (percent of lines)
   "proxy_suspected_rate_pct": 5.0,    // optional
   "ip_mismatch_rate_pct": 10.0,       // optional
   "prefetch_suspected_rate_pct": 2.5, // optional
   "warm_cache_suspected_rate_pct": 7.5, // optional
   "conn_reuse_rate_pct": 35.0,        // optional
   "plateau_stable_rate_pct": 45.0     // optional
}
```

Notes:
- Percent fields are already expressed as percentages (0–100) with one decimal typical.
- A field may be omitted (not just zero) in raw summaries when no contributing lines expose that signal; alert JSON focuses on non-zero metrics for brevity.
- `error_rate_pct` is computed only in the alert JSON (not stored in batch summaries) to keep the summary struct focused on raw counts & averages.
</details>

### Extending
Ideas (see improvement doc) include anomaly flagging, adaptive sampling, rotating logs, exporting Prometheus metrics.

## Structure
<details>
<summary>Expand repository structure</summary>
- `src/main.go`: Entry point
- `src/monitor/monitor.go`: Monitoring logic
- `src/types/types.go`: Type definitions
- `sites.jsonc`: List of sites to monitor
</details>

## Platform Portability
<details>
<summary>Expand platform portability</summary>

The collector is designed to run on Linux, macOS, and Windows with graceful degradation:

Linux (full detail):
- Load averages from `/proc/loadavg`
- Uptime from `/proc/uptime`
- Kernel version from `/proc/sys/kernel/osrelease`
- Container detection via `/.dockerenv` and `/proc/1/cgroup`

macOS / Windows / other:
- Load averages omitted (fields absent)
- Uptime approximated using process start time (duration since program launch)
- Kernel version reported as `<GOOS>-unknown`
- Container detection falls back to `false` (no Linux cgroup inspection)

Common (all platforms):
- Local outbound IP discovered via a short UDP dial to `8.8.8.8:80` (no packets exchanged beyond socket metadata)
- Default interface derived by matching the local IP to enumerated interfaces (may be blank if not resolvable)
- Connection type heuristic (wifi vs ethernet) infers from interface name prefixes (`wl*`, `wlan*`, `wifi`, `ath`, etc.); may return `unknown` if pattern not matched

Result meta object always includes only the fields successfully collected on the current platform to avoid placeholder or misleading values.
</details>

### Progress Logging & IP Fanout

Two scheduling strategies exist for collection mode:

1. IP Fanout (default `--ip-fanout=true`):
   - All sites are DNS-resolved first; IPs may be limited by `--max-ips-per-site`.
   - A task list of (site, IP) pairs is created then shuffled (Fisher–Yates) to distribute multi-IP sites across workers.
   - Each task enforces its own `--site-timeout` budget.
   - Debug mode (`--log-level debug`) prints task order before & after shuffle.
   - Progress line example:
     ```
     [iteration 1 progress] workers_busy=3/8 remaining=42 done=10/55 active=[ExampleSite(203.0.113.10),Another(2001:db8::1),Third(198.51.100.7)]
     ```
     Meaning: 3 busy of 8 workers, 42 tasks not yet started, 10 finished out of 55 total per-IP tasks.

2. Sequential Site (`--ip-fanout=false`):
   - Each worker processes a whole site sequentially over its selected IP list.
   - Optional inline short-DNS (1s) shows first IPs in progress lines when `--progress-resolve-ip` is true.
   - Remaining / done counts refer to sites, not (site,IP) tasks.

Accurate remaining/done counters are maintained via atomic counters (not `len(channel)` which is always 0 for unbuffered channels).

Use these progress signals to identify stalls or pathological sites (e.g. one site repeatedly occupying a worker due to many slow IPs – mitigate via `--max-ips-per-site` or enabling fanout).

### Public IP Discovery (Dual Stack)

The tool now records ONLY per-family public IP information (unified `public_ip_candidates` / `public_ip_consensus` have been removed):

- `public_ipv4_candidates` / `public_ipv4_consensus`
- `public_ipv6_candidates` / `public_ipv6_consensus`

Consensus is the most frequently observed address in its candidate list (simple frequency tally). If only one address is fetched, it becomes the consensus. Absence of a list means no successful discovery for that family within the timeout.

Example extraction with `jq`:
```bash
# Last line IPv4 consensus
tail -n 1 monitor_results.jsonl | jq '.meta.public_ipv4_consensus'

# Last line IPv6 consensus
tail -n 1 monitor_results.jsonl | jq '.meta.public_ipv6_consensus'

# Show both candidate arrays (safely handle nulls)
tail -n 1 monitor_results.jsonl | jq '{v4: .meta.public_ipv4_candidates, v6: .meta.public_ipv6_candidates}'

# Filter only runs where both families were detected
grep -F 'public_ipv4_consensus' monitor_results.jsonl | grep -F 'public_ipv6_consensus' | tail -n 5 | jq '.meta | {time: .timestamp_utc, v4: .public_ipv4_consensus, v6: .public_ipv6_consensus}'
```

Rationale: downstream processing often needs fast separation of IPv4 vs IPv6 without post-filtering a mixed array. Removing the legacy unified fields eliminates duplication and ambiguity when both families are present.

If you need consistent cross-platform fields, post-process by adding defaults where absent (e.g. set `load_avg_*` to null explicitly in downstream tooling).

## GeoIP Country Verification
<details>
<summary>Expand GeoIP details</summary>

This project supports both modern and legacy GeoIP databases for country verification:

- **Modern (GeoLite2 MMDB):**
  - Uses the MaxMind GeoLite2-Country.mmdb file (free, but requires registration).
  - Place the file at `/usr/share/GeoIP/GeoLite2-Country.mmdb` or update the path in the code.
  - The Go code uses the `github.com/oschwald/geoip2-golang` package.

- **Legacy (GeoIP.dat):**
  - Uses the legacy MaxMind GeoIP.dat and GeoIPv6.dat files.
  - Place the files at `/usr/share/GeoIP/GeoIP.dat` and `/usr/share/GeoIP/GeoIPv6.dat`.
  - The Go code uses the `github.com/oschwald/geoip` package as a fallback if the modern database is not available.

**How it works:**
- For each monitored site, the tool resolves the IP address and attempts to look up the country using the modern database first.
- If the modern database is unavailable, it falls back to the legacy database.
- Both the configured country (from your input) and the detected country (from GeoIP) are logged in the results.

**Setup:**
1. Download the GeoLite2-Country.mmdb from MaxMind (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Download the legacy GeoIP.dat from MaxMind or other sources if needed.
3. Place the files in `/usr/share/GeoIP/` or update the code to use your preferred path.
4. Install the required Go packages:
   ```bash
   go get github.com/oschwald/geoip2-golang
   go get github.com/oschwald/geoip
   ```

## Installing GeoIP2 (GeoLite2) Databases on Ubuntu

To use GeoIP2 (GeoLite2) databases for country verification, you can install and update them using Ubuntu packages:

1. Install the geoipupdate tool:
   ```bash
   sudo apt install geoipupdate
   ```

2. Configure your MaxMind account and license key in `/etc/GeoIP.conf` (required for database downloads).
   - Register for a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
   - Add your account details and license key to `/etc/GeoIP.conf`.

3. Download and update the databases:
   ```bash
   sudo geoipupdate
   ```

4. The databases (e.g., `GeoLite2-Country.mmdb`) will be placed in `/usr/share/GeoIP/` by default.

Your Go code will then be able to use these databases for GeoIP lookups.

**Result:**
- The output JSONL file will show both the configured and detected country for each site, helping you verify and troubleshoot geographic routing and CDN issues.
</details>

## Troubleshooting
<details>
<summary>Common issues & resolutions</summary>

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| "no records" error | Empty results file or schema_version mismatch | Run with `--analyze-only=false` to collect; ensure `monitor.SchemaVersion` matches lines |
| Extended metrics all zero | Missing `speed_analysis` (errors or aborted transfers) | Inspect recent lines; reduce errors; ensure successful GETs |
| High error rate alert | Real network failures or strict thresholds | View last 20 errors: `grep -E 'tcp_error|http_error' monitor_results.jsonl | tail -n 20` |
| GeoIP fields empty | GeoLite2 DB not installed | Install via `geoipupdate`; verify path `/usr/share/GeoIP/GeoLite2-Country.mmdb` |
| Slow analysis | Very large results file | Limit with `--analysis-batches`; rotate/archive old lines |
| Memory concern | Many recent batches retained | Lower `--analysis-batches` (default 10) |
| HEAD slower than GET (ratio >1) | Proxy / caching anomaly | Check `proxy_suspected_rate_pct` and headers (`Via`, `X-Cache`) |
| Sudden p99/p50 spike | Bursty traffic or fewer samples | Validate sample count; look for plateau instability |
| ip_mismatch_rate_pct spike | CDN path shift or proxy insertion | Compare ASN/org; correlate with `proxy_suspected_rate_pct` |
| Warm cache suspected w/ low cache hit rate | HEAD path cached, object not | Inspect `header_age` / `x-cache` and warm HEAD timings |
| Need verbose analysis | Want batch grouping debug | `ANALYSIS_DEBUG=1 go run ./src/main.go` |
| Need baseline only | Old data noisy | Move or delete results file; collect fresh single batch |
| All speeds zero for tiny object | Sub-ms transfer (older versions) | Update to latest (uses high-res timing) or test with larger asset |

Quick focused test rerun:
```bash
go test ./src/analysis -run TestExtendedRateAndSlopeMetrics -count=1
```

</details>

### Changelog

See `CHANGELOG.md` for a summary of recent changes across the analyzer and viewer.
