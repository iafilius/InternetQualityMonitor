# Analysis reference

This document explains how the analysis layer reads `monitor_results.jsonl`, which knobs influence computed metrics, and what metrics are derived. It’s useful if you run analysis headlessly, consume summaries programmatically, or want to understand what the viewer visualizes.

## Inputs and scope

- Source: JSON Lines produced by the monitor, typically `monitor_results.jsonl`.
- Windowing: Analysis returns the most recent N batches (default 10; configurable by the caller, e.g., viewer uses its Batches setting).
- Situation filtering: Batches can be filtered by `meta.situation` (viewer toolbar, or programmatic via AnalyzeOptions.SituationFilter).
- IPv4/IPv6 splits: For each batch, Overall/IPv4/IPv6 summaries are computed when family data exists.

## Configurable thresholds and options

These influence how certain derived metrics are computed. Defaults shown are those used by the viewer and screenshots.

- Low‑Speed Threshold (kbps)
  - Purpose: time share of transfer spent below this throughput.
  - Affects: Low‑Speed Time Share (%).
  - Default: 1000 kbps.
  - Where set: viewer Settings → “Low‑Speed Threshold…”, screenshot flag `--screenshot-low-speed-threshold-kbps`. Programmatic: `AnalyzeOptions.LowSpeedThresholdKbps`.

- Micro‑stall Minimum Gap (ms)
  - Purpose: detect short pauses where bytes don’t increase for at least this gap, while the transfer later resumes (distinct from hard stall timeouts).
  - Affects: Transient Stall Rate (%), Avg Transient Stall Time (ms), Avg Transient Stall Count.
  - Default: 500 ms.
  - Where set: currently fixed in viewer/screenshots at 500 ms. Programmatic: `AnalyzeOptions.MicroStallMinGapMs`.

- SLA thresholds
  - SLA P50 Speed (kbps): target for “SLA Compliance – Speed” (% of requests meeting/beat P50 target).
  - SLA P95 TTFB (ms): target for “SLA Compliance – TTFB” (% of requests with P95 ≤ target).
  - Defaults: Speed 10,000 kbps; TTFB 200 ms (viewer defaults; change under Settings → SLA Thresholds…).
  - Where set: viewer Settings dialog. Programmatic consumers can apply similar thresholds externally to the summaries.

- Batches (recent N)
  - Purpose: controls how many recent batches are included.
  - Default: viewer uses 50 by default; CLI runner may use 10.
  - Where set: viewer Settings → “Batches…”. Programmatic: pass MaxBatches to analysis.

Notes:
- Pre‑TTFB stall signals are collected by the monitor (runtime watchdog). Analysis surfaces them when present; there’s no analysis‑side threshold for that signal.

## Derived metrics (high‑level)

Per batch (Overall/IPv4/IPv6 when available):

- Throughput averages and percentiles
  - Avg Speed (unit selectable in viewer); Speed P50/P90/P95/P99.
  - TTFB (Avg) and TTFB P50/P90/P95/P99.

- Stability and stalls
  - Low‑Speed Time Share (%): share of transfer time below the Low‑Speed Threshold.
  - Stall Rate (%): requests that stalled (hit stall timeout or meaningful stall event recorded by monitor).
  - Avg Stall Time (ms): average total stalled time among stalled requests.
  - Pre‑TTFB Stall Rate (%): share of requests that aborted before first byte due to pre‑TTFB stall (if monitor recorded it).

- Transient/micro‑stalls (resume after pause)
  - Transient Stall Rate (%): share of requests with ≥1 micro‑stall.
  - Avg Transient Stall Time (ms): average total micro‑stall time among affected requests.
  - Avg Transient Stall Count: average number of micro‑stall events among affected requests.

- Variability and shape
  - Jitter (%), Coefficient of Variation (%).
  - Plateau metrics: Count, Longest (ms), Stable Share (%).
  - Tail heaviness ratios: Speed P99/P50, TTFB P95/P50.
  - TTFB P95−P50 gap (ms).

- Protocols and signals
  - HTTP protocol mix (%), Avg Speed by protocol.
  - Error/Partial rates by protocol (%), and their shares (% of all errors/partials).
  - Stall rate by protocol (%), Stall share by protocol (% of all stalls).
  - TLS/ALPN mixes (%), Chunked Transfer Rate (%).
  - Cache Hit Rate, Enterprise Proxy Rate, Server-side Proxy Rate, Warm Cache Suspected Rate.

Note on deprecation and compatibility
- The legacy combined Proxy Suspected Rate (`proxy_suspected_rate_pct`) is deprecated in the Viewer UI and replaced by split metrics for clearer attribution: `enterprise_proxy_rate_pct` and `server_proxy_rate_pct`.
- For backward compatibility, the analysis still emits `proxy_suspected_rate_pct`. Downstream consumers are encouraged to migrate to the split fields.

Note on sourcing: Protocol/TLS/encoding fields are primarily taken from the primary GET response. If that is unavailable (e.g., timeout or abort), the monitor fills these fields from a successful HEAD or Range response when present, so protocol/TLS mixes remain informative in those edge cases.

- IPv6 vs IPv4 deltas
  - Speed delta (abs, %), TTFB delta (abs, %).

- SLA metrics
  - SLA Compliance – Speed (% meeting P50 target), SLA Compliance – TTFB (% with P95 ≤ target).
  - SLA deltas (percentage points) between IPv6 and IPv4.

## Calibration fields (metadata → analysis)

When the monitor runs with calibration enabled (default in collection mode), metadata includes a calibration block that the analysis layer lifts into per‑batch summaries:

- calibration_max_kbps: max sustainable local throughput observed by the loopback probe.
- calibration_ranges_target_kbps: array of target speeds (kbps) used during calibration (auto‑generated as 10/30 per decade up to the measured max when not provided).
- calibration_ranges_observed_kbps: observed throughput (kbps) per target.
- calibration_ranges_error_pct: absolute error (%) per target vs the target speed.
- calibration_samples: integer array with the number of measurement samples contributing to each target’s observation (same order as targets/observed).

Notes:
- These fields are optional and appear only when calibration metadata is present in the input JSONL.
- The input also accepts the alias key speed_targets for targets; analysis/viewer normalize this to the above arrays.

## Programmatic usage

Use `AnalyzeRecentResultsFullWithOptions(path, schemaVersion, maxBatches, AnalyzeOptions)` to retrieve summaries. The options let you apply situation filters and thresholds like Low‑Speed and Micro‑stall gap.

Example (pseudocode):

```
opts := AnalyzeOptions{
    SituationFilter: "All",
    LowSpeedThresholdKbps: 1000,
    MicroStallMinGapMs: 500,
}
sums, err := AnalyzeRecentResultsFullWithOptions("monitor_results.jsonl", SchemaVersion, 50, opts)
```

The viewer and headless screenshots use this API under the hood and then render charts from these summaries.

## Visuals

See `README_iqmviewer.md` for how these metrics are visualized, exported, and themed in the desktop viewer.

## Analyze‑only quickstart (CLI)

Run the binary in analyze‑only mode to summarize existing results without collecting new data:

```bash
# Build the CLI (outputs a binary named 'main')
go build -o main ./src

# Analyze existing results
./main --analyze-only=true \
  --analysis-batches 15 \
  --input monitor_results.jsonl

# Optional: choose a fixed alerts JSON path instead of the default alerts_<run_tag>.json
# ./main --analyze-only=true --analysis-batches 15 --out monitor_results.jsonl --alerts-json alerts_latest.json
```

I/O summary:
- Input: the JSON Lines results file (default monitor_results.jsonl). In analyze‑only mode, use `--input` to specify the JSONL to read. `--out` is used by collection mode to write results.
- Output: a single alerts report in JSON (not JSONL). If `--alerts-json` is omitted, it’s written at the repo root as `alerts_<last_run_tag>.json`.

Notes:
- `--analysis-batches N` controls the recent window. Defaults to 10 when omitted.
- The input path defaults to `monitor_results.jsonl` unless you pass `--input` to point elsewhere.
- Alerts output is JSON (not JSONL). By default it’s `alerts_<run_tag>.json` at the repo root; override with `--alerts-json <path>` if you prefer a fixed filename.
- For viewer‑style thresholds (e.g., Low‑Speed, micro‑stall gap, SLA), the CLI uses internal defaults; to tune thresholds programmatically or for headless visuals, prefer the viewer flags or use the `AnalyzeRecentResultsFullWithOptions` API in a small Go snippet.

Backward compatibility: none required; analyze‑only requires `--input` (defaults to monitor_results.jsonl if omitted).
