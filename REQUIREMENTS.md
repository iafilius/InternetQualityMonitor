# InternetQualityMonitor: Reader and Viewer Requirements

This document captures the current requirements and behaviors for the IQM Reader (CLI) and IQM Viewer (desktop app). It intentionally avoids mixing with the monitoring/analysis pipeline details.

## Scope
- iqmreader: a small CLI to parse `monitor_results.jsonl` and report batch counts (and later, summaries) by situation.
- iqmviewer: a Fyne-based desktop viewer to visualize batch summaries with interactive charts.

## Data Model
- Input: JSONL file of ResultEnvelope entries with schema_version=3 containing:
  - meta.run_tag (string) required
  - meta.situation (string) optional but used for filtering/presentation
  - meta.timestamp_utc (RFC3339) optional; used for time axis
  - site_result metrics (transfer speeds, TTFB, family, analysis, flags)
- Aggregation unit: run_tag ("batch"). Multiple lines with the same run_tag are one batch.

## Reader (iqmreader)
- Inputs: `--file`, `--n` max batches, optional `--situation` filter (exact match).
- Behavior:
  - Uses AnalyzeRecentResultsFull (scanner buffer increased to 8MB) to avoid truncated lines.
  - Groups by run_tag, sorts tags lexicographically (timestamp tags sort chronologically), trims to last N.
  - Prints total batch count and counts grouped by Situation ("(none)" for missing).
- Non-goals: charting, UI.

## Viewer (iqmviewer)
- Persistent prefs: last file, situation selection (defaults to All), batchesN, series toggles (overall/IPv4/IPv6), x-axis mode (Batch|RunTag|Time), y-scale (Absolute|Relative), speed units, tab, crosshair enabled, SLA thresholds, Low‑Speed Threshold (kbps), Rolling Window (N, default 7), Rolling Mean toggle, and ±1σ Band toggle.
- Data load:
  - Calls AnalyzeRecentResultsFull(file, schema, N, "").
  - Builds run_tag→situation from returned summaries (no rescan).
  - Populates Situation dropdown with unique situations (+ All).
- Filtering:
  - When a situation is selected, filteredSummaries returns only summaries whose run_tag maps to that situation.
- Charts:
  - go-chart rendered offscreen to PNG, shown via ImageFillContain; responsive width.
  - Series: points-only; stacked charts: Avg Speed and Avg TTFB with percentiles placed immediately under their respective averages.
  - Rolling overlays on Avg Speed and Avg TTFB: Rolling Mean (μ) and optional translucent ±1σ band; band has a single legend entry “Rolling μ±1σ (N)” per chart.
  - X-axis modes: Batch (1..N), RunTag (trimmed), Time (uses parseRunTagTime; timestamps honored for data, ticks are rounded "nice" via pickTimeStep/makeNiceTimeTicks).
  - Y-scale: Absolute or Relative (derived flag useRelative).
  - Units: kbps/kBps/Mbps/MBps/Gbps/GBps conversion.
- Stability & quality suite:
  - Low‑Speed Time Share (%): time below the configurable Low‑Speed Threshold.
  - Stall Rate (%): share of requests that stalled.
  - Avg Stall Time (ms): average stalled time for stalled requests.
  - Stalled Requests Count: round(Lines × Stall Rate%).
- Crosshair overlay:
  - Theme-aware colors; vertical/horizontal lines follow the mouse; dot at intersection.
  - Label with semi-transparent background; shows values for Overall/IPv4/IPv6 depending on toggles.
  - No X-axis highlight band (removed to avoid misalignment).
  - Hidden when cursor is outside actual drawn image rect (contain-fit aware).
  - Crosshair enabled state persists across restarts.
- Help: Per-chart info dialogs include concise hints for interpretation; Speed/TTFB help explain the μ±1σ band and effect of window N.
- Export: PNG export for each chart and a combined “Export All (One Image)” that preserves on-screen order. Each export embeds a bottom-right watermark displaying the active Situation.
- Dedicated export for Stalled Requests Count exists in addition to its inclusion in the combined export.
- Keyboard shortcuts: Open (Cmd/Ctrl+O), Reload (Cmd/Ctrl+R), Close window (Cmd/Ctrl+W).

## Reliability and Limits
- Dynamic JSONL reader (no fixed Scanner token limit). Lines are streamed and parsed on-demand.
- Per-line safety cap: 200MB. If a single JSONL line exceeds this, analysis returns a clear error.
  - Change limit at: `src/analysis/analysis.go`, constant `MaxLineBytes`.
- Summaries include Situation to avoid rescanning files for meta.
- Default Situation selection is All to avoid accidental filtering.

## Open Items / Future Enhancements
- Add richer CLI summaries (avg speed/TTFB per situation).
- Add per-situation batch count indicator in the viewer status bar.
- Optional tests for time tick generation edge cases.
- Documentation for run_tag timestamp encoding and _iN suffix handling.
