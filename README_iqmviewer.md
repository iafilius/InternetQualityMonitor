# iqmviewer

A Fyne-based desktop viewer for InternetQualityMonitor results focused on clear, accurate charts and robust filtering by situation.

## Build and run

```
go build ./cmd/iqmviewer
./iqmviewer -file monitor_results.jsonl
```

## Features
- Load `monitor_results.jsonl` and display the latest N batches (grouped by `run_tag`).
- Situation dropdown with "All" option (default).
- X-axis modes: Batch, RunTag, and Time with rounded ticks.
- Y-scale: Absolute or Relative.
- Speed units: kbps, kBps, Mbps, MBps, Gbps, GBps.
- Crosshair overlay: theme-aware, points follow mouse, label with semi-transparent background; hidden outside drawn area.
- PNG export for each chart.
- Keyboard shortcuts: Open (Cmd/Ctrl+O), Reload (Cmd/Ctrl+R), Close window (Cmd/Ctrl+W).

## Design
- Offscreen rendering via go-chart, displayed as PNG with ImageFillContain.
- Summaries come from `analysis.AnalyzeRecentResultsFull`; Situation is propagated in summaries (no rescan).
- Nice time ticks via `pickTimeStep` + `makeNiceTimeTicks`, actual data timestamps are preserved.

## Troubleshooting
- If you see too few batches, ensure your JSONL has distinct `run_tag` values for each batch. Many lines with the same `run_tag` count as a single batch.
- The app logs situation counts after each load to help verify filtering.
- The analysis layer uses a dynamic line reader with a 200MB per-line cap to avoid OOM.
	- To raise the cap, edit `src/analysis/analysis.go` and update `const MaxLineBytes`.
