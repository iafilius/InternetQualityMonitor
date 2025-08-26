# Changelog

All notable changes to this project are documented here. Dates use YYYY‑MM‑DD.

## [Unreleased]
- Viewer: Rolling overlays with independent toggles — Rolling Mean (μ) and translucent ±1σ band; single legend entry “Rolling μ±1σ (N)”; window N persisted (default 7).
- Viewer: Stability & quality suite — Low‑Speed Time Share (%), Stall Rate (%), Avg Stall Time (ms), and Stalled Requests Count (derived) with dedicated export item.
- Viewer: Situation watermark embedded in all exports; chart titles kept clean; export order mirrors on‑screen order.
- Viewer: Percentiles re‑organized — Speed Percentiles under Avg Speed; TTFB Percentiles under Avg TTFB.
- Viewer: Preferences persist Situation, axis modes, speed unit, crosshair, SLA thresholds, Low‑Speed Threshold, Rolling Window, overlays toggles.
- Analysis: Added jitter, coefficient of variation, plateau metrics (count/longest/stability), tail heaviness, TTFB P95−P50 gap, IPv6↔IPv4 deltas (abs/%), SLA compliance and deltas, proxy/cache/warm‑cache indicators.
- Analysis: Safer rendering ranges and single‑point padding to avoid panics/blank charts.

## [3.0.0] – 2025‑08‑18
- Major analysis pipeline refactor into `analysis.AnalyzeRecentResultsFull*`.
- Per‑IP‑family batch summaries (IPv4/IPv6) and console output improvements.
- Alert JSON schema v3 with thresholds and per‑batch/overall sections.

## [2.6.0] – 2025‑07‑xx
- High‑resolution speed fallback for sub‑ms transfers.
- Expanded proxy/CDN/enterprise proxy detection and environment proxy usage tracking.

## [2.5.0] – 2025‑06‑xx
- First RTT goodput, plateaus, jitter, slope, CoV, and richer insights.

[Unreleased]: https://github.com/iafilius/InternetQualityMonitor/compare/main...HEAD
[3.0.0]: https://github.com/iafilius/InternetQualityMonitor/releases/tag/v3.0.0
