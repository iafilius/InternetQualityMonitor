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
 - Viewer (Protocols): Added companion “Share by HTTP Protocol (%)” charts for Errors, Stalls, and Partials alongside the existing per‑protocol “Rate …” charts; inline help clarified “Rates vs Shares”; README updated and headless screenshots regenerated (error/stall/partial share images).
 - Monitor (Logging): Fixed printf artifact that rendered “%!o(MISSING)” when logging preformatted lines with literal percent signs; logger now avoids double‑formatting when no args are provided.
 - Docs: `README_iqmreader.md` now includes a brief “Log lines explained” section covering status labels (done/aborted/incomplete) and the “(x% of y)” snippet when Content‑Length is known.
 - Viewer (Theme): Centralized chart theming and full theme support — View → Screenshot Theme now offers Auto (default), Dark, Light; selection is persisted. Auto follows system theme on macOS.
 - Viewer (Theme): Fixed charts that didn’t switch fully; rolling μ±1σ band cut‑outs and stitched exports are now theme‑aware; hints and watermark contrast improved for both themes.
 - Viewer (Theme): Safer UI updates during theme change — redraws and menu rebuilds scheduled asynchronously to avoid re‑entrancy issues.
 - Viewer (Headless): New screenshot flags — `--screenshot-theme auto|dark|light`, `--screenshot-variants averages|none`, `--screenshot-batches N`, `--screenshot-low-speed-threshold-kbps K`.
 - Viewer (Headless): Added “action” variants for averages (time‑axis and relative‑scale) gated by `--screenshot-variants`.
 - Viewer: New setup timing charts — DNS Lookup Time (ms), TCP Connect Time (ms), TLS Handshake Time (ms); included in UI, individual exports, combined export, and headless screenshots (`dns_lookup_time.png`, `tcp_connect_time.png`, `tls_handshake_time.png`).
 - Scripts: `update_screenshots.sh` updated to accept THEME/VARIANTS/BATCHES/LOW_SPEED_KBPS and pass through to the viewer.
 - Docs: `README.md` and `README_iqmviewer.md` updated with theme selection, headless flags, examples, and defaults.

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
