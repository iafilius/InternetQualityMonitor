# Changelog

All notable changes to this project are documented here. Dates use YYYY‑MM‑DD.

## [Unreleased]
 - Calibration (Default‑on): The monitor now runs a short local speed calibration at the start of each collection session (skipped in analyze‑only). Targets auto‑generate as 10/30 per decade up to the measured local max when not provided.
 - Calibration (Tolerance): CLI prints a concise summary of targets within tolerance (e.g., "within 10%: X/Y"). Tolerance is configurable via --calibrate-tolerance.
 - Calibration (Samples): Each calibration target now records how many measurement samples were taken; the CLI logs "[calibration] samples per target: [...]" for context.
 - Metadata/Analysis: Calibration sample counts are propagated in analysis output as calibration_samples (array, per target), alongside existing calibration fields (targets, observed, error%).
 - Viewer (Diagnostics): Diagnostics show Speed Targets with observed values, error percentages, and sample counts (header indicates "[samples]"). "Copy JSON" now includes calibration_samples; "speed_targets" alias is supported in input.
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
 - Viewer (Crosshair): Fixed X‑axis drift and ensured the crosshair snaps to the nearest data point in both index/time modes. Implemented image‑based calibration (gridline detection) to align overlay with the actual go‑chart plot geometry; falls back to math mapping if calibration isn’t available. Added robust image‑based tests that assert snapping and tooltip content always reflect the snapped X.
 - Viewer (Diagnostics): Brighter, theme‑aware Diagnostics dialog using rich text with scrolling; added Copy (text) and Copy JSON buttons; new menu item “Show Diagnostics (selected row)” with Cmd/Ctrl+D shortcut; remembers last selected row.
	- Viewer (Diagnostics): Right‑click context menu on table rows adds “Diagnostics…” for mouse users.
		- Viewer (Diagnostics): Added “Copy traceroute”, “Copy ping”, and “Copy mtr” buttons. Traceroute uses `traceroute -n` on macOS/Linux or `tracert` on Windows. Ping uses a finite count on Unix. mtr appears only if installed and on macOS/Linux.
		- Viewer (Diagnostics): Added “Copy curl -v” which builds a verbose curl command for a representative URL from the batch, adding an HTTP version hint when there’s a clear majority. Analysis now propagates a SampleURL per batch to enable this.
 - Viewer (Export): Combined export stitches all visible charts into one PNG and now shows a confirmation after saving.
 - Viewer (UX): Selection is session‑only (restored during the session, not persisted across restarts). Context menu includes Diagnostics only.

- Alert JSON schema v3 with thresholds and per‑batch/overall sections.
- High‑resolution speed fallback for sub‑ms transfers.

## [2.5.0] – 2025‑06‑xx
- First RTT goodput, plateaus, jitter, slope, CoV, and richer insights.

[Unreleased]: https://github.com/iafilius/InternetQualityMonitor/compare/main...HEAD
[3.0.0]: https://github.com/iafilius/InternetQualityMonitor/releases/tag/v3.0.0
