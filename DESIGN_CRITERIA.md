# InternetQualityMonitor — Design Criteria

This document captures the enduring design principles, goals, constraints, and non‑goals for the collector (monitor), analysis, and viewer. It’s a stable reference to guide decisions and reviews.

## Purpose and scope
- Measure end‑to‑end Internet experience reliably across IPv4/IPv6 and network paths, then surface clear, actionable insights via summaries and charts.
- Components: monitor (collection), analysis (offline/aggregations), viewer (desktop UI), small reader CLIs.

## Principles (tenets)
- Correctness over cleverness: prefer explicit, verifiable behavior and tests that lock it in.
- Observability first: record the signals that explain outcomes (protocol/TLS, cache/proxy hints, timing phases, stalls).
- Predictable I/O: explicit flags and file formats; avoid hidden fallbacks and side effects.
- Cross‑platform: work on macOS, Linux, Windows with graceful degradation.
- Minimal dependencies: standard library first; small, well‑understood libs when necessary.
- Robust to bad data and flaky networks: defensive parsing, bounded memory, clear errors.
- Progressive disclosure: viewer shows the most important metrics first with per‑chart help.

## Current goals
- Stalls visibility: detect stall timeouts (abort) and micro‑stalls (resume) with clear metrics and visuals.
- Protocol/TLS insight: attribute performance/reliability by HTTP protocol, TLS version, and ALPN.
- Accurate charts: clean axes, consistent widths, precise crosshair overlays, deterministic exports.
- Analyze‑only clarity: separate input (`--input`) from collection output (`--out`); no fallback.
- Headless parity: screenshots reflect the same computations and defaults as the viewer.

## Non‑goals (for now)
- Full APM/trace correlation, deep browser waterfalls.
- Active network shaping or intrusive kernel tuning.
- Complex distributed storage and multi‑user dashboards.

## Constraints and assumptions
- File‑based workflow: JSONL input, append‑only writes during collection; summaries built from recent batches.
- Schema versioned envelope (`schema_version=3`), strongly typed fields in code; additive evolution favored.
- One retry on transient network errors (EOF/reset) per phase; never infinite retries.
- Timeouts are explicit per phase: per‑request HTTP timeout, stall timeout (no progress), optional pre‑TTFB watchdog.
- Micro‑stall detection is offline in analysis; default minimum gap 500 ms.

## Reliability and error handling
- Transient errors: single retry for HEAD/GET/Range; flags recorded (`retried_*`).
- Timeouts: surfaced as explicit error strings; stall aborts labeled consistently (e.g., `stall_pre_ttfb`, `stall_abort`).
- Partial bodies: `content_length_mismatch` marks incomplete transfers; counted as errors in analysis.
- Logs: human‑readable single‑line status with percent snippets and no fmt artifacts.

## Data and schema basics
- Envelope: `{ meta, site_result }` per line in JSONL.
- Protocol/TLS/encoding fields populated from the primary GET; if unavailable, populated from HEAD/Range when present to avoid “Unknown”.
- Batch unit: `run_tag` groups lines; per‑batch summaries computed for Overall/IPv4/IPv6 when present.

## Performance and UX targets
- Viewer: responsive redraws, nice time ticks, absolute/relative scales, unit conversions.
- Exports: deterministic width; combined export respects on‑screen order; situation watermark included.
- Analysis: streams recent window; dynamic reader with a hard per‑line cap to avoid OOM.

## Security and privacy
- Respect OS proxy env (HTTP(S)_PROXY/NO_PROXY); record effective proxy for transparency.
- Optional TLS cert subject/issuer for enterprise proxy detection; do not persist secrets.

## Testing and quality
- Unit tests for helpers (e.g., protocol normalization) and integration tests for monitor flows (timeouts, retries, stalls, protocol population).
- “Green before done”: run tests after meaningful changes; linting/types where available.

## Documentation commitments
- Separate READMEs for viewer, reader, and analysis; monitor/analysis I/O and flags explicitly documented.
- Changelog records behavior changes affecting users (flags, schema, chart semantics).

## Acceptance examples (abridged)
- Crosshair alignment: overlay lines/dot within image bounds; labels accurate at the sampled point.
- Protocol capture: `http_protocol` reflects actual negotiation; not 100% Unknown unless truly missing.
- Analyze‑only: `--input` required for non‑default paths; `--out` never used as implicit input.
