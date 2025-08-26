#!/usr/bin/env bash
set -euo pipefail

# Regenerate viewer screenshots headlessly into docs/images
# Usage (positional, all optional):
#   ./update_screenshots.sh [RESULTS_FILE] [SITUATION] [THEME] [VARIANTS] [BATCHES] [LOW_SPEED_KBPS] [DNS_LEGACY]
#
# Defaults:
#   RESULTS_FILE   = monitor_results.jsonl
#   SITUATION      = All
#   THEME          = auto        # auto | dark | light
#   VARIANTS       = averages    # averages | none
#   BATCHES        = 50
#   LOW_SPEED_KBPS = 1000        # used for Low-Speed Time Share
#   DNS_LEGACY     = false       # overlay dashed legacy dns_time_ms on DNS chart

RESULTS_FILE=${1:-monitor_results.jsonl}
SITUATION=${2:-All}
THEME=${3:-auto}
VARIANTS=${4:-averages}
BATCHES=${5:-50}
LOW_SPEED_KBPS=${6:-1000}
DNS_LEGACY=${7:-false}

OUTDIR="docs/images"

echo "[shots] building viewer..."
go build ./cmd/iqmviewer

echo "[shots] generating screenshots from ${RESULTS_FILE} (situation: ${SITUATION}, theme: ${THEME}, variants: ${VARIANTS}, batches: ${BATCHES}, low-speed-kbps: ${LOW_SPEED_KBPS}, dns-legacy: ${DNS_LEGACY}) -> ${OUTDIR}"
./iqmviewer -file "${RESULTS_FILE}" \
  --screenshot \
  --screenshot-outdir "${OUTDIR}" \
  --screenshot-situation "${SITUATION}" \
  --screenshot-batches "${BATCHES}" \
  --screenshot-rolling-window 7 \
  --screenshot-rolling-band \
  --screenshot-theme "${THEME}" \
  --screenshot-variants "${VARIANTS}" \
  --screenshot-low-speed-threshold-kbps "${LOW_SPEED_KBPS}" \
  --screenshot-dns-legacy "${DNS_LEGACY}"

echo "[shots] done. See ${OUTDIR}/*.png"
