#!/usr/bin/env bash
set -euo pipefail

# Regenerate viewer screenshots headlessly into docs/images
# Usage:
#   ./update_screenshots.sh [RESULTS_FILE] [SITUATION]
# Defaults:
#   RESULTS_FILE = monitor_results.jsonl
#   SITUATION    = All

RESULTS_FILE=${1:-monitor_results.jsonl}
SITUATION=${2:-All}

OUTDIR="docs/images"

echo "[shots] building viewer..."
go build ./cmd/iqmviewer

echo "[shots] generating screenshots from ${RESULTS_FILE} (situation: ${SITUATION}) -> ${OUTDIR}"
./iqmviewer -file "${RESULTS_FILE}" \
  --screenshot \
  --screenshot-outdir "${OUTDIR}" \
  --screenshot-situation "${SITUATION}" \
  --screenshot-rolling-window 7 \
  --screenshot-rolling-band

echo "[shots] done. See ${OUTDIR}/*.png"
