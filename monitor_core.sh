#!/usr/bin/env bash
set -euo pipefail

##############################################
# InternetQualityMonitor Core Runner Script  #
##############################################
# Purpose:
#   Invariant execution logic for a collection run. Situation / scenario specific
#   scripts only set environment variables (e.g. SITUATION, PARALLEL) and then
#   invoke this script. This file should remain stable so improvements propagate
#   to all scenario wrappers automatically.
#
# Usage (direct):
#   SITUATION="Home_WiFi" ./monitor_core.sh
#   SITUATION="Office_VPN" PARALLEL=4 ITERATIONS=2 ./monitor_core.sh
#
# Typical Wrapper Pattern (example wrapper script contents):
#   #!/usr/bin/env bash
#   SITUATION="Home_CorporateLaptop_SequencedTest"
#   PARALLEL=2
#   ITERATIONS=1
#   ./monitor_core.sh
#
# Environment Variables (all optional):
#   SITUATION    : Situation label (default: Unknown)
#   PARALLEL     : Worker pool size (default: 2)
#   ITERATIONS   : Passes over sites (default: 1)
#   OUT_DIR      : Directory for JSONL + alerts (default: repo root)
#   OUT_BASENAME : Base name for results file (default: monitor_results)
#   LOG_LEVEL    : debug|info|warn|error (default: info)
#   SITES        : Sites file (default: ./sites.jsonc)
#   GO_ARGS      : Extra args appended to go run invocation (advanced / optional)
#   ANALYSIS_BATCHES : How many recent batches to analyze in step 2 (default: 15)
#
# Output File Strategy:
#   Single persistent JSONL file (OUT_DIR/OUT_BASENAME.jsonl). All batches for all
#   situations are appended; meta.situation differentiates them.
#
# Post-Run Examples:
#   tail -n 1 monitor_results.jsonl | jq '.'
#   go run ./src/main.go --out monitor_results.jsonl --analysis-batches 5 --situation "$SITUATION"
#
# Safe Re-entrancy:
#   Multiple sequential invocations append. To isolate, override OUT_BASENAME.
#
# Exit Codes: inherits go run exit status.
##############################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SITUATION=${SITUATION:-Unknown}
PARALLEL=${PARALLEL:-1}
ITERATIONS=${ITERATIONS:-1}
OUT_DIR=${OUT_DIR:-$SCRIPT_DIR}
OUT_BASENAME=${OUT_BASENAME:-monitor_results}
LOG_LEVEL=${LOG_LEVEL:-info}
SITES=${SITES:-./sites.jsonc}
GO_ARGS=${GO_ARGS:-}
ANALYSIS_BATCHES=${ANALYSIS_BATCHES:-15}

RESULT_FILE="${OUT_DIR}/${OUT_BASENAME}.jsonl"

short_host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)
# Lowercase in a POSIX-safe way (macOS / older bash compatibility)
short_host=$(printf '%s' "$short_host" | tr 'A-Z' 'a-z')

echo "[core-run] situation=$SITUATION host=$short_host parallel=$PARALLEL iterations=$ITERATIONS out=$RESULT_FILE"

echo
echo "#########################################################"
echo "# Monitor step: Measure fresh results into new batch    #"
echo "#########################################################"
echo "[monitor-run] parallel=$PARALLEL iterations=$ITERATIONS situation='$SITUATION' log_level='$LOG_LEVEL' sites='$SITES' out='$RESULT_FILE' analysis_batches=$ANALYSIS_BATCHES"
echo
# Execute collection run (always analyze-only=false here)
go run ./src/main.go \
  --analyze-only=false \
  --parallel "$PARALLEL" \
  --iterations "$ITERATIONS" \
  --situation "$SITUATION" \
  --log-level "$LOG_LEVEL" \
  --sites "$SITES" \
  --out "$RESULT_FILE" \
  $GO_ARGS

status=$?
if [ $status -eq 0 ]; then
  echo "[core-run] complete -> $RESULT_FILE (appended)"

  echo
  echo "##############################################"
  echo "# Analysis step: summarize recent batches     #"
  echo "##############################################"
  echo "[analysis-run] situation='$SITUATION' batches=$ANALYSIS_BATCHES file='$RESULT_FILE'"
  echo
  # Perform analyze-only pass over recent batches for the same situation
  go run ./src/main.go \
    --analyze-only=true \
    --analysis-batches "$ANALYSIS_BATCHES" \
    --situation "$SITUATION" \
    --out "$RESULT_FILE"

  analysis_status=$?
  if [ $analysis_status -ne 0 ]; then
    echo "[analysis-run] FAILED (exit=$analysis_status)" >&2
    status=$analysis_status
  fi

else
  echo "[core-run] FAILED (exit=$status)" >&2
fi
exit $status
