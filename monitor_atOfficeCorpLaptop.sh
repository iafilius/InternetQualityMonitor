#!/usr/bin/env bash
set -euo pipefail

##################################################
# Scenario Wrapper:                              #
# From Office,                                     #
# Corporate laptop                               #                                         
# Corporate Proxy                                #
# tests in Sequenced mode                        #
##################################################

# Always set SITUATION to guarantee repeatable wel defined tests
SITUATION=${SITUATION:-Office_CorporateLaptop_CorpProxy_SequencedTest}
PARALLEL=${PARALLEL:-1}
ITERATIONS=${ITERATIONS:-1}
OUT_DIR=${OUT_DIR:-$(pwd)}
OUT_BASENAME=${OUT_BASENAME:-monitor_results}
LOG_LEVEL=${LOG_LEVEL:-info}
SITES=${SITES:-./sites.jsonc}
ANALYSIS_BATCHES=${ANALYSIS_BATCHES:-15}

# Export so exec'd core script receives them in its environment
export SITUATION PARALLEL ITERATIONS OUT_DIR OUT_BASENAME LOG_LEVEL SITES ANALYSIS_BATCHES

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/monitor_core.sh"
