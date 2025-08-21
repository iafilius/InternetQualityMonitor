#!/usr/bin/env bash
set -euo pipefail

##################################################
# Scenario Wrapper:                              #
# From Home,                                     #
# Private laptop                                 #                                         
# No Corporate Proxy                             #
# tests in Parallel (limit to 8) mode            #
##################################################

# Note: this will put a load on your network, so be careful with this setting.

# Always set SITUATION to guarantee repeatable wel defined tests
SITUATION=${SITUATION:-atHome_Privatelaptop_NoCorpProxy_ParallelTest}
PARALLEL=${PARALLEL:-8}
ITERATIONS=${ITERATIONS:-1}
OUT_DIR=${OUT_DIR:-$(pwd)}
OUT_BASENAME=${OUT_BASENAME:-monitor_results}
LOG_LEVEL=${LOG_LEVEL:-info}
SITES=${SITES:-./sites.jsonc}

# Export so exec'd core script receives them in its environment
export SITUATION PARALLEL ITERATIONS OUT_DIR OUT_BASENAME LOG_LEVEL SITES

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/monitor_core.sh"
