#!/usr/bin/env pwsh
<#
InternetQualityMonitor Core Runner (Windows / PowerShell)
- Mirrors monitor_core.sh behavior
- Performs a measurement (collection) step, then an analysis step for the same SITUATION

Usage examples (PowerShell):
  # Defaults: Situation=Unknown, Parallel=1, Iterations=1, AnalysisBatches=15
  ./monitor_core.ps1

  # Override via parameters
  ./monitor_core.ps1 -Situation "Home_CorporateLaptop_CorpProxy_SequencedTest" -Parallel 2 -Iterations 1 -AnalysisBatches 15

  # Or via environment variables
  $env:SITUATION = "Home_CorpLaptop"; $env:PARALLEL = "2"; ./monitor_core.ps1

Prereqs:
- Go installed and on PATH
- PowerShell 7+ recommended (but script uses compatible constructs)
- Alternatively, you can run the .sh scripts using Git Bash or WSL
#>

param(
  [string]$Situation,
  [int]$Parallel,
  [int]$Iterations,
  [string]$OutDir,
  [string]$OutBasename,
  [string]$LogLevel,
  [string]$Sites,
  [string]$GoArgs,
  [int]$AnalysisBatches
)

$ErrorActionPreference = "Stop"

# Resolve defaults from env or use fallbacks
if (-not $Situation) { $Situation = $env:SITUATION; if (-not $Situation) { $Situation = "Unknown" } }
if (-not $Parallel) {
  if ($env:PARALLEL) { [int]$Parallel = $env:PARALLEL } else { $Parallel = 1 }
}
if (-not $Iterations) {
  if ($env:ITERATIONS) { [int]$Iterations = $env:ITERATIONS } else { $Iterations = 1 }
}
if (-not $OutDir) { $OutDir = if ($env:OUT_DIR) { $env:OUT_DIR } else { $PSScriptRoot } }
if (-not $OutBasename) { $OutBasename = if ($env:OUT_BASENAME) { $env:OUT_BASENAME } else { "monitor_results" } }
if (-not $LogLevel) { $LogLevel = if ($env:LOG_LEVEL) { $env:LOG_LEVEL } else { "info" } }
if (-not $Sites) { $Sites = if ($env:SITES) { $env:SITES } else { "./sites.jsonc" } }
if (-not $GoArgs) { $GoArgs = if ($env:GO_ARGS) { $env:GO_ARGS } else { "" } }
if (-not $AnalysisBatches) { $AnalysisBatches = if ($env:ANALYSIS_BATCHES) { [int]$env:ANALYSIS_BATCHES } else { 15 } }
$env:ANALYSIS_BATCHES = "$AnalysisBatches"

# Move to repo root (script directory)
Set-Location $PSScriptRoot

# Result file path
$ResultFile = Join-Path -Path $OutDir -ChildPath ("{0}.jsonl" -f $OutBasename)

# Short host (best-effort)
$short_host = $env:COMPUTERNAME
if (-not $short_host) { $short_host = "unknown" }
$short_host = $short_host.ToLowerInvariant()

Write-Host "[core-run] situation=$Situation host=$short_host parallel=$Parallel iterations=$Iterations out=$ResultFile"

Write-Host ""
Write-Host "#########################################################"
Write-Host "# Monitorstep: Measure fresh results into new batch     #"
Write-Host "#########################################################"
Write-Host "[monitor-run] parallel=$Parallel iterations=$Iterations situation='$Situation' log_level='$LogLevel' sites='$Sites' out='$ResultFile' analysis_batches=$AnalysisBatches"
Write-Host ""

# Build arg list for collection step
$collectArgs = @(
  "run", "./src/main.go",
  "--analyze-only=false",
  "--parallel=$Parallel",
  "--iterations=$Iterations",
  "--situation=$Situation",
  "--log-level=$LogLevel",
  "--sites=$Sites",
  "--out=$ResultFile"
)
if ($GoArgs) { $collectArgs += ($GoArgs -split ' ') }

# Execute collection
& go @collectArgs
$status = $LASTEXITCODE

if ($status -eq 0) {
  Write-Host "[core-run] complete -> $ResultFile (appended)"
  Write-Host ""
  Write-Host "##############################################"
  Write-Host "# Analysis step: summarize recent batches     #"
  Write-Host "##############################################"
  Write-Host "[analysis-run] situation='$Situation' batches=$AnalysisBatches file='$ResultFile'"
  Write-Host ""

  $analysisArgs = @(
    "run", "./src/main.go",
    "--analyze-only=true",
    "--analysis-batches=$AnalysisBatches",
    "--situation=$Situation",
    "--out=$ResultFile"
  )

  & go @analysisArgs
  $analysisStatus = $LASTEXITCODE
  if ($analysisStatus -ne 0) {
    Write-Host "[analysis-run] FAILED (exit=$analysisStatus)" -ForegroundColor Red
    exit $analysisStatus
  }

  exit 0
} else {
  Write-Host "[core-run] FAILED (exit=$status)" -ForegroundColor Red
  exit $status
}
