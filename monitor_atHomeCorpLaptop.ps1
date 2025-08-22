#!/usr/bin/env pwsh
param(
  [string]$Situation,
  [int]$Parallel,
  [int]$Iterations,
  [string]$OutDir,
  [string]$OutBasename,
  [string]$LogLevel,
  [string]$Sites,
  [int]$AnalysisBatches
)

$ErrorActionPreference = "Stop"

# Scenario Wrapper (PowerShell): Home, Corporate laptop, Corporate Proxy, Sequenced

# Defaults
if (-not $PSBoundParameters.ContainsKey('Situation') -or [string]::IsNullOrWhiteSpace($Situation)) { $Situation = "Home_CorporateLaptop_CorpProxy_SequencedTest" }
if (-not $PSBoundParameters.ContainsKey('Parallel') -or -not $Parallel) { $Parallel = 1 }
if (-not $PSBoundParameters.ContainsKey('Iterations') -or -not $Iterations) { $Iterations = 1 }
if (-not $PSBoundParameters.ContainsKey('OutDir') -or [string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = (Get-Location).Path }
if (-not $PSBoundParameters.ContainsKey('OutBasename') -or [string]::IsNullOrWhiteSpace($OutBasename)) { $OutBasename = "monitor_results" }
if (-not $PSBoundParameters.ContainsKey('LogLevel') -or [string]::IsNullOrWhiteSpace($LogLevel)) { $LogLevel = "info" }
if (-not $PSBoundParameters.ContainsKey('Sites') -or [string]::IsNullOrWhiteSpace($Sites)) { $Sites = "./sites.jsonc" }
if (-not $PSBoundParameters.ContainsKey('AnalysisBatches') -or -not $AnalysisBatches) { $AnalysisBatches = 15 }

# Export-like behavior: pass as env vars so core picks them up if needed
$env:SITUATION = $Situation
$env:PARALLEL = "$Parallel"
$env:ITERATIONS = "$Iterations"
$env:OUT_DIR = $OutDir
$env:OUT_BASENAME = $OutBasename
$env:LOG_LEVEL = $LogLevel
$env:SITES = $Sites
$env:ANALYSIS_BATCHES = "$AnalysisBatches"

Set-Location $PSScriptRoot
& ./monitor_core.ps1 -Situation $Situation -Parallel $Parallel -Iterations $Iterations -OutDir $OutDir -OutBasename $OutBasename -LogLevel $LogLevel -Sites $Sites -AnalysisBatches $AnalysisBatches
