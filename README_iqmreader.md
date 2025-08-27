# iqmreader

A tiny CLI to read InternetQualityMonitor results and print batch counts by situation. This is separate from the monitoring/analysis pipeline and the Fyne viewer.

## Build

```
go build ./cmd/iqmreader
```

## Usage

```
./iqmreader -file monitor_results.jsonl -n 10000
./iqmreader -file monitor_results.jsonl -n 10000 -situation Home_CorporateLaptop_CorpProxy_SequencedTest
```

## Try it

Quick start examples using the repo’s `monitor_results.jsonl`:

```
# Build the CLI
go build ./cmd/iqmreader

# Show counts for the last 10k records (grouped by run_tag/situation)
./iqmreader -file monitor_results.jsonl -n 10000

# Focus on a single situation/run_tag
./iqmreader -file monitor_results.jsonl -n 10000 -situation Home_CorporateLaptop_CorpProxy_SequencedTest
```

## Output example

```
Total batches: 19
Home_CorporateLaptop_CorpProxy_SequencedTest: 18
atHome_CorpLaptop_CorpProxy_ParallelTest_8: 1
```

## Notes
- Batches are grouped by `run_tag`.
- Uses the same analysis package as the viewer, with large scanner buffers to avoid truncation.
 - The analysis uses a dynamic reader with a 200MB per-line cap. Adjust in `src/analysis/analysis.go` (`MaxLineBytes`).
