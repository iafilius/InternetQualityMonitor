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

## Log lines explained (quick reference)

When running the monitor, status lines look like:

```
[Linode UK 100MB 2a01:7e00::…] done head=200 sec_get=206 bytes=104857600 (100.0% of 104857600) time=2893ms speed=35395.8kbps dns=35ms tcp=0ms tls=116ms ttfb=431ms proto=HTTP/1.1 alpn=(unknown) tls_ver=TLS1.3
```

- Status label: `done` = success, `aborted` = pre‑TTFB stall (transfer stopped before first byte), `incomplete` = partial body (early EOF or Content‑Length mismatch).
- `(x% of y)`: shown when the server provided a Content‑Length header; indicates how much of the expected body was received.
- `head` and `sec_get`: HEAD and GET HTTP status codes.
- `dns/tcp/tls/ttfb`: per‑phase timings; `proto/alpn/tls_ver`: negotiated protocol details.
