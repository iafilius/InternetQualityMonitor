package analysis

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write a synthetic line with URL and error
func writeErrorLine(t *testing.T, f *os.File, runTag, url, tcpErr, httpErr string) {
	t.Helper()
	env := &monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion},
		SiteResult: &monitor.SiteResult{Name: "t", URL: url, TransferSpeedKbps: 0, TraceTTFBMs: 0, TransferSizeBytes: 0, TCPError: tcpErr, HTTPError: httpErr}}
	b, _ := json.Marshal(env)
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestErrorsByURLAggregation(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "results-*.jsonl")
	if err != nil {
		t.Fatalf("tmp: %v", err)
	}
	defer tmp.Close()
	// One batch with three URLs; introduce errors on two
	writeErrorLine(t, tmp, "20240101_000000", "https://a.test/x", "dial tcp: i/o timeout", "")
	writeErrorLine(t, tmp, "20240101_000000", "https://a.test/x", "dial tcp: i/o timeout", "")
	writeErrorLine(t, tmp, "20240101_000000", "https://b.test/y", "", "HTTP 503 Service Unavailable")
	// one success (no error)
	env := &monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: "20240101_000000", SchemaVersion: monitor.SchemaVersion}, SiteResult: &monitor.SiteResult{Name: "t", URL: "https://c.test/z", TransferSpeedKbps: 1000, TraceTTFBMs: 50, TransferSizeBytes: 1000}}
	b, _ := json.Marshal(env)
	tmp.Write(append(b, '\n'))

	sums, err := AnalyzeRecentResults(tmp.Name(), monitor.SchemaVersion, 10)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(sums))
	}
	m := sums[0].ErrorLinesByURL
	if len(m) != 2 {
		t.Fatalf("expected 2 URLs with errors, got %d: %+v", len(m), m)
	}
	if m["https://a.test/x"] != 2 {
		t.Fatalf("wrong count for a.test: %d", m["https://a.test/x"])
	}
	if m["https://b.test/y"] != 1 {
		t.Fatalf("wrong count for b.test: %d", m["https://b.test/y"])
	}
}
