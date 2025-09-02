package analysis

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write one envelope line
func writeEnvLine(t *testing.T, f *os.File, env monitor.ResultEnvelope) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestProtocolTlsAlpnChunkedAggregations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	runTag := "20250101_000000"

	// Two HTTP/2.0 (h2, TLS1.3) lines, one stalled, both chunked
	for i := 0; i < 2; i++ {
		sr := &monitor.SiteResult{Name: "a", TransferSpeedKbps: 2000 + float64(i*1000), HTTPProtocol: "HTTP/2.0", ALPN: "h2", TLSVersion: "TLS1.3", Chunked: true}
		if i == 0 {
			sr.TransferStalled = true
		}
		env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: ts, RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
		writeEnvLine(t, f, env)
	}
	// One HTTP/1.1 (http/1.1, TLS1.2) with error, not chunked
	sr := &monitor.SiteResult{Name: "b", TransferSpeedKbps: 500, HTTPProtocol: "HTTP/1.1", ALPN: "http/1.1", TLSVersion: "TLS1.2", Chunked: false, HTTPError: "500"}
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: ts, RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	writeEnvLine(t, f, env)

	// One HTTP/1.0 (no TLS)
	sr = &monitor.SiteResult{Name: "c", TransferSpeedKbps: 300, HTTPProtocol: "HTTP/1.0"}
	env = monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: ts, RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	writeEnvLine(t, f, env)

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(sums))
	}
	b := sums[0]

	// Protocol counts
	if b.HTTPProtocolCounts["HTTP/2.0"] != 2 {
		t.Fatalf("h2 count= %v", b.HTTPProtocolCounts["HTTP/2.0"])
	}
	if b.HTTPProtocolCounts["HTTP/1.1"] != 1 {
		t.Fatalf("h1 count= %v", b.HTTPProtocolCounts["HTTP/1.1"])
	}
	if b.HTTPProtocolCounts["HTTP/1.0"] != 1 {
		t.Fatalf("h1.0 count= %v", b.HTTPProtocolCounts["HTTP/1.0"])
	}

	// Avg speed by protocol
	if v := b.AvgSpeedByHTTPProtocolKbps["HTTP/2.0"]; (v-2500) > 1e-6 && (2500-v) > 1e-6 {
		t.Fatalf("avg speed h2 got %.2f want 2500", v)
	}
	if v := b.AvgSpeedByHTTPProtocolKbps["HTTP/1.1"]; (v-500) > 1e-6 && (500-v) > 1e-6 {
		t.Fatalf("avg speed h1 got %.2f want 500", v)
	}
	if v := b.AvgSpeedByHTTPProtocolKbps["HTTP/1.0"]; (v-300) > 1e-6 && (300-v) > 1e-6 {
		t.Fatalf("avg speed h1.0 got %.2f want 300", v)
	}

	// Stall/Error rate by protocol
	if v := b.StallRateByHTTPProtocolPct["HTTP/2.0"]; (v-50) > 0.001 && (50-v) > 0.001 {
		t.Fatalf("stall rate h2 got %.3f want 50", v)
	}
	if v := b.ErrorRateByHTTPProtocolPct["HTTP/1.1"]; (v-100) > 0.001 && (100-v) > 0.001 {
		t.Fatalf("error rate h1 got %.3f want 100", v)
	}

	// Error share by protocol should sum to ~100% when errors exist
	if len(b.ErrorShareByHTTPProtocolPct) == 0 {
		t.Fatalf("expected non-empty error share map")
	}
	var sum float64
	for _, v := range b.ErrorShareByHTTPProtocolPct {
		sum += v
	}
	if diff := math.Abs(sum - 100.0); diff > 1e-6 {
		t.Fatalf("error share sum got %.6f want 100.000000 (diff=%.6f)", sum, diff)
	}

	// Stall share should also sum to ~100% when any stalls exist
	if len(b.StallShareByHTTPProtocolPct) == 0 {
		t.Fatalf("expected non-empty stall share map")
	}
	sum = 0
	for _, v := range b.StallShareByHTTPProtocolPct {
		sum += v
	}
	if diff := math.Abs(sum - 100.0); diff > 1e-6 {
		t.Fatalf("stall share sum got %.6f want 100.000000 (diff=%.6f)", sum, diff)
	}

	// No partials were recorded; partial share map may be empty
	if len(b.PartialShareByHTTPProtocolPct) != 0 {
		t.Fatalf("expected empty partial share map, got: %#v", b.PartialShareByHTTPProtocolPct)
	}

	// TLS and ALPN counts
	if b.TLSVersionCounts["TLS1.3"] != 2 {
		t.Fatalf("TLS1.3 count=%v", b.TLSVersionCounts["TLS1.3"])
	}
	if b.TLSVersionCounts["TLS1.2"] != 1 {
		t.Fatalf("TLS1.2 count=%v", b.TLSVersionCounts["TLS1.2"])
	}
	if b.ALPNCounts["h2"] != 2 {
		t.Fatalf("ALPN h2 count=%v", b.ALPNCounts["h2"])
	}
	if b.ALPNCounts["http/1.1"] != 1 {
		t.Fatalf("ALPN http/1.1 count=%v", b.ALPNCounts["http/1.1"])
	}

	// Chunked rate: 2 of 3 -> 66.666...
	if (b.ChunkedRatePct-66.6666667) > 0.1 && (66.6666667-b.ChunkedRatePct) > 0.1 {
		t.Fatalf("chunked rate got %.3f want ~66.667", b.ChunkedRatePct)
	}
}
