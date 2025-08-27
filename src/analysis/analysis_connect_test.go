package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write a SiteResult with connect/tls fields
func writeConnectLine(t *testing.T, f *os.File, runTag string, sr *monitor.SiteResult) {
	t.Helper()
	env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
	b, err := json.Marshal(&env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestConnectAndTLSAggregation_MixedSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "C1"
	// Line 1: trace-based connect/tls
	writeConnectLine(t, f, tag, &monitor.SiteResult{TraceConnectMs: 50, TraceTLSMs: 30})
	// Line 2: tcp_time and ssl_handshake fallback
	writeConnectLine(t, f, tag, &monitor.SiteResult{TCPTimeMs: 70, SSLHandshakeTimeMs: 40})
	// Line 3: http_connect fallback, no TLS
	writeConnectLine(t, f, tag, &monitor.SiteResult{HTTPConnectTimeMs: 90})
	// Line 4: zeros (should be ignored)
	writeConnectLine(t, f, tag, &monitor.SiteResult{})

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	// AvgConnectMs = avg(50, 70, 90) = 70
	if diff := abs(b.AvgConnectMs - 70.0); diff > 1e-6 {
		t.Fatalf("avg connect got %.3f want 70.000", b.AvgConnectMs)
	}
	// AvgTLSHandshake = avg(30, 40) = 35
	if diff := abs(b.AvgTLSHandshake - 35.0); diff > 1e-6 {
		t.Fatalf("avg tls handshake got %.3f want 35.000", b.AvgTLSHandshake)
	}
}

func TestConnectPrecedence_TraceBeatsTCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "C2"
	// Both set: TraceConnectMs should take precedence over TCPTimeMs
	writeConnectLine(t, f, tag, &monitor.SiteResult{TraceConnectMs: 60, TCPTimeMs: 100})

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	if diff := abs(b.AvgConnectMs - 60.0); diff > 1e-6 {
		t.Fatalf("avg connect got %.3f want 60.000 (trace precedence)", b.AvgConnectMs)
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
