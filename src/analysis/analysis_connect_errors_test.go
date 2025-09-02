package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

func TestConnectTLSIncludeErroredLinesInAverages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "CE1"
	// Two errored lines with timings
	writeConnectLine(t, f, tag, &monitor.SiteResult{TraceConnectMs: 50, TraceTLSMs: 30, HTTPError: "500"})
	writeConnectLine(t, f, tag, &monitor.SiteResult{TCPTimeMs: 70, SSLHandshakeTimeMs: 40, HTTPError: "timeout"})
	// One successful line with connect only
	writeConnectLine(t, f, tag, &monitor.SiteResult{HTTPConnectTimeMs: 90})

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	if b.ErrorLines != 2 {
		t.Fatalf("error lines got %d want 2", b.ErrorLines)
	}
	// Connect averages include all 3 lines with connect timings
	if diff := abs(b.AvgConnectMs - 70.0); diff > 1e-6 {
		t.Fatalf("avg connect got %.3f want 70.000", b.AvgConnectMs)
	}
	// TLS average includes the two errored lines with tls timings
	if diff := abs(b.AvgTLSHandshake - 35.0); diff > 1e-6 {
		t.Fatalf("avg tls handshake got %.3f want 35.000", b.AvgTLSHandshake)
	}
}
