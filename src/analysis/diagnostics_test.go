package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

// Test that the latest non-empty diagnostics (dns_server, dns_server_network, next_hop, next_hop_source)
// are propagated into the BatchSummary for a batch.
func TestAnalyzeRecentResults_DiagnosticsLatestWins(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	// Write two envelopes for the same run_tag: first has empty diagnostics, second has values.
	// Keep schema_version=3 to match monitor.SchemaVersion.
	// NOTE: Keep this minimal; analysis only relies on a subset of fields.
	lines := []string{
		"{\"meta\":{\"schema_version\":3,\"run_tag\":\"t1\",\"timestamp_utc\":\"2024-01-01T00:00:00Z\"},\"site_result\":{\"ip_family\":\"ipv4\",\"transfer_speed_kbps\":1000,\"trace_ttfb_ms\":100}}\n",
		"{\"meta\":{\"schema_version\":3,\"run_tag\":\"t1\",\"timestamp_utc\":\"2024-01-01T00:00:01Z\"},\"site_result\":{\"ip_family\":\"ipv4\",\"transfer_speed_kbps\":1100,\"trace_ttfb_ms\":90,\"dns_server\":\"9.9.9.9:53\",\"dns_server_network\":\"udp\",\"next_hop\":\"192.0.2.1\",\"next_hop_source\":\"route\"}}\n",
	}
	for _, s := range lines {
		if _, err := f.WriteString(s); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	f.Close()

	sums, err := AnalyzeRecentResultsFull(file, 3, 10, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("want 1 summary, got %d", len(sums))
	}
	s := sums[0]
	if s.DNSServer != "9.9.9.9:53" || s.DNSServerNetwork != "udp" {
		t.Fatalf("dns diagnostics not propagated: %#v", s)
	}
	if s.NextHop != "192.0.2.1" || s.NextHopSource != "route" {
		t.Fatalf("next-hop diagnostics not propagated: %#v", s)
	}
}
