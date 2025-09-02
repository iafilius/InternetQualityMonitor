package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

func TestConnReuseRatesOverallAndPerFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "REUSE1"
	// IPv4: 2 lines, 1 reused
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv4", ConnectionReusedSecond: true})
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv4", ConnectionReusedSecond: false})
	// IPv6: 3 lines, 1 reused
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv6", ConnectionReusedSecond: true})
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv6", ConnectionReusedSecond: false})
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv6", ConnectionReusedSecond: false})

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	// Overall: 2/5 = 40%
	if d := abs(b.ConnReuseRatePct - 40.0); d > 1e-6 {
		t.Fatalf("overall reuse pct got %.3f want 40.000", b.ConnReuseRatePct)
	}
	if b.IPv4 == nil || b.IPv6 == nil {
		t.Fatalf("expected both IPv4 and IPv6 family summaries")
	}
	// IPv4: 1/2 = 50%
	if d := abs(b.IPv4.ConnReuseRatePct - 50.0); d > 1e-6 {
		t.Fatalf("ipv4 reuse pct got %.3f want 50.000", b.IPv4.ConnReuseRatePct)
	}
	// IPv6: 1/3 ≈ 33.333%
	if d := abs(b.IPv6.ConnReuseRatePct - 33.3333333); d > 1e-3 {
		t.Fatalf("ipv6 reuse pct got %.3f want ~33.333", b.IPv6.ConnReuseRatePct)
	}
}

func TestFamilyConnectTLSAverages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "FAM1"
	// IPv4 (2): connect 50,70; tls 30,40
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv4", TraceConnectMs: 50, TraceTLSMs: 30})
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv4", TCPTimeMs: 70, SSLHandshakeTimeMs: 40})
	// IPv6 (2): connect 90,110; tls 60 (one line without tls)
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv6", HTTPConnectTimeMs: 90})
	writeConnectLine(t, f, tag, &monitor.SiteResult{IPFamily: "ipv6", TraceConnectMs: 110, TraceTLSMs: 60})

	sums, err := AnalyzeRecentResultsFull(path, monitor.SchemaVersion, 5, "")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]

	// Overall connect avg = (50+70+90+110)/4 = 80
	if d := abs(b.AvgConnectMs - 80.0); d > 1e-6 {
		t.Fatalf("overall avg connect got %.3f want 80.000", b.AvgConnectMs)
	}
	// Overall tls avg = (30+40+60)/3 ≈ 43.333
	if d := abs(b.AvgTLSHandshake - 43.3333333); d > 1e-3 {
		t.Fatalf("overall avg tls got %.3f want ~43.333", b.AvgTLSHandshake)
	}
	if b.IPv4 == nil || b.IPv6 == nil {
		t.Fatalf("expected both IPv4 and IPv6 family summaries")
	}
	// IPv4 connect avg = (50+70)/2 = 60; tls = (30+40)/2 = 35
	if d := abs(b.IPv4.AvgConnectMs - 60.0); d > 1e-6 {
		t.Fatalf("ipv4 avg connect got %.3f want 60.000", b.IPv4.AvgConnectMs)
	}
	if d := abs(b.IPv4.AvgTLSHandshake - 35.0); d > 1e-6 {
		t.Fatalf("ipv4 avg tls got %.3f want 35.000", b.IPv4.AvgTLSHandshake)
	}
	// IPv6 connect avg = (90+110)/2 = 100; tls = (60)/1 = 60
	if d := abs(b.IPv6.AvgConnectMs - 100.0); d > 1e-6 {
		t.Fatalf("ipv6 avg connect got %.3f want 100.000", b.IPv6.AvgConnectMs)
	}
	if d := abs(b.IPv6.AvgTLSHandshake - 60.0); d > 1e-6 {
		t.Fatalf("ipv6 avg tls got %.3f want 60.000", b.IPv6.AvgTLSHandshake)
	}
}
