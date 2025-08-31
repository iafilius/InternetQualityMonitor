package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
)

func TestCommandBuilders_EmptyNextHop(t *testing.T) {
	cases := []analysis.BatchSummary{
		{NextHop: ""},
		{NextHop: "-"},
		{NextHop: "", DNSServer: ""},
		{NextHop: "-", DNSServer: "-"},
	}
	for _, bs := range cases {
		if got := buildTracerouteCommand(bs); got != "" {
			t.Fatalf("expected empty traceroute cmd for NextHop %q, got %q", bs.NextHop, got)
		}
		if got := buildPingCommand(bs); got != "" {
			t.Fatalf("expected empty ping cmd for NextHop %q, got %q", bs.NextHop, got)
		}
		if got := buildMTRCommand(bs); got != "" {
			t.Fatalf("expected empty mtr cmd for NextHop %q, got %q", bs.NextHop, got)
		}
	}
}

func TestCommandBuilders_NonEmptyNextHop(t *testing.T) {
	hop := "1.2.3.4"
	bs := analysis.BatchSummary{NextHop: hop}

	// traceroute command
	tr := buildTracerouteCommand(bs)
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(tr, "tracert ") || !strings.Contains(tr, hop) {
			t.Fatalf("unexpected traceroute cmd on windows: %q", tr)
		}
	} else {
		if !strings.HasPrefix(tr, "traceroute -n ") || !strings.Contains(tr, hop) {
			t.Fatalf("unexpected traceroute cmd on unix: %q", tr)
		}
	}

	// ping command
	pg := buildPingCommand(bs)
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(pg, "ping ") || !strings.Contains(pg, hop) {
			t.Fatalf("unexpected ping cmd on windows: %q", pg)
		}
	} else {
		if !strings.HasPrefix(pg, "ping -c 10 ") || !strings.Contains(pg, hop) {
			t.Fatalf("unexpected ping cmd on unix: %q", pg)
		}
	}

	// mtr command may or may not be available; if non-empty it must include hop
	mt := buildMTRCommand(bs)
	if mt != "" && !strings.Contains(mt, hop) {
		t.Fatalf("mtr cmd should include hop when non-empty: %q", mt)
	}
}

func TestCommandBuilders_FallbackToDNSServer(t *testing.T) {
	dns := "9.9.9.9"
	bs := analysis.BatchSummary{NextHop: "", DNSServer: dns}

	tr := buildTracerouteCommand(bs)
	if tr == "" || !strings.Contains(tr, dns) {
		t.Fatalf("expected traceroute to include dns fallback target, got %q", tr)
	}
	pg := buildPingCommand(bs)
	if pg == "" || !strings.Contains(pg, dns) {
		t.Fatalf("expected ping to include dns fallback target, got %q", pg)
	}
	mt := buildMTRCommand(bs)
	if mt != "" && !strings.Contains(mt, dns) {
		t.Fatalf("mtr, when present, should include dns fallback target, got %q", mt)
	}
}

func TestCurlVerboseCommand_NoURL(t *testing.T) {
	cases := []analysis.BatchSummary{{}, {SampleURL: ""}, {SampleURL: "-"}}
	for _, bs := range cases {
		if s := buildCurlVerboseCommand(bs); s != "" {
			t.Fatalf("expected empty curl command for missing URL, got %q", s)
		}
	}
}

func TestCurlVerboseCommand_WithURL_AndHints(t *testing.T) {
	bs := analysis.BatchSummary{SampleURL: "https://example.com/file.bin", HTTPProtocolRatePct: map[string]float64{"HTTP/2.0": 85}}
	s := buildCurlVerboseCommand(bs)
	if !strings.HasPrefix(s, "curl -v") || !strings.Contains(s, "https://example.com/file.bin") {
		t.Fatalf("unexpected curl cmd: %q", s)
	}
	// When HTTP/2 is dominant, expect --http2
	if !strings.Contains(s, "--http2") {
		t.Fatalf("expected --http2 hint in curl cmd, got %q", s)
	}
	// For HTTP/1.1 majority
	bs = analysis.BatchSummary{SampleURL: "https://example.com/x", HTTPProtocolRatePct: map[string]float64{"HTTP/1.1": 70}}
	s = buildCurlVerboseCommand(bs)
	if !strings.Contains(s, "--http1.1") {
		t.Fatalf("expected --http1.1 hint in curl cmd, got %q", s)
	}
	// For HTTP/3 majority
	bs = analysis.BatchSummary{SampleURL: "https://example.com/x", HTTPProtocolRatePct: map[string]float64{"HTTP/3": 90}}
	s = buildCurlVerboseCommand(bs)
	if !strings.Contains(s, "--http3") {
		t.Fatalf("expected --http3 hint in curl cmd, got %q", s)
	}
}
