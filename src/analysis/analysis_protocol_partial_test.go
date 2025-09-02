package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

func TestPartialBodyRateByHTTPProtocol(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	tag := "PBPROTO1"
	write := func(proto string, partial bool) {
		sr := &monitor.SiteResult{HTTPProtocol: proto}
		if partial {
			sr.ContentLengthMismatch = true
		}
		env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: tag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
		b, _ := json.Marshal(env)
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// For HTTP/2.0: 2 lines, 1 partial => 50%
	write("HTTP/2.0", true)
	write("HTTP/2.0", false)
	// For HTTP/1.1: 3 lines, 2 partial => 66.666%
	write("HTTP/1.1", true)
	write("HTTP/1.1", true)
	write("HTTP/1.1", false)
	// Unknown: 1 line, not partial => 0%
	write("", false)

	sums, err := AnalyzeRecentResultsFullWithOptions(path, monitor.SchemaVersion, 5, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 batch got %d", len(sums))
	}
	b := sums[0]
	if b.PartialBodyRateByHTTPProtocolPct == nil {
		t.Fatalf("expected map present")
	}
	if v := b.PartialBodyRateByHTTPProtocolPct["HTTP/2.0"]; abs(v-50.0) > 1e-6 {
		t.Fatalf("h2 partial rate got %.3f want 50.000", v)
	}
	if v := b.PartialBodyRateByHTTPProtocolPct["HTTP/1.1"]; abs(v-66.6666667) > 1e-3 {
		t.Fatalf("h1.1 partial rate got %.3f want ~66.667", v)
	}
	if v := b.PartialBodyRateByHTTPProtocolPct["(unknown)"]; abs(v-0.0) > 1e-6 {
		t.Fatalf("unknown partial rate got %.3f want 0.000", v)
	}
}
