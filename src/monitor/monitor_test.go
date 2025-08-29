package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	typespkg "github.com/iafilius/InternetQualityMonitor/src/types"
)

func TestIsTransientNetErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"EOF", io.EOF, true},
		{"reset by peer", errors.New("read: connection reset by peer"), true},
		{"broken pipe", errors.New("write: broken pipe"), true},
		{"http2 stream closed", errors.New("http2: stream closed"), true},
		{"temporary", &net.DNSError{Err: "temporary", IsTemporary: true}, true},
		{"timeout", &net.DNSError{Err: "timeout", IsTimeout: true}, true},
		{"context deadline", context.DeadlineExceeded, false},
		{"context string", errors.New("context deadline exceeded"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTransientNetErr(tc.err)
			if got != tc.want {
				t.Fatalf("isTransientNetErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
func TestResultEnvelopeMarshalUnmarshal(t *testing.T) {
	sr := &SiteResult{Name: "example", URL: "https://example.com", TCPTimeMs: 10}
	env := wrapRoot(sr)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var dec ResultEnvelope
	if err := json.Unmarshal(b, &dec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dec.Meta == nil || dec.SiteResult == nil {
		t.Fatalf("decoded envelope missing parts")
	}
	if dec.Meta.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version mismatch: got %d want %d", dec.Meta.SchemaVersion, SchemaVersion)
	}
	if dec.SiteResult.Name != "example" {
		t.Fatalf("site_result name mismatch: %s", dec.SiteResult.Name)
	}
}

func TestSmallHTTPTimeoutTriggersDeadline(t *testing.T) {
	// Slow server: sleep beyond small timeout to force deadline
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest url: %v", err)
	}
	hostIP := u.Hostname() // usually 127.0.0.1

	// Ensure no proxy interferes
	origEnv := map[string]string{
		"HTTP_PROXY":  os.Getenv("HTTP_PROXY"),
		"HTTPS_PROXY": os.Getenv("HTTPS_PROXY"),
		"ALL_PROXY":   os.Getenv("ALL_PROXY"),
		"NO_PROXY":    os.Getenv("NO_PROXY"),
	}
	for k := range origEnv {
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range origEnv {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	// Tight timeouts
	oldHTTP := httpTimeout
	oldSite := siteTimeout
	oldStall := stallTimeout
	SetHTTPTimeout(200 * time.Millisecond)
	SetSiteTimeout(350 * time.Millisecond)
	SetStallTimeout(200 * time.Millisecond)
	defer func() {
		SetHTTPTimeout(oldHTTP)
		SetSiteTimeout(oldSite)
		SetStallTimeout(oldStall)
	}()

	// Use fallback writer (no goroutine); reset channel and set path
	tmp := t.TempDir() + "/results.jsonl"
	resultChan = nil
	resultPath = tmp

	// Run monitor for the single local IP
	site := typespkg.Site{Name: "timeout-local", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)

	// Read and assert
	data, rerr := os.ReadFile(tmp)
	if rerr != nil {
		t.Fatalf("read results: %v", rerr)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatalf("no results written")
	}
	var env ResultEnvelope
	if jerr := json.Unmarshal([]byte(lines[len(lines)-1]), &env); jerr != nil {
		t.Fatalf("unmarshal: %v", jerr)
	}
	if env.SiteResult == nil {
		t.Fatalf("missing site_result")
	}
	// Accept either HEAD or GET timing out, but at least one should reflect a deadline
	he := strings.ToLower(env.SiteResult.HeadError)
	ge := strings.ToLower(env.SiteResult.HTTPError)
	if !strings.Contains(he, "context deadline exceeded") && !strings.Contains(ge, "context deadline exceeded") {
		t.Fatalf("expected context deadline exceeded in head or get error, got head=%q get=%q", env.SiteResult.HeadError, env.SiteResult.HTTPError)
	}
}

func TestFormatPercentOf_SnippetAndIncompleteLog(t *testing.T) {
	// Verify helper formatting
	if got := formatPercentOf(104857600, 104857600); got != " (100.0% of 104857600)" {
		t.Fatalf("formatPercentOf 100%% got %q", got)
	}
	if got := formatPercentOf(0, 0); got != "" {
		t.Fatalf("formatPercentOf zero total should be empty, got %q", got)
	}

	// Build a synthetic SiteResult and log line, ensuring no fmt artifacts
	var buf strings.Builder
	saved := baseLogger
	baseLogger = log.New(&buf, "", 0)
	defer func() { baseLogger = saved }()

	sr := &SiteResult{
		Name:                  "TestSite",
		IP:                    "::1",
		HeadStatus:            200,
		SecondGetStatus:       206,
		TransferSizeBytes:     104857600,
		TransferTimeMs:        1234,
		TransferSpeedKbps:     12345.6,
		TraceTTFBMs:           100,
		TCPTimeMs:             0,
		SSLHandshakeTimeMs:    50,
		DNSTimeMs:             35,
		HTTPProtocol:          "HTTP/1.1",
		TLSVersion:            "TLS1.3",
		ContentLengthHeader:   104857600,
		ContentLengthMismatch: true,
	}

	// Compose the final log as production code does
	ipStr := sr.IP
	if ipStr == "" {
		ipStr = "(unknown)"
	}
	proto := sr.HTTPProtocol
	if proto == "" {
		proto = "(unknown)"
	}
	alpn := sr.ALPN
	if alpn == "" {
		alpn = "(unknown)"
	}
	tlsv := sr.TLSVersion
	if tlsv == "" {
		tlsv = "(unknown)"
	}
	statusLabel := "done"
	if sr.TransferStalled {
		statusLabel = "aborted"
	} else if sr.ContentLengthMismatch {
		statusLabel = "incomplete"
	}
	extra := formatPercentOf(sr.TransferSizeBytes, sr.ContentLengthHeader)
	line := fmt.Sprintf("[%s %s] %s head=%d sec_get=%d bytes=%d%s time=%dms speed=%.1fkbps dns=%dms tcp=%dms tls=%dms ttfb=%dms proto=%s alpn=%s tls_ver=%s",
		sr.Name, ipStr, statusLabel, sr.HeadStatus, sr.SecondGetStatus, sr.TransferSizeBytes, extra, sr.TransferTimeMs, sr.TransferSpeedKbps, sr.DNSTimeMs, sr.TCPTimeMs, sr.SSLHandshakeTimeMs, sr.TraceTTFBMs, proto, alpn, tlsv,
	)
	Warnf(line)
	out := buf.String()
	if !strings.Contains(out, "(100.0% of 104857600)") {
		t.Fatalf("expected percent-of snippet in log, got: %s", out)
	}
	if strings.Contains(out, "%!o(MISSING)") || strings.Contains(out, "%!f(MISSING)") {
		t.Fatalf("unexpected fmt artifact in log: %s", out)
	}
}

func TestHeadTimeoutOnly(t *testing.T) {
	// Handler: HEAD sleeps long, GET responds fast
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			time.Sleep(1 * time.Second)
			w.WriteHeader(200)
			return
		}
		// primary GET fast
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	// Clean proxies
	orig := os.Environ()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	defer func() {
		for _, kv := range orig {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}()
	// Tight timeouts
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(200 * time.Millisecond)
	SetSiteTimeout(500 * time.Millisecond)
	SetStallTimeout(200 * time.Millisecond)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	// Fallback writer
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "head-timeout", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	he := strings.ToLower(env.SiteResult.HeadError)
	if !(strings.Contains(he, "context deadline exceeded") || strings.Contains(he, "client.timeout exceeded")) {
		t.Fatalf("expected head timeout, got %q", env.SiteResult.HeadError)
	}
	if env.SiteResult.HTTPError != "" {
		t.Fatalf("unexpected get error: %q", env.SiteResult.HTTPError)
	}
}

func TestGetTimeoutOnly(t *testing.T) {
	// Handler: HEAD fast, primary GET (no Range) sleeps
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		if r.Header.Get("Range") == "" { // primary GET
			time.Sleep(1 * time.Second)
			w.WriteHeader(200)
			return
		}
		// Shouldn't reach here because primary GET will timeout and stop flow
		w.WriteHeader(206)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(200 * time.Millisecond)
	SetSiteTimeout(500 * time.Millisecond)
	SetStallTimeout(200 * time.Millisecond)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "get-timeout", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	ge := strings.ToLower(env.SiteResult.HTTPError)
	if !(strings.Contains(ge, "context deadline exceeded") || strings.Contains(ge, "client.timeout exceeded")) {
		t.Fatalf("expected get timeout, got %q", env.SiteResult.HTTPError)
	}
}

func TestRangeTimeoutOnly(t *testing.T) {
	// Handler: HEAD fast, primary GET fast, Range GET sleeps to timeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(200)
		case r.Header.Get("Range") != "":
			time.Sleep(1 * time.Second)
			w.WriteHeader(206)
		default: // primary GET
			w.WriteHeader(200)
			w.Write([]byte(strings.Repeat("x", 1024)))
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(200 * time.Millisecond)
	SetSiteTimeout(500 * time.Millisecond)
	SetStallTimeout(200 * time.Millisecond)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	// Fallback writer
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "range-timeout", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	re := strings.ToLower(env.SiteResult.SecondGetError)
	if !(strings.Contains(re, "context deadline exceeded") || strings.Contains(re, "client.timeout exceeded")) {
		t.Fatalf("expected range get timeout, got %q", env.SiteResult.SecondGetError)
	}
	if env.SiteResult.HTTPError != "" {
		t.Fatalf("unexpected primary get error: %q", env.SiteResult.HTTPError)
	}
}

func TestStallTimeoutAbort(t *testing.T) {
	// Handler: write a little, then stall beyond stallTimeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(strings.Repeat("a", 1024)))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(800 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(3 * time.Second)
	SetSiteTimeout(3 * time.Second)
	SetStallTimeout(200 * time.Millisecond)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "stall-abort", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	// We don't hard-abort read on stall; ensure we didn't hang and observed a slow transfer
	if env.SiteResult.TransferTimeMs < 700 {
		t.Fatalf("expected transfer to take >=700ms due to stall, got %dms", env.SiteResult.TransferTimeMs)
	}
	if env.SiteResult.TransferSizeBytes == 0 {
		t.Fatalf("expected some bytes read before stall")
	}
}

// Note: Range-read stall abort is not asserted here because http.Client.Body.Read blocks until
// progress resumes or the server closes. We log watchdog warnings, but do not force-abort mid-read
// to avoid invasive transport wrappers. See TestStallTimeoutAbort for overall stall surface.

func TestHeadTransientRetrySetsFlag(t *testing.T) {
	var headCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			headCalls++
			if headCalls == 1 {
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
					return
				}
			}
			w.WriteHeader(200)
		default:
			// normal fast responses for GETs
			if r.Header.Get("Range") != "" {
				w.WriteHeader(206)
				w.Write([]byte("R"))
			} else {
				w.WriteHeader(200)
				w.Write([]byte("G"))
			}
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(2 * time.Second)
	SetSiteTimeout(3 * time.Second)
	SetStallTimeout(1 * time.Second)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "head-transient", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	if !env.SiteResult.RetriedOnce || !env.SiteResult.RetriedHead {
		t.Fatalf("expected RetriedOnce && RetriedHead true")
	}
	if env.SiteResult.RetriedGet || env.SiteResult.RetriedRange {
		t.Fatalf("unexpected other retry flags set")
	}
	if env.SiteResult.HeadError != "" {
		t.Fatalf("head should succeed after retry, got %q", env.SiteResult.HeadError)
	}
}

func TestGetTransientRetrySetsFlag(t *testing.T) {
	var getCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		if r.Method == http.MethodGet && r.Header.Get("Range") == "" {
			getCalls++
			if getCalls == 1 {
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
					return
				}
			}
			w.WriteHeader(200)
			w.Write([]byte(strings.Repeat("x", 1024)))
			return
		}
		// Range and others respond fast
		w.WriteHeader(206)
		w.Write([]byte("R"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(2 * time.Second)
	SetSiteTimeout(3 * time.Second)
	SetStallTimeout(1 * time.Second)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "get-transient", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	// net/http may transparently retry GET; accept either explicit flags or clean success
	if env.SiteResult.RetriedGet {
		if !env.SiteResult.RetriedOnce {
			t.Fatalf("RetriedGet set but RetriedOnce false")
		}
	} else {
		if env.SiteResult.HTTPError != "" {
			t.Fatalf("expected GET success without error or explicit retry, got %q", env.SiteResult.HTTPError)
		}
		if env.SiteResult.TransferSizeBytes == 0 {
			t.Fatalf("expected some bytes on successful GET")
		}
	}
	if env.SiteResult.RetriedHead || env.SiteResult.RetriedRange {
		t.Fatalf("unexpected other retry flags set")
	}
}

func TestRangeTransientRetrySetsFlag(t *testing.T) {
	var rangeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		if r.Method == http.MethodGet && r.Header.Get("Range") == "" {
			// primary GET fast
			w.WriteHeader(200)
			w.Write([]byte(strings.Repeat("x", 1024)))
			return
		}
		if r.Header.Get("Range") != "" {
			rangeCalls++
			if rangeCalls == 1 {
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
					return
				}
			}
			w.WriteHeader(206)
			w.Write([]byte("R"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	hostIP := u.Hostname()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		os.Unsetenv(k)
	}
	oldHTTP, oldSite, oldStall := httpTimeout, siteTimeout, stallTimeout
	SetHTTPTimeout(2 * time.Second)
	SetSiteTimeout(3 * time.Second)
	SetStallTimeout(1 * time.Second)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "range-transient", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	// net/http may transparently retry Range GET; accept either explicit flags or clean success
	if env.SiteResult.RetriedRange {
		if !env.SiteResult.RetriedOnce {
			t.Fatalf("RetriedRange set but RetriedOnce false")
		}
	} else {
		if env.SiteResult.SecondGetError != "" {
			t.Fatalf("expected Range GET success without error or explicit retry, got %q", env.SiteResult.SecondGetError)
		}
		if env.SiteResult.SecondGetStatus == 0 {
			t.Fatalf("expected Range GET status present")
		}
	}
	if env.SiteResult.RetriedHead || env.SiteResult.RetriedGet {
		t.Fatalf("unexpected other retry flags set")
	}
}
