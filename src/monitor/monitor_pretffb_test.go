package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	typespkg "github.com/iafilius/InternetQualityMonitor/src/types"
)

func TestPreTTFBStallCancellation(t *testing.T) {
	// Server: HEAD fast, primary GET delays first byte beyond stall timeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		if r.Method == http.MethodGet && r.Header.Get("Range") == "" {
			// Delay sending first byte to trigger pre-TTFB watchdog
			time.Sleep(600 * time.Millisecond)
			w.WriteHeader(200)
			w.Write([]byte("late-first-byte"))
			return
		}
		// Range (should not be reached on pre-TTFB cancel)
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
	SetStallTimeout(200 * time.Millisecond)
	defer func() { SetHTTPTimeout(oldHTTP); SetSiteTimeout(oldSite); SetStallTimeout(oldStall) }()
	// Enable the feature via package-level setter
	SetPreTTFBStall(true)
	defer SetPreTTFBStall(false)
	// Fallback writer
	tmp := t.TempDir() + "/res.jsonl"
	resultChan = nil
	resultPath = tmp
	site := typespkg.Site{Name: "pretffb", URL: srv.URL}
	MonitorSiteIP(site, hostIP, []string{hostIP}, 0)
	data, _ := os.ReadFile(tmp)
	var env ResultEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &env); err != nil {
		t.Fatal(err)
	}
	if env.SiteResult == nil {
		t.Fatalf("no site_result")
	}
	if env.SiteResult.HTTPError != "stall_pre_ttfb" {
		t.Fatalf("expected http_error=stall_pre_ttfb, got %q", env.SiteResult.HTTPError)
	}
}
