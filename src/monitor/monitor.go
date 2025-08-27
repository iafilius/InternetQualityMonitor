package monitor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/types"
	"github.com/oschwald/geoip2-golang"
)

const SpeedSampleInterval = 100 * time.Millisecond

// DefaultResultsFile centralizes the default JSONL results filename so main and
// internal fallbacks remain consistent.
const DefaultResultsFile = "monitor_results.jsonl"

// SchemaVersion indicates the compatibility / schema version for the JSONL meta+site_result structure.
// Increment this when breaking changes are made to field names/types.
// v2: emit pure typed SiteResult (legacy duplicate map fields removed)
// v3: Meta also strongly typed (no generic map)
const SchemaVersion = 3

// SiteResult is an in-progress strongly typed representation of a site measurement.
// Output now fully uses strongly typed structs (legacy map[string]interface{} usage removed).
type SiteResult struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
	IP   string `json:"ip,omitempty"`
	// Migrated scalar timing / status fields
	TCPTimeMs          int64  `json:"tcp_time_ms,omitempty"`
	TCPError           string `json:"tcp_error,omitempty"`
	SSLHandshakeTimeMs int64  `json:"ssl_handshake_time_ms,omitempty"`
	SSLError           string `json:"ssl_error,omitempty"`
	TraceTTFBMs        int64  `json:"trace_ttfb_ms,omitempty"`
	HeadStatus         int    `json:"head_status,omitempty"`
	HeadError          string `json:"head_error,omitempty"`
	HTTPError          string `json:"http_error,omitempty"`
	HeadTimeMs         int64  `json:"head_time_ms,omitempty"`
	// Transfer metrics
	TransferTimeMs    int64   `json:"transfer_time_ms,omitempty"`
	TransferSizeBytes int64   `json:"transfer_size_bytes,omitempty"`
	TransferSpeedKbps float64 `json:"transfer_speed_kbps,omitempty"`
	TransferStalled   bool    `json:"transfer_stalled,omitempty"`
	StallElapsedMs    int64   `json:"stall_elapsed_ms,omitempty"`
	// Secondary (range) GET
	SecondGetStatus       int    `json:"second_get_status,omitempty"`
	SecondGetTimeMs       int64  `json:"second_get_time_ms,omitempty"`
	SecondGetHeaderAge    string `json:"second_get_header_age,omitempty"`
	SecondGetXCache       string `json:"second_get_x_cache,omitempty"`
	SecondGetContentRange string `json:"second_get_content_range,omitempty"`
	SecondGetError        string `json:"second_get_error,omitempty"`
	SecondGetCachePresent bool   `json:"second_get_cache_present,omitempty"`
	// Warm HEAD / connection reuse
	WarmHeadTimeMs         int64 `json:"warm_head_time_ms,omitempty"`
	WarmHeadSpeedup        bool  `json:"warm_head_speedup,omitempty"`
	WarmCacheSuspected     bool  `json:"warm_cache_suspected,omitempty"`
	DialCount              int   `json:"dial_count,omitempty"`
	ConnectionReusedSecond bool  `json:"connection_reused_second_get,omitempty"`
	// Protocol/TLS/encoding telemetry (for diagnostics, esp. with proxies)
	HTTPProtocol      string   `json:"http_protocol,omitempty"`     // e.g., HTTP/1.1, HTTP/2.0
	TLSVersion        string   `json:"tls_version,omitempty"`       // e.g., TLS1.2, TLS1.3
	TLSCipher         string   `json:"tls_cipher,omitempty"`        // e.g., TLS_AES_128_GCM_SHA256
	ALPN              string   `json:"alpn,omitempty"`              // e.g., h2, http/1.1
	TransferEncoding  string   `json:"transfer_encoding,omitempty"` // joined list, e.g., chunked
	Chunked           bool     `json:"chunked,omitempty"`
	CountryConfigured string   `json:"country_configured,omitempty"`
	CountryGeoIP      string   `json:"country_geoip,omitempty"`
	DNSIPs            []string `json:"dns_ips,omitempty"`
	DNSTimeMs         int64    `json:"dns_time_ms,omitempty"`
	ResolvedIP        string   `json:"resolved_ip,omitempty"`
	IPIndex           int      `json:"ip_index,omitempty"`
	IPFamily          string   `json:"ip_family,omitempty"`
	ASNNumber         uint     `json:"asn_number,omitempty"`
	ASNOrg            string   `json:"asn_org,omitempty"`
	RemoteIP          string   `json:"remote_ip,omitempty"`
	CachePresent      bool     `json:"cache_present,omitempty"`
	IPMismatch        bool     `json:"ip_mismatch,omitempty"`
	PrefetchSuspected bool     `json:"prefetch_suspected,omitempty"`
	ProxySuspected    bool     `json:"proxy_suspected,omitempty"`
	ProbeHeaderValue  string   `json:"probe_header_value,omitempty"`
	ProbeEchoed       bool     `json:"probe_echoed,omitempty"`
	HeadGetTimeRatio  float64  `json:"head_get_time_ratio,omitempty"`
	// Control-plane flags
	RetriedOnce  bool `json:"retried_once,omitempty"`
	RetriedHead  bool `json:"retried_head,omitempty"`
	RetriedGet   bool `json:"retried_get,omitempty"`
	RetriedRange bool `json:"retried_range,omitempty"`
	// Trace timings
	TraceDNSMs        int64 `json:"trace_dns_ms,omitempty"`
	TraceConnectMs    int64 `json:"trace_connect_ms,omitempty"`
	TraceTLSMs        int64 `json:"trace_tls_ms,omitempty"`
	TraceTimeToConnMs int64 `json:"trace_time_to_conn_ms,omitempty"`
	HTTPConnectTimeMs int64 `json:"http_connect_time_ms,omitempty"`
	// Headers (primary GET / HEAD)
	HeaderVia    string `json:"header_via,omitempty"`
	HeaderXCache string `json:"header_x_cache,omitempty"`
	HeaderAge    string `json:"header_age,omitempty"`
	HeaderServer string `json:"header_server,omitempty"`
	// Proxy identification (heuristic). proxy_suspected remains a broader flag; these fields
	// attempt to classify the proxy/CDN if discernible from headers.
	ProxyName   string `json:"proxy_name,omitempty"`
	ProxySource string `json:"proxy_source,omitempty"`
	// ProxyIndicators lists raw indicator tokens (header names or key substrings) observed that
	// contributed to proxy/CDN detection (e.g. cf-ray, x-akamai-request-id, x-zscaler-*) to aid
	// downstream auditing & new heuristic refinement.
	ProxyIndicators []string `json:"proxy_indicators,omitempty"`
	// Go's proxy resolution (respecting environment variables like HTTPS_PROXY / NO_PROXY) for the target URL.
	// This records what proxy (if any) the standard library would use before any custom transport overrides.
	EnvProxyURL string `json:"env_proxy_url,omitempty"`
	// Whether NO_PROXY excluded the host (explicit bypass) when EnvProxyURL is empty.
	EnvProxyBypassed bool `json:"env_proxy_bypassed,omitempty"`
	UsingEnvProxy    bool `json:"using_env_proxy,omitempty"`
	// When using a proxy, remote_ip reflects the proxy endpoint. These fields explicitly label and duplicate it
	// so downstream processors need not infer from header heuristics.
	ProxyRemoteIP      string `json:"proxy_remote_ip,omitempty"`
	ProxyRemoteIsProxy bool   `json:"proxy_remote_is_proxy,omitempty"`
	// OriginIPCandidate attempts to record the underlying origin server IP when a proxy is used.
	// For direct connections this is identical to remote_ip. When an HTTP proxy is used the
	// underlying origin IP is not visible (tunnel established to proxy). In that case we fall
	// back to the first resolved DNS IP (if any) so downstream analysis can still reason about
	// suspected origin location / ASN. It is best-effort and may be empty.
	OriginIPCandidate string `json:"origin_ip_candidate,omitempty"`
	// TLS certificate subject / issuer (leaf). Included only when captured for potential
	// corporate proxy MITM detection (Zscaler, Bluecoat, Palo Alto, Netskope, Forcepoint, etc.).
	TLSCertSubject string `json:"tls_cert_subject,omitempty"`
	TLSCertIssuer  string `json:"tls_cert_issuer,omitempty"`
	// First RTT derived metrics
	FirstRTTBytes         int64   `json:"first_rtt_bytes,omitempty"`
	FirstRTTGoodputKbps   float64 `json:"first_rtt_goodput_kbps,omitempty"`
	ContentLengthMismatch bool    `json:"content_length_mismatch,omitempty"`
	ContentLengthHeader   int64   `json:"content_length_header,omitempty"`
	// Samples & analysis
	TransferSpeedSamples []SpeedSample  `json:"transfer_speed_samples,omitempty"`
	SpeedAnalysis        *SpeedAnalysis `json:"speed_analysis,omitempty"`
	// Additional fields will be added progressively.
}

// SpeedSample represents one periodic throughput sample.
type SpeedSample struct {
	TimeMs int64   `json:"time_ms"`
	Bytes  int64   `json:"bytes"`
	Speed  float64 `json:"speed_kbps"`
}

// PlateauSegment captures a relatively stable throughput window.
type PlateauSegment struct {
	StartMs    int64   `json:"start_ms"`
	EndMs      int64   `json:"end_ms"`
	DurationMs int64   `json:"duration_ms"`
	AvgKbps    float64 `json:"avg_kbps"`
}

// SpeedAnalysis provides aggregated statistics & qualitative insights.
type SpeedAnalysis struct {
	AverageKbps      float64          `json:"average_kbps"`
	StddevKbps       float64          `json:"stddev_kbps"`
	CoefVariation    float64          `json:"coef_variation"`
	MinKbps          float64          `json:"min_kbps"`
	MaxKbps          float64          `json:"max_kbps"`
	P50Kbps          float64          `json:"p50_kbps"`
	P90Kbps          float64          `json:"p90_kbps"`
	P95Kbps          float64          `json:"p95_kbps"`
	P99Kbps          float64          `json:"p99_kbps"`
	SlopeKbpsPerSec  float64          `json:"slope_kbps_per_sec"`
	JitterMeanAbsPct float64          `json:"jitter_mean_abs_pct"`
	Patterns         []string         `json:"patterns"`
	PlateauCount     int              `json:"plateau_count"`
	LongestPlateauMs int64            `json:"longest_plateau_ms"`
	PlateauStable    bool             `json:"plateau_stable"`
	PlateauSegments  []PlateauSegment `json:"plateau_segments"`
	Insights         []string         `json:"insights,omitempty"`
}

// ResultEnvelope is the strongly-typed root object written as one JSONL line.
// For now SiteResult remains a generic map while we transition to the struct above.
// Meta holds environment & run metadata (strongly typed in schema v3+).
type Meta struct {
	TimestampUTC         string   `json:"timestamp_utc"`
	Situation            string   `json:"situation,omitempty"` // Situation on front of json (struct keeps ordering)
	RunTag               string   `json:"run_tag,omitempty"`   // RunTag also in front of json (struct keeps ordering)
	Hostname             string   `json:"hostname,omitempty"`
	OS                   string   `json:"os,omitempty"`
	Arch                 string   `json:"arch,omitempty"`
	NumCPU               int      `json:"num_cpu,omitempty"`
	GOMAXPROCS           int      `json:"gomaxprocs,omitempty"`
	User                 string   `json:"user,omitempty"`
	LoadAvg1             float64  `json:"load_avg_1,omitempty"`
	LoadAvg5             float64  `json:"load_avg_5,omitempty"`
	LoadAvg15            float64  `json:"load_avg_15,omitempty"`
	UptimeSeconds        float64  `json:"uptime_seconds,omitempty"`
	KernelVersion        string   `json:"kernel_version,omitempty"`
	LocalIP              string   `json:"local_ip,omitempty"`
	DefaultIface         string   `json:"default_iface,omitempty"`
	PublicIPv4Candidates []string `json:"public_ipv4_candidates,omitempty"`
	PublicIPv6Candidates []string `json:"public_ipv6_candidates,omitempty"`
	PublicIPv4Consensus  string   `json:"public_ipv4_consensus,omitempty"`
	PublicIPv6Consensus  string   `json:"public_ipv6_consensus,omitempty"`
	PublicIPv4ASNNumber  uint     `json:"public_ipv4_asn_number,omitempty"`
	PublicIPv4ASNOrg     string   `json:"public_ipv4_asn_org,omitempty"`
	PublicIPv6ASNNumber  uint     `json:"public_ipv6_asn_number,omitempty"`
	PublicIPv6ASNOrg     string   `json:"public_ipv6_asn_org,omitempty"`
	ConnectionType       string   `json:"connection_type,omitempty"`
	Containerized        bool     `json:"containerized"`
	HomeOfficeEstimate   string   `json:"home_office_estimate,omitempty"`
	SchemaVersion        int      `json:"schema_version"`
}

type ResultEnvelope struct {
	Meta       *Meta       `json:"meta"`
	SiteResult *SiteResult `json:"site_result"`
}

var (
	resultChan        chan *ResultEnvelope
	writerOnce        sync.Once
	writerWG          sync.WaitGroup
	resultPath        string
	runTag            string
	fallbackWriteOnce sync.Once
	currentSituation  string
	httpTimeout       = 120 * time.Second
	stallTimeout      = 20 * time.Second
	siteTimeout       time.Duration     // overall per-site timeout (covers DNS+all IP attempts)
	dnsTimeoutDefault = 5 * time.Second // used for DNS when siteTimeout is 0
	maxIPsPerSite     int               // if >0 limit IPs processed per site (e.g. first v4 + first v6)
)

// SetHTTPTimeout configures the per-request total timeout (HEAD, GET, range & warm HEAD individually).
func SetHTTPTimeout(d time.Duration) {
	if d > 0 {
		httpTimeout = d
	}
}

// SetStallTimeout configures the maximum interval with no progress (no bytes read) before aborting a transfer.
func SetStallTimeout(d time.Duration) {
	if d > 0 {
		stallTimeout = d
	}
}

// SetDNSTimeout configures the default DNS timeout used when no siteTimeout is set.
func SetDNSTimeout(d time.Duration) {
	if d > 0 {
		dnsTimeoutDefault = d
	}
}

// SetSiteTimeout sets an upper bound on total time spent inside one MonitorSite call.
// 0 disables the limit.
func SetSiteTimeout(d time.Duration) {
	if d > 0 {
		siteTimeout = d
	}
}

// SetMaxIPsPerSite limits how many resolved IPs (across v4/v6) are probed per site. 0 means all.
func SetMaxIPsPerSite(n int) {
	if n > 0 {
		maxIPsPerSite = n
	}
}

// isTransientNetErr returns true for common transient network errors where a single retry may succeed.
func isTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	// Unwrap and inspect error messages conservatively; avoid brittle exact matches.
	es := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, io.EOF):
		return true
	case strings.Contains(es, "use of closed network connection"):
		return true
	case strings.Contains(es, "connection reset by peer"):
		return true
	case strings.Contains(es, "broken pipe"):
		return true
	case strings.Contains(es, "http2") && strings.Contains(es, "stream closed"):
		return true
	case strings.Contains(es, "temporary") || strings.Contains(es, "timeout"):
		// don't treat context deadline exceeded as transient
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(es, "context deadline exceeded") {
			return false
		}
		return true
	default:
		return false
	}
}

// InitResultWriter sets up an async JSONL writer (single goroutine) with a buffered channel.
func InitResultWriter(path string) {
	resultPath = path
	writerOnce.Do(func() {
		fmt.Printf("[writer] results file (append): %s\n", resultPath)
		resultChan = make(chan *ResultEnvelope, 128)
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			f, err := os.OpenFile(resultPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Println("open results file:", err)
				return
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			for r := range resultChan {
				if r == nil {
					continue
				}
				if err := enc.Encode(r); err != nil {
					fmt.Println("encode result:", err)
				}
			}
		}()
	})
}

// CloseResultWriter flushes and closes the async writer.
func CloseResultWriter() {
	if resultChan != nil {
		close(resultChan)
		writerWG.Wait()
	}
}

// MonitorSite performs the measurement and writes a JSONL line via writeResult.
func MonitorSite(site types.Site) {
	parsed, err := url.Parse(site.URL)
	if err != nil {
		Errorf("parse url %s: %v", site.URL, err)
		return
	}
	if getLevel() == LevelDebug {
		Debugf("[%s] start monitor", site.Name)
	} else if getLevel() == LevelInfo {
		Infof("[%s] start", site.Name)
	}
	host := parsed.Hostname()

	// Prepare context for entire site operation
	startSite := time.Now()
	ctx := context.Background()
	if siteTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, siteTimeout)
		defer cancel()
	}

	// DNS resolve once (always context-aware). If no siteTimeout is set, bound DNS to 5s.
	Debugf("[%s] DNS lookup %s", site.Name, host)
	start := time.Now()
	var ips []net.IP
	dnsCtx := ctx
	var dnsCancel context.CancelFunc
	if siteTimeout <= 0 {
		dnsCtx, dnsCancel = context.WithTimeout(context.Background(), dnsTimeoutDefault)
		defer dnsCancel()
	}
	addrs, derr := net.DefaultResolver.LookupIPAddr(dnsCtx, host)
	if derr != nil {
		err = derr
	} else {
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	dnsTime := time.Since(start)
	if err != nil || len(ips) == 0 {
		res := &SiteResult{Name: site.Name, URL: site.URL, CountryConfigured: site.Country, DNSTimeMs: dnsTime.Milliseconds()}
		// dns_error no longer persisted in v2; tcp_error/ssl_error/http_error fields retained.
		writeResult(wrapRoot(res))
		Warnf("[%s] DNS failed: %v", site.Name, err)
		return
	}
	var dnsIPs []string
	for _, ipr := range ips {
		dnsIPs = append(dnsIPs, ipr.String())
	}

	// Optionally limit IPs processed (e.g. first v4 + first v6) to avoid long sequential work per site.
	if maxIPsPerSite > 0 && len(ips) > maxIPsPerSite {
		var selected []net.IP
		var v4, v6 net.IP
		for _, ip := range ips {
			if ip.To4() != nil && v4 == nil {
				v4 = ip
			}
			if ip.To4() == nil && v6 == nil {
				v6 = ip
			}
			if (v4 != nil) && (v6 != nil) {
				break
			}
		}
		if v4 != nil {
			selected = append(selected, v4)
		}
		if v6 != nil && (maxIPsPerSite > 1 || v4 == nil) {
			selected = append(selected, v6)
		}
		if len(selected) == 0 {
			selected = ips[:maxIPsPerSite]
		}
		ips = selected
	}

	// Iterate over each selected IP and perform full measurement per IP.
	for idx, ipAddr := range ips {
		// Check site-level timeout before starting next IP
		if siteTimeout > 0 && time.Since(startSite) >= siteTimeout {
			Warnf("[%s] site timeout reached after %s (aborting remaining IPs)", site.Name, time.Since(startSite))
			return
		}
		monitorOneIP(ctx, site, ipAddr, idx, dnsIPs, dnsTime)
	}
}

// MonitorSiteIP performs monitoring for a single site & specific IP (pre-resolved).
// dnsIPs is the full list of resolved IPs for the site (both families) and dnsTimeMs
// represents the DNS lookup duration in milliseconds for context.
func MonitorSiteIP(site types.Site, ipStr string, dnsIPs []string, dnsTimeMs int64) {
	ipAddr := net.ParseIP(ipStr)
	if ipAddr == nil {
		Errorf("[%s %s] invalid ip", site.Name, ipStr)
		return
	}
	// Determine index in slice (best effort)
	idx := 0
	for i, v := range dnsIPs {
		if v == ipStr {
			idx = i
			break
		}
	}
	ctx := context.Background()
	startSite := time.Now()
	if siteTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, siteTimeout)
		defer cancel()
	}
	monitorOneIP(ctx, site, ipAddr, idx, dnsIPs, time.Duration(dnsTimeMs)*time.Millisecond)
	_ = startSite // reserved for potential future site-level metrics
}

// monitorOneIP encapsulates the original per-IP logic from MonitorSite, allowing reuse by MonitorSiteIP.
func monitorOneIP(ctx context.Context, site types.Site, ipAddr net.IP, idx int, dnsIPs []string, dnsTime time.Duration) {
	ipStr := ipAddr.String()
	parsed, err := url.Parse(site.URL)
	if err != nil {
		Errorf("parse url %s: %v", site.URL, err)
		return
	}
	// Determine environment proxy (standard library resolution) for transparency
	var envProxyURL string
	var envBypass bool
	reqURL := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	if pu, perr := http.ProxyFromEnvironment(&http.Request{URL: reqURL}); perr == nil {
		if pu != nil {
			envProxyURL = pu.String()
		}
	} else {
		Debugf("[%s %s] proxy resolution error: %v", site.Name, ipStr, perr)
	}
	if envProxyURL == "" { // check if NO_PROXY caused bypass
		if os.Getenv("HTTPS_PROXY") != "" || os.Getenv("HTTP_PROXY") != "" || os.Getenv("ALL_PROXY") != "" {
			envBypass = true
		}
	}
	var start time.Time
	// Begin migration to typed SiteResult: maintain legacy map for rich metrics while introducing sr.
	sr := &SiteResult{Name: site.Name, URL: site.URL, IP: ipStr, CountryConfigured: site.Country, DNSIPs: dnsIPs, DNSTimeMs: dnsTime.Milliseconds(), ResolvedIP: ipStr, IPIndex: idx}
	if envProxyURL != "" {
		sr.EnvProxyURL = envProxyURL
	} else if envBypass {
		sr.EnvProxyBypassed = true
	}
	if ipAddr.To4() != nil {
		sr.IPFamily = "ipv4"
	} else {
		sr.IPFamily = "ipv6"
	}

	// GeoIP per IP (prefer GeoIP2 mmdb; fall back to legacy database on Linux only via build tag helper)
	if country, ok := lookupGeoIP2Country(ipAddr); ok {
		sr.CountryGeoIP = country
	} else if cc, ok := lookupLegacyCountry(ipStr); ok { // linux-only; stubbed out elsewhere
		sr.CountryGeoIP = cc
	}

	// Direct TCP connect to specific IP (SNI host for TLS later)
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	// For IPv6 addresses we must wrap the literal in brackets before adding the port.
	var target string
	if ipAddr.To4() == nil && strings.Contains(ipStr, ":") && !strings.HasPrefix(ipStr, "[") {
		target = "[" + ipStr + "]:" + port
	} else {
		target = ipStr + ":" + port
	}
	Debugf("[%s %s] TCP connect %s", site.Name, ipStr, target)
	start = time.Now()
	conn, cerr := net.DialTimeout("tcp", target, 10*time.Second)
	tcpTime := time.Since(start)
	sr.TCPTimeMs = tcpTime.Milliseconds()
	if cerr != nil {
		sr.TCPError = cerr.Error()
		writeResult(wrapRoot(sr))
		Warnf("[%s %s] TCP connect failed: %v", site.Name, ipStr, cerr)
		return
	}

	if parsed.Scheme == "https" {
		Debugf("[%s %s] TLS handshake", site.Name, ipStr)
		tlsStart := time.Now()
		cfg := &tls.Config{ServerName: parsed.Hostname()}
		tlsConn := tls.Client(conn, cfg)
		// Ensure the manual handshake cannot block indefinitely. Use a bounded deadline
		// based on configured timeouts (prefer the lower of siteTimeout and httpTimeout; fallback 20s).
		hsDeadline := 20 * time.Second
		if httpTimeout > 0 && httpTimeout < hsDeadline {
			hsDeadline = httpTimeout
		}
		if siteTimeout > 0 && siteTimeout < hsDeadline {
			hsDeadline = siteTimeout
		}
		_ = tlsConn.SetDeadline(time.Now().Add(hsDeadline))
		herr := tlsConn.Handshake()
		// Clear deadline after handshake attempt
		_ = tlsConn.SetDeadline(time.Time{})
		tlt := time.Since(tlsStart)
		sr.SSLHandshakeTimeMs = tlt.Milliseconds()
		if herr != nil {
			sr.SSLError = herr.Error()
			tlsConn.Close()
			writeResult(wrapRoot(sr))
			Warnf("[%s %s] TLS failed: %v", site.Name, ipStr, herr)
			return
		}
		// Extract certificate subject/issuer for corporate proxy detection heuristics.
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			// Use CommonName if present plus first DNSName for brevity.
			var subjParts []string
			if leaf.Subject.CommonName != "" {
				subjParts = append(subjParts, leaf.Subject.CommonName)
			}
			if len(leaf.DNSNames) > 0 {
				subjParts = append(subjParts, leaf.DNSNames[0])
			}
			if len(subjParts) > 0 {
				sr.TLSCertSubject = strings.Join(subjParts, ",")
			}
			issuer := leaf.Issuer.CommonName
			if issuer == "" && len(leaf.Issuer.Organization) > 0 {
				issuer = leaf.Issuer.Organization[0]
			}
			if issuer != "" {
				sr.TLSCertIssuer = issuer
			}
			// Quick heuristic: corporate proxies often insert their brand in issuer or subject.
			li := strings.ToLower(sr.TLSCertIssuer + " " + sr.TLSCertSubject)
			if sr.ProxyName == "" { // only override if not already classified via headers
				switch {
				case strings.Contains(li, "zscaler"):
					sr.ProxyName = "zscaler"
					sr.ProxySource = "tls_cert"
					sr.ProxyIndicators = append(sr.ProxyIndicators, "cert:zscaler")
				case strings.Contains(li, "bluecoat") || strings.Contains(li, "symantec"):
					sr.ProxyName = "bluecoat"
					sr.ProxySource = "tls_cert"
					sr.ProxyIndicators = append(sr.ProxyIndicators, "cert:bluecoat")
				case strings.Contains(li, "netskope"):
					sr.ProxyName = "netskope"
					sr.ProxySource = "tls_cert"
					sr.ProxyIndicators = append(sr.ProxyIndicators, "cert:netskope")
				case strings.Contains(li, "palo alto") || strings.Contains(li, "palonetworks") || strings.Contains(li, "palosecure"):
					sr.ProxyName = "paloalto"
					sr.ProxySource = "tls_cert"
					sr.ProxyIndicators = append(sr.ProxyIndicators, "cert:paloalto")
				case strings.Contains(li, "forcepoint"):
					sr.ProxyName = "forcepoint"
					sr.ProxySource = "tls_cert"
					sr.ProxyIndicators = append(sr.ProxyIndicators, "cert:forcepoint")
				}
			}
		}
		tlsConn.Close()
	} else {
		conn.Close()
	}

	// Probe header value
	probeBytes := make([]byte, 8)
	rand.Read(probeBytes)
	probeVal := hex.EncodeToString(probeBytes)
	var remoteIP string
	dialCount := 0
	var transport *http.Transport
	if sr.EnvProxyURL != "" { // use proxy-aware transport; still wrap DialContext to record proxy connect timing & remoteIP
		proxyURL, _ := url.Parse(sr.EnvProxyURL)
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
				c, e := d.DialContext(ctx, network, address)
				if e == nil && remoteIP == "" {
					if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
						remoteIP = ta.IP.String()
					} else {
						remoteIP = c.RemoteAddr().String()
					}
					dialCount++
					// record as proxy endpoint
					sr.ProxyRemoteIP = remoteIP
					sr.ProxyRemoteIsProxy = true
					// best effort: origin candidate from DNS list (first entry) if present
					if sr.OriginIPCandidate == "" && len(sr.DNSIPs) > 0 {
						sr.OriginIPCandidate = sr.DNSIPs[0]
					}
				}
				return c, e
			},
			TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: httpTimeout,
			IdleConnTimeout:       30 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		}
		sr.UsingEnvProxy = true
	} else {
		// Direct IP dial preserving Host header
		transport = &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			c, e := d.DialContext(ctx, network, target)
			if e == nil && remoteIP == "" {
				if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
					remoteIP = ta.IP.String()
				} else {
					remoteIP = c.RemoteAddr().String()
				}
				dialCount++
				// direct path: origin candidate == remote IP
				if sr.OriginIPCandidate == "" {
					sr.OriginIPCandidate = remoteIP
				}
			}
			return c, e
		},
			TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: httpTimeout,
			IdleConnTimeout:       30 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		}
	}
	client := &http.Client{Transport: transport, Timeout: httpTimeout}

	// HEAD (with one-shot transient retry)
	Debugf("[%s %s] HEAD %s", site.Name, ipStr, site.URL)
	doHEAD := func() (*http.Response, time.Duration, error) {
		req, _ := http.NewRequestWithContext(ctx, "HEAD", site.URL, nil)
		req.Header.Set("X-Probe", probeVal)
		st := time.Now()
		r, e := client.Do(req)
		return r, time.Since(st), e
	}
	headResp, headTime, headErr := doHEAD()
	if headErr != nil && isTransientNetErr(headErr) {
		Warnf("[%s %s] HEAD transient error, retrying once: %v", site.Name, ipStr, headErr)
		time.Sleep(300 * time.Millisecond)
		sr.RetriedOnce = true
		sr.RetriedHead = true
		headResp, headTime, headErr = doHEAD()
	}
	sr.HeadTimeMs = headTime.Milliseconds()
	if headErr == nil && headResp != nil {
		headResp.Body.Close()
		sr.HeadStatus = headResp.StatusCode
	} else if headErr != nil {
		sr.HeadError = headErr.Error()
	}

	// GET with trace (with one-shot retry on transient errors like EOF/reset)
	var dnsStartT, dnsDoneT, connStartT, connDoneT, tlsStartT, tlsDoneT, gotConnT, gotFirstByteT time.Time
	Debugf("[%s %s] GET %s", site.Name, ipStr, site.URL)
	doGET := func() (*http.Response, error) {
		dnsStartT, dnsDoneT, connStartT, connDoneT, tlsStartT, tlsDoneT, gotConnT, gotFirstByteT = time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}
		req, _ := http.NewRequestWithContext(ctx, "GET", site.URL, nil)
		req.Header.Set("X-Probe", probeVal)
		trace := &httptrace.ClientTrace{DNSStart: func(info httptrace.DNSStartInfo) { dnsStartT = time.Now() }, DNSDone: func(info httptrace.DNSDoneInfo) { dnsDoneT = time.Now() }, ConnectStart: func(network, addr string) { connStartT = time.Now() }, ConnectDone: func(network, addr string, err error) { connDoneT = time.Now() }, TLSHandshakeStart: func() { tlsStartT = time.Now() }, TLSHandshakeDone: func(cs tls.ConnectionState, err error) { tlsDoneT = time.Now() }, GotConn: func(info httptrace.GotConnInfo) { gotConnT = time.Now() }, GotFirstResponseByte: func() { gotFirstByteT = time.Now() }}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		start = time.Now()
		r, e := client.Do(req)
		httpConnectTime := time.Since(start)
		sr.HTTPConnectTimeMs = httpConnectTime.Milliseconds()
		if !dnsStartT.IsZero() && !dnsDoneT.IsZero() {
			sr.TraceDNSMs = dnsDoneT.Sub(dnsStartT).Milliseconds()
		}
		if !connStartT.IsZero() && !connDoneT.IsZero() {
			sr.TraceConnectMs = connDoneT.Sub(connStartT).Milliseconds()
		}
		if !tlsStartT.IsZero() && !tlsDoneT.IsZero() {
			sr.TraceTLSMs = tlsDoneT.Sub(tlsStartT).Milliseconds()
		}
		if !gotConnT.IsZero() {
			sr.TraceTimeToConnMs = gotConnT.Sub(start).Milliseconds()
		}
		if !gotFirstByteT.IsZero() {
			sr.TraceTTFBMs = gotFirstByteT.Sub(start).Milliseconds()
		}
		return r, e
	}
	resp, gerr := doGET()
	if gerr != nil {
		// One-shot retry on transient errors (EOF/reset)
		if isTransientNetErr(gerr) {
			Warnf("[%s %s] GET transient error, retrying once: %v", site.Name, ipStr, gerr)
			time.Sleep(300 * time.Millisecond)
			sr.RetriedOnce = true
			sr.RetriedGet = true
			if r2, e2 := doGET(); e2 == nil {
				resp = r2
				gerr = nil
			} else {
				gerr = e2
			}
		}
	}
	if gerr != nil {
		sr.HTTPError = gerr.Error()
		if errors.Is(gerr, context.DeadlineExceeded) || strings.Contains(strings.ToLower(gerr.Error()), "context deadline exceeded") {
			Warnf("[%s %s] GET timeout (context deadline exceeded)", site.Name, ipStr)
		} else {
			Warnf("[%s %s] GET failed: %v", site.Name, ipStr, gerr)
		}
		writeResult(wrapRoot(sr))
		return
	}

	clHeader := resp.Header.Get("Content-Length")
	// Populate protocol/TLS/encoding telemetry early
	sr.HTTPProtocol = resp.Proto
	if resp.TLS != nil {
		// TLSVersion numeric to string
		switch resp.TLS.Version {
		case tls.VersionTLS13:
			sr.TLSVersion = "TLS1.3"
		case tls.VersionTLS12:
			sr.TLSVersion = "TLS1.2"
		case tls.VersionTLS11:
			sr.TLSVersion = "TLS1.1"
		case tls.VersionTLS10:
			sr.TLSVersion = "TLS1.0"
		default:
			sr.TLSVersion = fmt.Sprintf("0x%x", resp.TLS.Version)
		}
		sr.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)
		if len(resp.TLS.NegotiatedProtocol) > 0 {
			sr.ALPN = resp.TLS.NegotiatedProtocol
		}
	}
	if len(resp.TransferEncoding) > 0 {
		sr.TransferEncoding = strings.Join(resp.TransferEncoding, ",")
		for _, te := range resp.TransferEncoding {
			if strings.EqualFold(te, "chunked") {
				sr.Chunked = true
				break
			}
		}
	}
	// content length header handled later into sr.ContentLengthHeader
	via := resp.Header.Get("Via")
	xcache := resp.Header.Get("X-Cache")
	ageHeader := resp.Header.Get("Age")
	serverHeader := resp.Header.Get("Server")
	sr.HeaderVia = via
	sr.HeaderXCache = xcache
	if ageHeader != "" {
		sr.HeaderAge = ageHeader
	}
	if serverHeader != "" {
		sr.HeaderServer = serverHeader
	}
	cachePresent := false
	if ageHeader != "" {
		if ageVal, e := strconv.Atoi(ageHeader); e == nil && ageVal > 0 {
			cachePresent = true
		}
	}
	if xcache != "" && containsCI(xcache, "HIT") {
		cachePresent = true
	}
	sr.CachePresent = cachePresent
	sr.RemoteIP = remoteIP
	ipMismatch := true
	for _, dip := range dnsIPs {
		if dip == remoteIP {
			ipMismatch = false
			break
		}
	}
	sr.IPMismatch = ipMismatch
	// derive connect duration from recorded metric
	connectDur := time.Duration(sr.HTTPConnectTimeMs) * time.Millisecond
	prefetchSuspect := headErr == nil && headTime > 0 && connectDur > 0 && connectDur < (headTime/2)
	sr.PrefetchSuspected = prefetchSuspect
	proxySuspected := ipMismatch || via != "" || xcache != ""
	// Basic heuristic mapping to identify common CDN/proxy names and enterprise proxies (Zscaler, Bluecoat etc.)
	var proxyName, proxySource string
	var proxyIndicators []string
	if via != "" {
		proxySource = "via"
		lower := strings.ToLower(via)
		switch {
		case strings.Contains(lower, "cloudfront"):
			proxyName = "cloudfront"
		case strings.Contains(lower, "fastly"):
			proxyName = "fastly"
		case strings.Contains(lower, "akamai"):
			proxyName = "akamai"
		case strings.Contains(lower, "cachefly"):
			proxyName = "cachefly"
		case strings.Contains(lower, "azureedge"):
			proxyName = "azurecdn"
		case strings.Contains(lower, "cloudflare"):
			proxyName = "cloudflare"
		case strings.Contains(lower, "google") && strings.Contains(lower, "cache"):
			proxyName = "google"
		case strings.Contains(lower, "zscaler"):
			proxyName = "zscaler"
		case strings.Contains(lower, "bluecoat") || strings.Contains(lower, "symantec"):
			proxyName = "bluecoat"
		case strings.Contains(lower, "netskope"):
			proxyName = "netskope"
		case strings.Contains(lower, "palosecure") || strings.Contains(lower, "palo"):
			proxyName = "paloalto"
		case strings.Contains(lower, "forcepoint"):
			proxyName = "forcepoint"
		}
		proxyIndicators = append(proxyIndicators, "via:"+via)
	}
	if proxyName == "" && xcache != "" {
		ls := strings.ToLower(xcache)
		proxySource = "x-cache"
		switch {
		case strings.Contains(ls, "cloudfront"):
			proxyName = "cloudfront"
		case strings.Contains(ls, "fastly"):
			proxyName = "fastly"
		case strings.Contains(ls, "akam"):
			proxyName = "akamai"
		case strings.Contains(ls, "cloudflare"):
			proxyName = "cloudflare"
		case strings.Contains(ls, "cachefly"):
			proxyName = "cachefly"
		case strings.Contains(ls, "zscaler"):
			proxyName = "zscaler"
		}
		proxyIndicators = append(proxyIndicators, "x-cache:"+xcache)
	}
	if proxyName == "" && serverHeader != "" { // fallback to Server header hints
		lower := strings.ToLower(serverHeader)
		proxySource = "server"
		switch {
		case strings.Contains(lower, "cloudflare"):
			proxyName = "cloudflare"
		case strings.Contains(lower, "cloudfront"):
			proxyName = "cloudfront"
		case strings.Contains(lower, "fastly"):
			proxyName = "fastly"
		case strings.Contains(lower, "akamai"):
			proxyName = "akamai"
		case strings.Contains(lower, "varnish"):
			proxyName = "varnish"
		case strings.Contains(lower, "squid"):
			proxyName = "squid"
		case strings.Contains(lower, "nginx"):
			proxyName = "nginx" // generic
		case strings.Contains(lower, "apache"):
			proxyName = "apache" // generic
		case strings.Contains(lower, "zscaler"):
			proxyName = "zscaler"
		case strings.Contains(lower, "bluecoat") || strings.Contains(lower, "symantec"):
			proxyName = "bluecoat"
		case strings.Contains(lower, "netskope"):
			proxyName = "netskope"
		case strings.Contains(lower, "palosecure") || strings.Contains(lower, "palo"):
			proxyName = "paloalto"
		case strings.Contains(lower, "forcepoint"):
			proxyName = "forcepoint"
		}
		proxyIndicators = append(proxyIndicators, "server:"+serverHeader)
	}
	// Additional specialized headers frequently used by enterprise / security proxies
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-zscaler-") || lk == "x-zscaler-bypass" {
			if proxyName == "" {
				proxyName = "zscaler"
				proxySource = k
			}
			proxyIndicators = append(proxyIndicators, k+":"+strings.Join(vv, ","))
		}
		if lk == "x-bluecoat-via" || lk == "x-bluecoat-request-id" {
			if proxyName == "" {
				proxyName = "bluecoat"
				proxySource = k
			}
			proxyIndicators = append(proxyIndicators, k+":"+strings.Join(vv, ","))
		}
		if lk == "x-paloalto-metadata" || lk == "x-paloalto-app" {
			if proxyName == "" {
				proxyName = "paloalto"
				proxySource = k
			}
			proxyIndicators = append(proxyIndicators, k+":"+strings.Join(vv, ","))
		}
		if strings.HasPrefix(lk, "x-netskope-") {
			if proxyName == "" {
				proxyName = "netskope"
				proxySource = k
			}
			proxyIndicators = append(proxyIndicators, k+":"+strings.Join(vv, ","))
		}
		if strings.HasPrefix(lk, "x-forcepoint-") {
			if proxyName == "" {
				proxyName = "forcepoint"
				proxySource = k
			}
			proxyIndicators = append(proxyIndicators, k+":"+strings.Join(vv, ","))
		}
	}
	if proxyName != "" {
		proxySuspected = true
		sr.ProxyName = proxyName
		sr.ProxySource = proxySource
		if len(proxyIndicators) > 0 {
			sr.ProxyIndicators = proxyIndicators
		}
	}
	sr.ProxySuspected = proxySuspected
	sr.ProbeHeaderValue = probeVal
	probeEcho := resp.Header.Get("X-Probe")
	sr.ProbeEchoed = (probeEcho != "")
	if headTime > 0 && headTime.Milliseconds() > 0 && sr.HTTPConnectTimeMs > 0 {
		sr.HeadGetTimeRatio = float64(sr.HTTPConnectTimeMs) / float64(headTime.Milliseconds())
	}
	if remoteIP != "" {
		if asnNum, asnOrg, ok := lookupGeoIP2ASN(remoteIP); ok {
			sr.ASNNumber = asnNum
			sr.ASNOrg = asnOrg
		}
	}

	// Transfer loop
	transferStart := time.Now()
	var bytesRead int64
	var firstRTTBytes int64
	rawRTTms := sr.TCPTimeMs
	if rawRTTms <= 0 {
		rawRTTms = 1
	}
	rttDuration := time.Duration(rawRTTms) * time.Millisecond
	buf := make([]byte, 32*1024)
	var speedSamples []SpeedSample
	nextSample := transferStart.Add(SpeedSampleInterval)
	lastProgressLog := time.Now()
	lastProgress := time.Now()
	// If Content-Length header is present, pre-parse expected total bytes for richer progress logs
	var expectedBytes int64
	if clHeader != "" {
		if v, e := strconv.ParseInt(clHeader, 10, 64); e == nil && v > 0 {
			expectedBytes = v
		}
	}
	// Watchdog goroutine: logs if no additional bytes for half stallTimeout (but does not abort; abort handled inline)
	watchdogQuit := make(chan struct{})
	var lastBytesLogged int64
	if stallTimeout > 0 {
		go func(name, ip string, expected int64) {
			interval := stallTimeout / 2
			if interval < 5*time.Second {
				interval = 5 * time.Second
			}
			for {
				select {
				case <-watchdogQuit:
					return
				case <-time.After(interval):
					br := bytesRead
					if br == lastBytesLogged {
						if expected > 0 {
							pct := (float64(br) * 100.0) / float64(expected)
							Warnf("[%s %s] watchdog: no progress for %s (%d/%d bytes, %.1f%%)", name, ip, interval, br, expected, pct)
						} else {
							Warnf("[%s %s] watchdog: no progress for %s (%d/unknown bytes)", name, ip, interval, br)
						}
					} else if getLevel() == LevelDebug {
						if expected > 0 {
							pct := (float64(br) * 100.0) / float64(expected)
							Debugf("[%s %s] watchdog: progress %d(+%d) bytes (%.1f%%)", name, ip, br, br-lastBytesLogged, pct)
						} else {
							Debugf("[%s %s] watchdog: progress %d(+%d)/unknown bytes", name, ip, br, br-lastBytesLogged)
						}
					}
					lastBytesLogged = br
				}
			}
		}(site.Name, ipStr, expectedBytes)
	}
	for {
		n, er := resp.Body.Read(buf)
		bytesRead += int64(n)
		if n > 0 {
			lastProgress = time.Now()
		}
		progressInterval := 3 * time.Second
		if getLevel() == LevelInfo {
			progressInterval = 10 * time.Second
		}
		if time.Since(lastProgressLog) >= progressInterval {
			if getLevel() == LevelDebug {
				if expectedBytes > 0 {
					pct := (float64(bytesRead) * 100.0) / float64(expectedBytes)
					Debugf("[%s %s] transfer progress %d/%d bytes (%.1f%%)", site.Name, ipStr, bytesRead, expectedBytes, pct)
				} else {
					Debugf("[%s %s] transfer progress %d/unknown bytes", site.Name, ipStr, bytesRead)
				}
			} else if getLevel() == LevelInfo {
				if expectedBytes > 0 {
					pct := (float64(bytesRead) * 100.0) / float64(expectedBytes)
					Infof("[%s %s] progress %d/%d bytes (%.1f MB, %.1f%%)", site.Name, ipStr, bytesRead, expectedBytes, float64(bytesRead)/1024.0/1024.0, pct)
				} else {
					Infof("[%s %s] progress %d/unknown bytes (%.1f MB)", site.Name, ipStr, bytesRead, float64(bytesRead)/1024.0/1024.0)
				}
			}
			lastProgressLog = time.Now()
		}
		if time.Now().After(nextSample) {
			elapsed := time.Since(transferStart)
			elapsedMs := elapsed.Milliseconds()
			sp := 0.0
			if elapsedMs > 0 {
				sp = float64(bytesRead) / (float64(elapsedMs) / 1000) / 1024
			}
			speedSamples = append(speedSamples, SpeedSample{TimeMs: elapsedMs, Bytes: bytesRead, Speed: sp})
			nextSample = nextSample.Add(SpeedSampleInterval)
		}
		if firstRTTBytes == 0 && time.Since(transferStart) >= rttDuration {
			firstRTTBytes = bytesRead
		}
		if er != nil {
			break
		}
		// Stall detection
		if stallTimeout > 0 && time.Since(lastProgress) > stallTimeout {
			if expectedBytes > 0 {
				pct := (float64(bytesRead) * 100.0) / float64(expectedBytes)
				Warnf("[%s %s] transfer stalled for %s, aborting (%d/%d bytes, %.1f%%)", site.Name, ipStr, time.Since(lastProgress), bytesRead, expectedBytes, pct)
			} else {
				Warnf("[%s %s] transfer stalled for %s, aborting (%d/unknown bytes)", site.Name, ipStr, time.Since(lastProgress), bytesRead)
			}
			sr.TransferStalled = true
			sr.StallElapsedMs = time.Since(transferStart).Milliseconds()
			break
		}
	}
	close(watchdogQuit)
	resp.Body.Close()
	transferDuration := time.Since(transferStart)
	// Compute overall average transfer speed. Previously this used only whole milliseconds;
	// extremely fast (sub-millisecond) transfers would yield ms=0 -> speed 0. Use high-resolution seconds fallback.
	speed := 0.0
	ms := transferDuration.Milliseconds()
	if ms > 0 {
		speed = float64(bytesRead) / (float64(ms) / 1000) / 1024
	} else if bytesRead > 0 {
		secs := transferDuration.Seconds()
		if secs <= 0 {
			secs = 0.0005 // assume 0.5ms minimal duration to avoid huge inflated speeds
		}
		speed = float64(bytesRead) / secs / 1024
	}
	sr.TransferTimeMs = transferDuration.Milliseconds()
	sr.TransferSizeBytes = bytesRead
	sr.TransferSpeedKbps = speed
	sr.TransferSpeedSamples = speedSamples
	if rawRTTms > 0 {
		firstGoodput := float64(firstRTTBytes) / (float64(rawRTTms) / 1000) / 1024
		sr.FirstRTTBytes = firstRTTBytes
		sr.FirstRTTGoodputKbps = firstGoodput
	}
	if clHeader != "" {
		if clVal, e := strconv.ParseInt(clHeader, 10, 64); e == nil {
			sr.ContentLengthHeader = clVal
			sr.ContentLengthMismatch = (clVal != bytesRead)
		}
	}

	// Secondary Range GET (with one-shot transient retry)
	doSecondGET := func() (*http.Response, time.Duration, error) {
		st := time.Now()
		req, _ := http.NewRequestWithContext(ctx, "GET", site.URL, nil)
		req.Header.Set("X-Probe", probeVal)
		req.Header.Set("Range", "bytes=0-65535")
		r, e := client.Do(req)
		return r, time.Since(st), e
	}
	secondResp, secondGetTime, secondErr := doSecondGET()
	if secondErr != nil && isTransientNetErr(secondErr) {
		Warnf("[%s %s] Range GET transient error, retrying once: %v", site.Name, ipStr, secondErr)
		time.Sleep(300 * time.Millisecond)
		sr.RetriedOnce = true
		sr.RetriedRange = true
		secondResp, secondGetTime, secondErr = doSecondGET()
	}
	if secondErr == nil && secondResp != nil {
		sr.SecondGetStatus = secondResp.StatusCode
		sr.SecondGetTimeMs = secondGetTime.Milliseconds()
		sr.SecondGetHeaderAge = secondResp.Header.Get("Age")
		sr.SecondGetXCache = secondResp.Header.Get("X-Cache")
		if rng := secondResp.Header.Get("Content-Range"); rng != "" {
			sr.SecondGetContentRange = rng
		}
		// Read Range body with lightweight progress logs
		var expectedRange int64
		if cr := sr.SecondGetContentRange; cr != "" {
			// Parse format: "bytes start-end/total"
			parts := strings.Fields(cr)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bytes" {
				rng := parts[1]
				// split start-end/total
				se := strings.SplitN(rng, "/", 2)
				if len(se) >= 1 {
					re := strings.SplitN(se[0], "-", 2)
					if len(re) == 2 {
						if start, e1 := strconv.ParseInt(re[0], 10, 64); e1 == nil {
							if end, e2 := strconv.ParseInt(re[1], 10, 64); e2 == nil && end >= start {
								expectedRange = (end - start + 1)
							}
						}
					}
				}
			}
		}
		if expectedRange == 0 {
			if cl := secondResp.Header.Get("Content-Length"); cl != "" {
				if v, e := strconv.ParseInt(cl, 10, 64); e == nil && v > 0 {
					expectedRange = v
				}
			}
		}
		buf2 := make([]byte, 32*1024)
		var rangeBytes int64
		lastRangeProgressLog := time.Now()
		for {
			n, er := secondResp.Body.Read(buf2)
			rangeBytes += int64(n)
			progressInterval := 3 * time.Second
			if getLevel() == LevelInfo {
				progressInterval = 10 * time.Second
			}
			if time.Since(lastRangeProgressLog) >= progressInterval {
				if getLevel() == LevelDebug {
					if expectedRange > 0 {
						pct := (float64(rangeBytes) * 100.0) / float64(expectedRange)
						Debugf("[%s %s] range progress %d/%d bytes (%.1f%%)", site.Name, ipStr, rangeBytes, expectedRange, pct)
					} else {
						Debugf("[%s %s] range progress %d/unknown bytes", site.Name, ipStr, rangeBytes)
					}
				} else if getLevel() == LevelInfo {
					if expectedRange > 0 {
						pct := (float64(rangeBytes) * 100.0) / float64(expectedRange)
						Infof("[%s %s] range progress %d/%d bytes (%.1f%%)", site.Name, ipStr, rangeBytes, expectedRange, pct)
					} else {
						Infof("[%s %s] range progress %d/unknown bytes", site.Name, ipStr, rangeBytes)
					}
				}
				lastRangeProgressLog = time.Now()
			}
			if er != nil {
				break
			}
		}
		secondResp.Body.Close()
	} else if secondErr != nil {
		sr.SecondGetError = secondErr.Error()
	}
	secondCachePresent := false
	if s := sr.SecondGetHeaderAge; s != "" {
		if v, e := strconv.Atoi(s); e == nil && v > 0 {
			secondCachePresent = true
		}
	}
	if xc := sr.SecondGetXCache; xc != "" && containsCI(xc, "HIT") {
		secondCachePresent = true
	}
	sr.SecondGetCachePresent = secondCachePresent

	// Warm HEAD
	warmHeadStart := time.Now()
	warmHeadReq, _ := http.NewRequestWithContext(ctx, "HEAD", site.URL, nil)
	warmHeadReq.Header.Set("X-Probe", probeVal)
	warmHeadResp, warmHeadErr := client.Do(warmHeadReq)
	warmHeadTime := time.Since(warmHeadStart)
	if warmHeadErr == nil && warmHeadResp != nil {
		warmHeadResp.Body.Close()
	}
	sr.WarmHeadTimeMs = warmHeadTime.Milliseconds()
	warmHeadSpeedup := headTime > 0 && warmHeadTime < headTime/2
	sr.WarmHeadSpeedup = warmHeadSpeedup
	sr.WarmCacheSuspected = (warmHeadSpeedup && cachePresent)
	sr.DialCount = dialCount
	sr.ConnectionReusedSecond = (dialCount == 1)

	// Speed / stats analysis (reusing existing logic)
	var avgSpeed, stddevSpeed float64
	var speeds []float64
	for _, s := range speedSamples {
		speeds = append(speeds, s.Speed)
		avgSpeed += s.Speed
	}
	n := float64(len(speeds))
	var p50, p90, p95, p99, minSpeed, maxSpeed, slope, jitterMeanAbsPct float64
	if n > 0 {
		avgSpeed /= n
		for i, v := range speeds {
			stddevSpeed += (v - avgSpeed) * (v - avgSpeed)
			if v < minSpeed || minSpeed == 0 {
				minSpeed = v
			}
			if v > maxSpeed {
				maxSpeed = v
			}
			if i > 0 {
				prev := speeds[i-1]
				if prev > 0 {
					jitterMeanAbsPct += math.Abs(v-prev) / prev
				}
			}
		}
		stddevSpeed = math.Sqrt(stddevSpeed / n)
		if n > 1 {
			jitterMeanAbsPct /= (n - 1)
			var sumX, sumY, sumXY, sumX2 float64
			for _, sample := range speedSamples {
				x := float64(sample.TimeMs) / 1000
				y := sample.Speed
				sumX += x
				sumY += y
				sumXY += x * y
				sumX2 += x * x
			}
			den := float64(n)*sumX2 - sumX*sumX
			if den != 0 {
				slope = (float64(n)*sumXY - sumX*sumY) / den
			}
		}
		sort.Float64s(speeds)
		idxFunc := func(p float64) int {
			i := int(p*(n-1) + 0.5)
			if i < 0 {
				i = 0
			}
			if i >= int(n) {
				i = int(n) - 1
			}
			return i
		}
		p50 = speeds[idxFunc(0.50)]
		p90 = speeds[idxFunc(0.90)]
		p95 = speeds[idxFunc(0.95)]
		p99 = speeds[idxFunc(0.99)]
	}
	patterns := []string{}
	if n > 2 {
		first, last := speeds[0], speeds[len(speeds)-1]
		maxV := first
		minV := first
		for _, v := range speeds {
			if v > maxV {
				maxV = v
			}
			if v < minV {
				minV = v
			}
		}
		if maxV > 0 && first < 0.5*maxV {
			patterns = append(patterns, "slow start until max speed")
		}
		if maxV > 0 && last < 0.5*maxV {
			patterns = append(patterns, "good speed at begin but slow in the end")
		}
		if avgSpeed > 0 && stddevSpeed > 0.5*avgSpeed {
			patterns = append(patterns, "highly volatile speed measurement over whole window")
		}
		if avgSpeed > 0 && stddevSpeed < 0.1*avgSpeed {
			patterns = append(patterns, "stable speed throughout transfer")
		}
		if maxV > 0 && first > 0.8*maxV {
			patterns = append(patterns, "fast start, reaches max speed quickly")
		}
		if maxV > 0 && last > 0.8*maxV {
			patterns = append(patterns, "fast end, maintains speed until finish")
		}
		if n > 5 {
			mid := speeds[int(n/2)]
			if mid < 0.5*maxV && first > 0.7*maxV && last > 0.7*maxV {
				patterns = append(patterns, "mid-transfer dip: speed drops in the middle")
			}
			if first < 0.5*maxV && mid > 0.8*maxV {
				patterns = append(patterns, "slow start, then speed recovers mid-transfer")
			}
			decline := true
			for i := 1; i < len(speeds); i++ {
				if speeds[i] > speeds[i-1] {
					decline = false
					break
				}
			}
			if decline && first > last {
				patterns = append(patterns, "gradual decline: speed decreases throughout transfer")
			}
			increase := true
			for i := 1; i < len(speeds); i++ {
				if speeds[i] < speeds[i-1] {
					increase = false
					break
				}
			}
			if increase && last > first {
				patterns = append(patterns, "gradual increase: speed increases throughout transfer")
			}
		}
	}
	cov := 0.0
	if avgSpeed > 0 {
		cov = stddevSpeed / avgSpeed
	}
	// Collect plateau segments directly in a strongly typed slice (avoid map[string]interface{} usage)
	plateauSegments := []PlateauSegment{}
	plateauCount := 0
	longestPlateauMs := int64(0)
	plateauStable := false
	if n > 2 && p50 > 0 && cov > 0 {
		threshold := 0.10 * p50
		currentStart := -1
		sumSpeed := 0.0
		for i, smp := range speedSamples {
			v := smp.Speed
			if math.Abs(v-p50) <= threshold {
				if currentStart == -1 {
					currentStart = i
					sumSpeed = 0
				}
				sumSpeed += v
			} else if currentStart != -1 {
				length := i - currentStart
				if length >= 3 {
					startMs := speedSamples[currentStart].TimeMs
					endMs := speedSamples[i-1].TimeMs
					dur := endMs - startMs
					avgPlateau := sumSpeed / float64(length)
					plateauSegments = append(plateauSegments, PlateauSegment{StartMs: startMs, EndMs: endMs, DurationMs: dur, AvgKbps: avgPlateau})
					plateauCount++
					if dur > longestPlateauMs {
						longestPlateauMs = dur
					}
				}
				currentStart = -1
			}
		}
		if currentStart != -1 {
			length := len(speedSamples) - currentStart
			if length >= 3 {
				startMs := speedSamples[currentStart].TimeMs
				endMs := speedSamples[len(speedSamples)-1].TimeMs
				dur := endMs - startMs
				avgPlateau := sumSpeed / float64(length)
				plateauSegments = append(plateauSegments, PlateauSegment{StartMs: startMs, EndMs: endMs, DurationMs: dur, AvgKbps: avgPlateau})
				plateauCount++
				if dur > longestPlateauMs {
					longestPlateauMs = dur
				}
			}
		}
		if plateauCount > 0 && cov < 0.15 {
			plateauStable = true
		}
	}
	analysis := &SpeedAnalysis{AverageKbps: avgSpeed, StddevKbps: stddevSpeed, CoefVariation: cov, MinKbps: minSpeed, MaxKbps: maxSpeed, P50Kbps: p50, P90Kbps: p90, P95Kbps: p95, P99Kbps: p99, SlopeKbpsPerSec: slope, JitterMeanAbsPct: jitterMeanAbsPct, Patterns: patterns, PlateauCount: plateauCount, LongestPlateauMs: longestPlateauMs, PlateauStable: plateauStable, PlateauSegments: plateauSegments}
	if n > 0 {
		insights := []string{}
		if p50 > 0 && p99 > 0 {
			ratio := p99 / p50
			stab := "high variability"
			if ratio < 1.2 {
				stab = "very stable throughput"
			} else if ratio < 1.8 {
				stab = "moderate variability"
			}
			insights = append(insights, fmt.Sprintf("Stability: p99/p50=%.2f -> %s", ratio, stab))
		}
		if p50 > 0 && p90 >= p50 {
			gap := (p90 - p50) / p50 * 100
			insights = append(insights, fmt.Sprintf("Headroom: p90 is %.1f%% above median", gap))
		}
		if p95 > 0 && p99 >= p95 {
			spike := p99 / p95
			if spike > 1.2 {
				insights = append(insights, fmt.Sprintf("Rare high spikes: p99 %.2fx p95", spike))
			} else {
				insights = append(insights, "Tail spikes minimal (p99 close to p95)")
			}
		}
		if slope != 0 {
			if math.Abs(slope) < 0.05*avgSpeed {
				insights = append(insights, fmt.Sprintf("Slope ~%.1f kbps/s: plateau early", slope))
			} else if slope > 0 {
				insights = append(insights, fmt.Sprintf("Positive ramp: +%.1f kbps/s (throughput building)", slope))
			} else {
				insights = append(insights, fmt.Sprintf("Negative ramp: %.1f kbps/s (declining throughput)", slope))
			}
		}
		if jitterMeanAbsPct > 0 {
			jp := jitterMeanAbsPct * 100
			jq := "high jitter"
			if jp < 5 {
				jq = "very low jitter"
			} else if jp < 15 {
				jq = "moderate jitter"
			}
			insights = append(insights, fmt.Sprintf("Jitter: mean abs change %.1f%% -> %s", jp, jq))
		}
		if cov > 0 {
			insights = append(insights, fmt.Sprintf("Variation: CoV %.1f%%", cov*100))
		}
		if len(patterns) > 0 {
			insights = append(insights, "Patterns: "+joinFirst(patterns, 5))
		}
		if plateauCount > 0 {
			suffix := ""
			if plateauStable {
				suffix = ", stable"
			}
			insights = append(insights, fmt.Sprintf("Plateaus: %d (longest %d ms)%s", plateauCount, longestPlateauMs, suffix))
		}
		if len(insights) > 0 {
			analysis.Insights = insights
		}
	}
	sr.SpeedAnalysis = analysis

	writeResult(wrapRoot(sr))
	headStatus := sr.HeadStatus
	secStatus := sr.SecondGetStatus
	transferBytes := sr.TransferSizeBytes
	transferTime := sr.TransferTimeMs
	transferSpeed := sr.TransferSpeedKbps
	dnsMs := dnsTime.Milliseconds()
	tcpMs := sr.TCPTimeMs
	sslMs := sr.SSLHandshakeTimeMs
	ttfbMs := sr.TraceTTFBMs
	// Include negotiated HTTP protocol, ALPN, and TLS version for debugging missing protocol cases
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
	Infof("[%s %s] done head=%d sec_get=%d bytes=%d time=%dms speed=%.1fkbps dns=%dms tcp=%dms tls=%dms ttfb=%dms proto=%s alpn=%s tls_ver=%s", site.Name, ipStr, headStatus, secStatus, transferBytes, transferTime, transferSpeed, dnsMs, tcpMs, sslMs, ttfbMs, proto, alpn, tlsv)
}

// ---- Root meta & system info helpers (portable) ----
var baseMetaOnce sync.Once
var cachedBaseMeta *Meta
var processStart = time.Now()

// wrapRoot can accept either a typed *SiteResult plus supplemental map fields, or a legacy map.
func wrapRoot(sr *SiteResult) *ResultEnvelope {
	meta := gatherBaseMeta()
	if runTag != "" {
		meta.RunTag = runTag
	}
	if meta.ConnectionType == "" {
		meta.ConnectionType = detectConnectionType()
	}
	meta.HomeOfficeEstimate = classifyClientEnvironment(meta)
	return &ResultEnvelope{Meta: meta, SiteResult: sr}
}

// SetRunTag sets the batch/run tag added into meta for each result line.
func SetRunTag(tag string) { runTag = tag }

// SetSituation sets the situation label (e.g., Home, Office, VPN) embedded in meta for each result.
func SetSituation(s string) { currentSituation = s }
func gatherBaseMeta() *Meta {
	baseMetaOnce.Do(func() {
		m := &Meta{}
		if h, err := os.Hostname(); err == nil {
			m.Hostname = h
		}
		m.OS = runtime.GOOS
		m.Arch = runtime.GOARCH
		m.NumCPU = runtime.NumCPU()
		m.GOMAXPROCS = runtime.GOMAXPROCS(0)
		if u := os.Getenv("USER"); u != "" {
			m.User = u
		}
		if la1, la5, la15, err := readLoadAvg(); err == nil {
			m.LoadAvg1, m.LoadAvg5, m.LoadAvg15 = la1, la5, la15
		}
		if up, err := readUptime(); err == nil {
			m.UptimeSeconds = up
		}
		if kv, err := readKernelVersion(); err == nil {
			m.KernelVersion = kv
		}
		if ip := getLocalOutboundIP(); ip != "" {
			m.LocalIP = ip
		}
		pubs := getPublicIPs(2 * time.Second)
		if len(pubs) > 0 {
			var v4s, v6s []string
			for _, ipStr := range pubs {
				if parsed := net.ParseIP(ipStr); parsed != nil {
					if parsed.To4() != nil {
						v4s = append(v4s, ipStr)
					} else {
						v6s = append(v6s, ipStr)
					}
				}
			}
			if len(v4s) > 0 {
				m.PublicIPv4Candidates = v4s
				m.PublicIPv4Consensus = consensusIP(v4s)
			}
			if len(v6s) > 0 {
				m.PublicIPv6Candidates = v6s
				m.PublicIPv6Consensus = consensusIP(v6s)
			}
			if asnDB, err := geoip2.Open("/usr/share/GeoIP/GeoLite2-ASN.mmdb"); err == nil {
				if v := m.PublicIPv4Consensus; v != "" {
					if rec, err := asnDB.ASN(net.ParseIP(v)); err == nil && rec != nil {
						m.PublicIPv4ASNNumber = rec.AutonomousSystemNumber
						m.PublicIPv4ASNOrg = rec.AutonomousSystemOrganization
					}
				}
				if v := m.PublicIPv6Consensus; v != "" {
					if rec, err := asnDB.ASN(net.ParseIP(v)); err == nil && rec != nil {
						m.PublicIPv6ASNNumber = rec.AutonomousSystemNumber
						m.PublicIPv6ASNOrg = rec.AutonomousSystemOrganization
					}
				}
				asnDB.Close()
			}
		}
		if iface, err := getDefaultInterface(); err == nil {
			m.DefaultIface = iface
		}
		m.ConnectionType = detectConnectionType()
		m.Containerized = detectContainer()
		m.SchemaVersion = SchemaVersion
		m.Situation = currentSituation
		cachedBaseMeta = m
	})
	// Shallow copy with updated timestamp
	cp := *cachedBaseMeta
	cp.TimestampUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return &cp
}
func readLoadAvg() (float64, float64, float64, error) {
	if runtime.GOOS != "linux" {
		return 0, 0, 0, fmt.Errorf("loadavg unsupported")
	}
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	parts := strings.Fields(string(b))
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected")
	}
	var vals [3]float64
	for i := 0; i < 3; i++ {
		f, e := strconv.ParseFloat(parts[i], 64)
		if e != nil {
			return 0, 0, 0, e
		}
		vals[i] = f
	}
	return vals[0], vals[1], vals[2], nil
}
func readUptime() (float64, error) {
	if runtime.GOOS != "linux" {
		return time.Since(processStart).Seconds(), nil
	}
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return 0, fmt.Errorf("bad format")
	}
	f, err := strconv.ParseFloat(parts[0], 64)
	return f, err
}
func readKernelVersion() (string, error) {
	if runtime.GOOS != "linux" {
		return runtime.GOOS + "-unknown", nil
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
func getLocalOutboundIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if ta, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ta.IP.String()
	}
	return conn.LocalAddr().String()
}
func getPublicIPs(timeout time.Duration) []string {
	endpoints := []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://ipinfo.io/ip"}
	client := &http.Client{Timeout: timeout}
	ips := []string{}
	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		if ip != "" && !contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	return ips
}
func contains(slice []string, v string) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}
func consensusIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	counts := map[string]int{}
	best := ips[0]
	bestC := 0
	for _, ip := range ips {
		counts[ip]++
	}
	for ip, c := range counts {
		if c > bestC {
			best = ip
			bestC = c
		}
	}
	return best
}
func getDefaultInterface() (string, error) {
	ipStr := getLocalOutboundIP()
	if ipStr == "" {
		return "", fmt.Errorf("no outbound ip")
	}
	localIP := net.ParseIP(ipStr)
	if localIP == nil {
		return "", fmt.Errorf("parse ip")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localIP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("interface not found")
}
func detectConnectionType() string {
	iface, err := getDefaultInterface()
	if err != nil || iface == "" {
		return "unknown"
	}
	name := strings.ToLower(iface)
	for _, h := range []string{"wl", "wlan", "wifi", "air", "ath"} {
		if strings.HasPrefix(name, h) {
			return "wifi"
		}
	}
	if runtime.GOOS == "darwin" && name == "en0" {
		return "wifi/unknown"
	}
	return "ethernet"
}
func detectContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			s := string(b)
			if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd") {
				return true
			}
		}
	}
	return false
}
func classifyHomeOffice(asnOrg string) string {
	lower := strings.ToLower(asnOrg)
	for _, h := range []string{"comcast", "telecom", "cable", "verizon", "vodafone", "t-mobile", "orange", "at&t", "charter"} {
		if strings.Contains(lower, h) {
			return "home"
		}
	}
	for _, h := range []string{"cloud", "corp", "enterprise", "datacenter", "hosting", "colo"} {
		if strings.Contains(lower, h) {
			return "office"
		}
	}
	return "unknown"
}

// classifyClientEnvironment infers environment (home/office/unknown) from client ASN org
// and connection characteristics. Prefers public IPv4 ASN org, then IPv6.
func classifyClientEnvironment(meta *Meta) string {
	if meta.PublicIPv4ASNOrg != "" {
		return classifyHomeOffice(meta.PublicIPv4ASNOrg)
	}
	if meta.PublicIPv6ASNOrg != "" {
		return classifyHomeOffice(meta.PublicIPv6ASNOrg)
	}
	if strings.HasPrefix(meta.ConnectionType, "wifi") {
		return "home"
	}
	return "unknown"
}
func writeResult(env *ResultEnvelope) {
	if resultChan != nil {
		resultChan <- env
		return
	}
	path := resultPath
	if path == "" { // fallback only if async writer not initialized & no path set
		path = DefaultResultsFile
	}
	fallbackWriteOnce.Do(func() { fmt.Printf("[writer fallback] results file (append): %s\n", path) })
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("write result:", err)
		return
	}
	defer f.Close()
	b, _ := json.Marshal(env)
	f.WriteString(string(b) + "\n")
}

func containsCI(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	h := []rune(haystack)
	n := []rune(needle)
	for i := 0; i <= len(h)-len(n); i++ {
		match := true
		for j := 0; j < len(n); j++ {
			r1 := h[i+j]
			r2 := n[j]
			if r1 >= 'A' && r1 <= 'Z' {
				r1 = r1 - 'A' + 'a'
			}
			if r2 >= 'A' && r2 <= 'Z' {
				r2 = r2 - 'A' + 'a'
			}
			if r1 != r2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
func joinFirst(items []string, max int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) > max {
		items = items[:max]
	}
	out := ""
	for i, v := range items {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
