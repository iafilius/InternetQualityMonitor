package analysis

import "testing"

func TestNormalizeErrorReason_Generic(t *testing.T) {
    cases := map[string]string{
        "context deadline exceeded":                 "timeout",
        "i/o timeout":                                "timeout",
        "connection refused":                         "conn_refused",
        "ECONNREFUSED":                               "conn_refused",
        "connection reset by peer":                   "conn_reset",
        "RST_STREAM":                                 "conn_reset",
        "no such host":                               "dns_failure",
        "server misbehaving":                         "dns_failure",
        "x509: certificate signed by unknown authority": "tls_cert",
        "TLS handshake error":                        "tls_handshake",
        "proxyconnect tcp: EOF":                      "proxy",
        "stall_pre_ttfb":                             "stall_pre_ttfb",
        "stall_abort":                                "stall_abort",
        "partial_body: expected=100 read=50":         "partial_body",
        "network is unreachable":                     "unreachable",
    }
    for in, want := range cases {
        if got := normalizeErrorReason(in); got != want {
            t.Fatalf("normalizeErrorReason(%q)=%q, want %q", in, got, want)
        }
    }
}

func TestNormalizeHTTPReason_StatusBuckets(t *testing.T) {
    // HEAD surfaced 500 should map to http_5xx irrespective of message
    if got := normalizeHTTPReason("some server error", 503); got != "http_5xx" {
        t.Fatalf("normalizeHTTPReason(…,503)=%q, want http_5xx", got)
    }
    if got := normalizeHTTPReason("not found", 404); got != "http_4xx" {
        t.Fatalf("normalizeHTTPReason(…,404)=%q, want http_4xx", got)
    }
    // Preserve special markers first
    if got := normalizeHTTPReason("stall_pre_ttfb", 200); got != "stall_pre_ttfb" {
        t.Fatalf("normalizeHTTPReason(stall_pre_ttfb,200)=%q, want stall_pre_ttfb", got)
    }
    if got := normalizeHTTPReason("stall_abort", 200); got != "stall_abort" {
        t.Fatalf("normalizeHTTPReason(stall_abort,200)=%q, want stall_abort", got)
    }
    if got := normalizeHTTPReason("partial_body: expected=123 read=0", 200); got != "partial_body" {
        t.Fatalf("normalizeHTTPReason(partial_body,200)=%q, want partial_body", got)
    }
    // Fallback to generic normalization when no bucket applies
    if got := normalizeHTTPReason("i/o timeout", 200); got != "timeout" {
        t.Fatalf("normalizeHTTPReason(timeout,200)=%q, want timeout", got)
    }
}
