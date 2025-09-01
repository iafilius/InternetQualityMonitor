package analysis

import "testing"

func TestNormalizeErrorReasonDetailed_HTTPBuckets(t *testing.T) {
    cases := []struct {
        name       string
        err        string
        headStatus int
        typed      string
        want       string
    }{
        {"http 404 explicit", "server responded with status 404 Not Found", 404, "http", "http_404"},
        {"http 503 explicit", "status code: 503", 503, "http", "http_503"},
        {"http 4xx other", "status code: 410 Gone", 410, "http", "http_410"},
        {"http 4xx generic bucket", "client error", 418, "http", "http_418"},
    }
    for _, tt := range cases {
        t.Run(tt.name, func(t *testing.T) {
            got := normalizeErrorReasonDetailed(tt.err, tt.headStatus, tt.typed)
            if got != tt.want {
                t.Fatalf("got %q want %q", got, tt.want)
            }
        })
    }
}

func TestNormalizeErrorReasonDetailed_TLS(t *testing.T) {
    cases := []struct{ err, want string }{
        {"x509: certificate has expired or is not yet valid", "tls_cert_expired"},
        {"x509: certificate signed by unknown authority", "tls_cert_untrusted"},
        {"x509: certificate is not valid for any names, but wanted example.com", "tls_cert_hostname"},
        {"tls: alert handshake failure", "tls_alert_handshake_failure"},
    }
    for _, tt := range cases {
        if got := normalizeErrorReasonDetailed(tt.err, 0, "tls"); got != tt.want {
            t.Fatalf("got %q want %q for %q", got, tt.want, tt.err)
        }
    }
}

func TestNormalizeErrorReasonDetailed_Timeouts(t *testing.T) {
    if got := normalizeErrorReasonDetailed("i/o timeout", 0, "tcp"); got != "timeout_connect" {
        t.Fatalf("tcp timeout mapped to %q", got)
    }
    if got := normalizeErrorReasonDetailed("context deadline exceeded while awaiting headers", 0, "http"); got != "timeout_ttfb" {
        t.Fatalf("http ttfb timeout mapped to %q", got)
    }
    if got := normalizeErrorReasonDetailed("read timeout", 0, "http"); got != "timeout_read" {
        t.Fatalf("http read timeout mapped to %q", got)
    }
}
