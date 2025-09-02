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
		{"tls: no application protocol", "tls_alert_no_application_protocol"},
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

func TestNormalizeErrorReasonDetailed_DNSAndProxyAndCF(t *testing.T) {
	cases := []struct {
		err, typed string
		head       int
		want       string
	}{
		{"lookup example.com: Name or service not known", "tcp", 0, "dns_no_such_host"},
		{"lookup example.com: no address associated with hostname", "tcp", 0, "dns_no_such_host"},
		{"lookup example.com: host not found", "tcp", 0, "dns_no_such_host"},
		{"lookup example.com: Temporary failure in name resolution", "tcp", 0, "dns_temp_failure"},
		{"lookup example.com: Try again", "tcp", 0, "dns_temp_failure"},
		{"proxyconnect tcp: dial tcp 10.0.0.1:8080: i/o timeout", "http", 0, "proxy_connect_timeout"},
		{"proxyconnect tcp: dial tcp 10.0.0.1:8080: connection refused", "http", 0, "proxy_connect_refused"},
		{"server responded with status 522", "http", 522, "http_522"},
		{"http: status code 598 upstream timeout", "http", 0, "http_598"},
		{"proxy error: policy blocked", "http", 0, "proxy_error"},
		{"connect: operation not permitted: administratively prohibited", "tcp", 0, "net_admin_prohibited"},
		{"write: software caused connection abort", "http", 0, "conn_abort"},
		{"read: connection closed by peer", "http", 0, "conn_reset"},
	}
	for _, tt := range cases {
		if got := normalizeErrorReasonDetailed(tt.err, tt.head, tt.typed); got != tt.want {
			t.Fatalf("for %q got %q want %q", tt.err, got, tt.want)
		}
	}
}
