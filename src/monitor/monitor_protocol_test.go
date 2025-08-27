package monitor

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestFillProtocolTLSAndEncoding_KnownHTTPVersions(t *testing.T) {
	// HTTP/1.0 without TLS
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/1.0"}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.HTTPProtocol != "HTTP/1.0" {
			t.Fatalf("want HTTP/1.0, got %q", sr.HTTPProtocol)
		}
		if sr.TLSVersion != "" || sr.ALPN != "" {
			t.Fatalf("unexpected TLS/ALPN for h1.0: tls=%q alpn=%q", sr.TLSVersion, sr.ALPN)
		}
	}

	// HTTP/1.1 with TLS1.2 and ALPN http/1.1
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/1.1", TLS: &tls.ConnectionState{Version: tls.VersionTLS12, NegotiatedProtocol: "http/1.1", CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.HTTPProtocol != "HTTP/1.1" {
			t.Fatalf("want HTTP/1.1, got %q", sr.HTTPProtocol)
		}
		if sr.TLSVersion != "TLS1.2" {
			t.Fatalf("want TLS1.2, got %q", sr.TLSVersion)
		}
		if sr.ALPN != "http/1.1" {
			t.Fatalf("want ALPN http/1.1, got %q", sr.ALPN)
		}
		if sr.TLSCipher == "" {
			t.Fatalf("expected cipher name to be set")
		}
	}

	// HTTP/2.0 with TLS1.3 and ALPN h2
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/2.0", TLS: &tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h2", CipherSuite: tls.TLS_AES_128_GCM_SHA256}}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.HTTPProtocol != "HTTP/2.0" {
			t.Fatalf("want HTTP/2.0, got %q", sr.HTTPProtocol)
		}
		if sr.TLSVersion != "TLS1.3" {
			t.Fatalf("want TLS1.3, got %q", sr.TLSVersion)
		}
		if sr.ALPN != "h2" {
			t.Fatalf("want ALPN h2, got %q", sr.ALPN)
		}
		if sr.TLSCipher == "" {
			t.Fatalf("expected cipher name to be set")
		}
	}

	// HTTP/2 alias normalization to HTTP/2.0
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/2"}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.HTTPProtocol != "HTTP/2.0" {
			t.Fatalf("want HTTP/2.0 for alias HTTP/2, got %q", sr.HTTPProtocol)
		}
	}

	// Transfer-Encoding chunked detection
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/1.1", TransferEncoding: []string{"chunked"}}
		fillProtocolTLSAndEncoding(sr, resp)
		if !sr.Chunked {
			t.Fatalf("expected chunked=true")
		}
		if sr.TransferEncoding == "" {
			t.Fatalf("expected transfer encoding string to be set")
		}
	}
}

func TestFillProtocolTLSAndEncoding_TLS_ALPN_Variants(t *testing.T) {
	// TLS1.0 mapping and ALPN http/1.1
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/1.1", TLS: &tls.ConnectionState{Version: tls.VersionTLS10, NegotiatedProtocol: "http/1.1", CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.TLSVersion != "TLS1.0" {
			t.Fatalf("want TLS1.0, got %q", sr.TLSVersion)
		}
		if sr.ALPN != "http/1.1" {
			t.Fatalf("want ALPN http/1.1, got %q", sr.ALPN)
		}
	}

	// TLS1.1 mapping and empty ALPN
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/1.1", TLS: &tls.ConnectionState{Version: tls.VersionTLS11, NegotiatedProtocol: "", CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.TLSVersion != "TLS1.1" {
			t.Fatalf("want TLS1.1, got %q", sr.TLSVersion)
		}
		if sr.ALPN != "" {
			t.Fatalf("want empty ALPN, got %q", sr.ALPN)
		}
	}

	// Unknown TLS version maps to hex string, ALPN h2 preserved
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/2.0", TLS: &tls.ConnectionState{Version: 0x9999, NegotiatedProtocol: "h2", CipherSuite: tls.TLS_AES_128_GCM_SHA256}}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.TLSVersion != "0x9999" {
			t.Fatalf("want 0x9999 for unknown TLS version, got %q", sr.TLSVersion)
		}
		if sr.ALPN != "h2" {
			t.Fatalf("want ALPN h2, got %q", sr.ALPN)
		}
	}

	// HTTP/2.0 with empty ALPN stays empty
	{
		sr := &SiteResult{}
		resp := &http.Response{Proto: "HTTP/2.0", TLS: &tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "", CipherSuite: tls.TLS_AES_128_GCM_SHA256}}
		fillProtocolTLSAndEncoding(sr, resp)
		if sr.ALPN != "" {
			t.Fatalf("want empty ALPN for missing negotiation, got %q", sr.ALPN)
		}
	}
}

func TestNormalizeHTTPProto_Variants(t *testing.T) {
	cases := map[string]string{
		" http/2 ":   "HTTP/2.0",
		"http/2":     "HTTP/2.0",
		"HTTP/2":     "HTTP/2.0",
		"HtTp/2":     "HTTP/2.0",
		"http/1.1":   "HTTP/1.1",
		"HtTp/1.1":   "HTTP/1.1",
		" http/1.0 ": "HTTP/1.0",
	}
	for in, want := range cases {
		got := normalizeHTTPProto(in)
		if got != want {
			t.Fatalf("normalize(%q) => %q, want %q", in, got, want)
		}
	}
}
