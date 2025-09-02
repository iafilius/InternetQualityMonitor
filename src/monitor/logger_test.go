package monitor

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestInfof_NoDoubleFormattingWithPercent(t *testing.T) {
	// Swap the base logger to capture output
	var buf bytes.Buffer
	saved := baseLogger
	baseLogger = log.New(&buf, "", 0)
	defer func() { baseLogger = saved }()

	SetLogLevel("info")

	msg := "[Linode UK 100MB ::1] done head=200 sec_get=206 bytes=104857600 (100.0% of 104857600) time=2893ms speed=35395.8kbps dns=35ms tcp=0ms tls=116ms ttfb=431ms proto=HTTP/1.1 alpn=(unknown) tls_ver=TLS1.3"
	Infof(msg)

	out := buf.String()
	if !strings.Contains(out, "(100.0% of 104857600)") {
		t.Fatalf("log output missing expected percent segment: %s", out)
	}
	if strings.Contains(out, "%!o(MISSING)") || strings.Contains(out, "%!f(MISSING)") {
		t.Fatalf("log output still shows fmt artifact: %s", out)
	}
}
