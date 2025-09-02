package main

import (
	"image"
	"testing"
)

// Smoke test for hideUnknownProtocols wiring; ensure renderers return non-nil images without panics.
func TestHideUnknownProtocolsToggle_Smoke(t *testing.T) {
	s := &uiState{}
	s.hideUnknownProtocols = true
	img1 := renderHTTPProtocolMixChart(s)
	if img1 == nil {
		t.Fatalf("expected non-nil image with hideUnknownProtocols=true")
	}
	img2 := renderAvgSpeedByHTTPProtocolChart(s)
	if img2 == nil {
		t.Fatalf("expected non-nil image for avg speed renderer")
	}
	img3 := renderTLSVersionMixChart(s)
	if img3 == nil {
		t.Fatalf("expected non-nil image for TLS mix renderer")
	}
	img4 := renderALPNMixChart(s)
	if img4 == nil {
		t.Fatalf("expected non-nil image for ALPN mix renderer")
	}
	_ = image.Rect
}
