package main

import (
	"image"
	"testing"
)

// This is a smoke test to ensure the new hideOtherCategories toggle is wired and does not crash rendering.
// We don't inspect pixels; we just ensure the chart renders with the toggle on/off without panics.
func TestHideOtherCategoriesToggle_Smoke(t *testing.T) {
	s := &uiState{}
	// Minimal state to call chart renderers; chartSize reads state only.
	// Toggle on and ensure no panic
	s.hideOtherCategories = true
	// rendering functions handle empty data by returning a blank image, which is fine.
	img1 := renderErrorReasonsChart(s)
	if img1 == nil {
		t.Fatalf("expected non-nil image with hideOtherCategories=true")
	}
	// Toggle off and render again
	s.hideOtherCategories = false
	img2 := renderErrorReasonsDetailedChart(s)
	if img2 == nil {
		t.Fatalf("expected non-nil image with hideOtherCategories=false")
	}
	// Dummy use to avoid unused import if optimized
	_ = image.Rect
}
