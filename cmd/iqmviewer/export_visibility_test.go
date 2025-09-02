package main

import (
	"image"
	"image/color"
	"testing"

	"fyne.io/fyne/v2/canvas"
)

func TestExportAll_RespectsVisibilityToggle(t *testing.T) {
	s := &uiState{}
	// Pretend some charts are rendered
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	s.setupDNSImgCanvas = canvas.NewImageFromImage(img)
	s.protocolMixImgCanvas = canvas.NewImageFromImage(img)
	s.errorReasonsDetailedImgCanvas = canvas.NewImageFromImage(img)

	// Start with respectVisibility = false -> all present should be planned regardless of isChartVisible
	s.exportRespectVisibility = false
	labels := getExportPlan(s)
	if len(labels) < 3 {
		t.Fatalf("expected >=3 charts in plan, got %d: %v", len(labels), labels)
	}

	// Now enable respectVisibility and hide protocol mix via stable ID
	s.exportRespectVisibility = true
	s.hiddenChartIDs = map[string]bool{"http_protocol_mix": true}
	labels2 := getExportPlan(s)
	for _, l := range labels2 {
		if l == "HTTP Protocol Mix (%)" {
			t.Fatalf("protocol mix should be omitted when hidden and respectVisibility=true; got plan: %v", labels2)
		}
	}
}
