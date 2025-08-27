package main

import (
	"encoding/json"
	"image"
	_ "image/png" // register PNG decoder
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// writeResultLine writes a minimal JSONL envelope suitable for analysis/screenshot rendering.
func writeResultLine(t *testing.T, f *os.File, runTag string, speedKbps float64, ttfbMs int64) {
	t.Helper()
	env := &monitor.ResultEnvelope{
		Meta: &monitor.Meta{
			TimestampUTC:  time.Now().UTC().Format(time.RFC3339Nano),
			RunTag:        runTag,
			SchemaVersion: monitor.SchemaVersion,
		},
		SiteResult: &monitor.SiteResult{
			Name:              "example",
			TransferSpeedKbps: speedKbps,
			TraceTTFBMs:       ttfbMs,
			TransferSizeBytes: 1024,
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestScreenshotWidths_BaseSet ensures all generated screenshots share the same width ("100%" relative to chartSize when headless).
func TestScreenshotWidths_BaseSet(t *testing.T) {
	// Force a fixed full-width value while headless so assertions are exact.
	screenshotWidthOverride = 1400
	// Prepare a small synthetic results file with a few batches.
	tmpResults, err := os.CreateTemp(t.TempDir(), "results-*.jsonl")
	if err != nil {
		t.Fatalf("create temp results: %v", err)
	}
	// Two runs with a couple of lines each.
	for i := 0; i < 3; i++ {
		writeResultLine(t, tmpResults, "20250101_000000", 1500+float64(i*10), 80)
	}
	for i := 0; i < 3; i++ {
		writeResultLine(t, tmpResults, "20250102_000000", 1200+float64(i*10), 90)
	}
	if err := tmpResults.Close(); err != nil {
		t.Fatalf("close results: %v", err)
	}

	outDir := t.TempDir()

	// Render screenshots headlessly using the base set only (variants = "none").
	if err := RunScreenshotsMode(tmpResults.Name(), outDir, "All", 5, false, 10, 1000, "none", "light", false); err != nil {
		t.Fatalf("RunScreenshotsMode: %v", err)
	}

	// Determine expected width from chartSize(nil) which is used when window=nil.
	expectedW, _ := chartSize(nil)

	// Walk the outDir and verify widths of all PNGs.
	checked := 0
	err = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".png" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		defer f.Close()
		img, _, err := image.Decode(f)
		if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		w := img.Bounds().Dx()
		if w != expectedW {
			t.Fatalf("image width mismatch for %s: got %d, want %d", filepath.Base(path), w, expectedW)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatalf("walk outDir: %v", err)
	}
	if checked == 0 {
		t.Fatalf("no PNG screenshots found in %s", outDir)
	}
}

// TestScreenshotWidths_AllowsShrink ensures charts render correctly at a small width,
// guarding against regressions that reintroduce large minimum widths.
func TestScreenshotWidths_AllowsShrink(t *testing.T) {
	// Force a small full-width value while headless.
	screenshotWidthOverride = 480
	// Prepare a tiny synthetic results file.
	tmpResults, err := os.CreateTemp(t.TempDir(), "results-*.jsonl")
	if err != nil {
		t.Fatalf("create temp results: %v", err)
	}
	for i := 0; i < 2; i++ {
		writeResultLine(t, tmpResults, "20250101_000000", 1000+float64(i*5), 70)
	}
	for i := 0; i < 2; i++ {
		writeResultLine(t, tmpResults, "20250102_000000", 900+float64(i*5), 85)
	}
	if err := tmpResults.Close(); err != nil {
		t.Fatalf("close results: %v", err)
	}

	outDir := t.TempDir()
	if err := RunScreenshotsMode(tmpResults.Name(), outDir, "All", 5, false, 10, 1000, "none", "light", false); err != nil {
		t.Fatalf("RunScreenshotsMode: %v", err)
	}

	expectedW, _ := chartSize(nil)

	checked := 0
	err = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".png" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		defer f.Close()
		img, _, err := image.Decode(f)
		if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if w := img.Bounds().Dx(); w != expectedW {
			t.Fatalf("image width mismatch for %s: got %d, want %d", filepath.Base(path), w, expectedW)
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatalf("walk outDir: %v", err)
	}
	if checked == 0 {
		t.Fatalf("no PNG screenshots found in %s", outDir)
	}
}
