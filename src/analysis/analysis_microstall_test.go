package analysis

import (
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// helper to write one envelope line with a crafted micro-stall in samples
func writeLineWithMicroStall(t *testing.T, f *os.File, runTag, family string, preSamples, stallSamples, postSamples int, interval time.Duration) {
    t.Helper()
    var samples []monitor.SpeedSample
    var bytesAccum int64
    // preSamples with progress
    for i := 0; i < preSamples; i++ {
        tm := int64(len(samples)) * int64(interval/time.Millisecond)
        bytesAccum += 32 * 1024 // arbitrary
        samples = append(samples, monitor.SpeedSample{TimeMs: tm, Bytes: bytesAccum, Speed: 1000})
    }
    // stallSamples with no progress (Bytes flat)
    for i := 0; i < stallSamples; i++ {
        tm := int64(len(samples)) * int64(interval/time.Millisecond)
        samples = append(samples, monitor.SpeedSample{TimeMs: tm, Bytes: bytesAccum, Speed: 0})
    }
    // postSamples with progress again
    for i := 0; i < postSamples; i++ {
        tm := int64(len(samples)) * int64(interval/time.Millisecond)
        bytesAccum += 32 * 1024
        samples = append(samples, monitor.SpeedSample{TimeMs: tm, Bytes: bytesAccum, Speed: 2000})
    }
    sr := &monitor.SiteResult{IPFamily: family, TransferSpeedKbps: 1500, TransferSizeBytes: bytesAccum, TransferSpeedSamples: samples}
    env := monitor.ResultEnvelope{Meta: &monitor.Meta{TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), RunTag: runTag, SchemaVersion: monitor.SchemaVersion}, SiteResult: sr}
    b, _ := json.Marshal(&env)
    if _, err := f.Write(append(b, '\n')); err != nil {
        t.Fatalf("write: %v", err)
    }
}

func TestMicroStalls_Computation(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "results.jsonl")
    f, err := os.Create(path)
    if err != nil {
        t.Fatalf("create: %v", err)
    }
    defer f.Close()

    runTag := "MS1"
    // Construct one IPv4 line with a 600ms no-progress gap and one IPv6 without
    interval := monitor.SpeedSampleInterval // 100ms
    writeLineWithMicroStall(t, f, runTag, "ipv4", 5, 6, 5, interval) // 6*100ms = 600ms micro-stall
    writeLineWithMicroStall(t, f, runTag, "ipv6", 10, 0, 10, interval) // no micro-stall

    opts := AnalyzeOptions{SituationFilter: "", LowSpeedThresholdKbps: 0, MicroStallMinGapMs: 500}
    sums, err := AnalyzeRecentResultsFullWithOptions(path, monitor.SchemaVersion, 5, opts)
    if err != nil {
        t.Fatalf("analyze: %v", err)
    }
    if len(sums) != 1 {
        t.Fatalf("expected 1 batch got %d", len(sums))
    }
    b := sums[0]
    if b.MicroStallRatePct <= 0 {
        t.Fatalf("expected overall micro-stall rate > 0, got %.3f", b.MicroStallRatePct)
    }
    if b.IPv4 == nil || b.IPv6 == nil {
        t.Fatalf("expected per-family summaries present")
    }
    if b.IPv4.MicroStallRatePct <= 0 {
        t.Fatalf("expected ipv4 micro-stall rate > 0, got %.3f", b.IPv4.MicroStallRatePct)
    }
    if b.IPv6.MicroStallRatePct != 0 {
        t.Fatalf("expected ipv6 micro-stall rate == 0, got %.3f", b.IPv6.MicroStallRatePct)
    }
    if b.AvgMicroStallMs <= 0 || b.AvgMicroStallCount <= 0 {
        t.Fatalf("expected avg micro-stall ms & count > 0, got ms=%.1f count=%.2f", b.AvgMicroStallMs, b.AvgMicroStallCount)
    }
}
