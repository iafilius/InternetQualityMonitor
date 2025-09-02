package monitor

import (
    "testing"
    "time"
)

func TestLocalMaxSpeedProbe(t *testing.T) {
    kbps, err := LocalMaxSpeedProbe(200 * time.Millisecond)
    if err != nil {
        t.Fatalf("LocalMaxSpeedProbe error: %v", err)
    }
    if kbps <= 0 {
        t.Fatalf("expected positive kbps, got %.2f", kbps)
    }
    // On most modern systems loopback should exceed 10000 kbps (10 Mbps), but
    // keep a low floor to avoid flakiness in constrained CI.
    if kbps < 1000 { // 1 Mbps floor
        t.Fatalf("unexpectedly low loopback kbps: %.2f", kbps)
    }
}
