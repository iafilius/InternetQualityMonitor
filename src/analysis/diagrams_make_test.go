package analysis

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMakeDiagrams ensures the PlantUML diagrams render without errors via `make diagrams`.
// Skips if PlantUML is not found in PATH to avoid false negatives in minimal environments.
func TestMakeDiagrams(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("unsupported runtime for exec")
	}
	if _, err := exec.LookPath("plantuml"); err != nil {
		t.Skip("plantuml not found in PATH; skipping diagrams test")
	}

	// Run `make diagrams` from repository root.
	// This test file lives in src/analysis, so go two directories up.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	cmd := exec.Command("make", "diagrams")
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("make diagrams failed: %v\nOutput:\n%s", err, out.String())
	}

	// Also run the local update script to verify it succeeds as well.
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found; skipping update_diagrams.sh execution")
	}
	scriptCmd := exec.Command("bash", "scripts/update_diagrams.sh")
	scriptCmd.Dir = root
	var out2 bytes.Buffer
	scriptCmd.Stdout = &out2
	scriptCmd.Stderr = &out2
	if err := scriptCmd.Run(); err != nil {
		t.Fatalf("scripts/update_diagrams.sh failed: %v\nOutput:\n%s", err, out2.String())
	}
}
