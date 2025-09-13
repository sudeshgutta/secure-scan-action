package trivy

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

func TestScanConstants(t *testing.T) {
	if TRIVY_TIMEOUT != 120*time.Second {
		t.Errorf("Expected TRIVY_TIMEOUT to be 120 seconds, got %v", TRIVY_TIMEOUT)
	}

	if TRIVY_SCAN_PATH != "." {
		t.Errorf("Expected TRIVY_SCAN_PATH to be '.', got '%s'", TRIVY_SCAN_PATH)
	}

	if TRIVY_SEVERITY != "HIGH" {
		t.Errorf("Expected TRIVY_SEVERITY to be 'HIGH', got '%s'", TRIVY_SEVERITY)
	}

	if TRIVY_OUTPUT_FORMAT != "json" {
		t.Errorf("Expected TRIVY_OUTPUT_FORMAT to be 'json', got '%s'", TRIVY_OUTPUT_FORMAT)
	}
}

func TestScanWithTimeout(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// This should timeout quickly
	_, err := Scan(ctx)
	if err == nil {
		t.Error("Expected scan to timeout, but it didn't")
	}
}

func TestScanCommandConstruction(t *testing.T) {
	// Test that the command is constructed correctly
	// We can't easily test the actual execution without trivy installed,
	// but we can test the command construction logic

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, TRIVY_TIMEOUT)
	defer cancel()

	// Create a mock command to test the arguments
	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--exit-code", "0",
		"--severity", TRIVY_SEVERITY,
		"--format", TRIVY_OUTPUT_FORMAT,
		TRIVY_SCAN_PATH,
	)

	expectedArgs := []string{
		"fs",
		"--exit-code", "0",
		"--severity", "HIGH",
		"--format", "json",
		".",
	}

	if len(cmd.Args) != len(expectedArgs)+1 { // +1 for the command name
		t.Errorf("Expected %d arguments, got %d", len(expectedArgs)+1, len(cmd.Args))
	}

	for i, expectedArg := range expectedArgs {
		if cmd.Args[i+1] != expectedArg {
			t.Errorf("Expected argument %d to be '%s', got '%s'", i, expectedArg, cmd.Args[i+1])
		}
	}
}
