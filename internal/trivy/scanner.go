package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

const (
	TRIVY_TIMEOUT       = 120 * time.Second
	TRIVY_SCAN_PATH     = "."
	TRIVY_SEVERITY      = "HIGH"
	TRIVY_OUTPUT_FORMAT = "json"
)

func Scan(ctx context.Context) (*TrivyReport, error) {
	ctx, cancel := context.WithTimeout(ctx, TRIVY_TIMEOUT)
	defer cancel()

	// Step 1: Create temporary file
	tmpFile, err := os.CreateTemp("", "trivy-report-*.json")
	if err != nil {
		logger.Log.Error("Failed to create temp file", "err", err)
		return nil, err
	}
	defer os.Remove(tmpFile.Name()) // auto-cleanup
	defer tmpFile.Close()

	logger.Log.Info("Trivy output file created", "file", tmpFile.Name())

	// Step 2: Construct command
	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--exit-code", "0",
		"--severity", TRIVY_SEVERITY,
		"--format", TRIVY_OUTPUT_FORMAT,
		"--output", tmpFile.Name(),
		TRIVY_SCAN_PATH,
	)

	cmd.Stderr = os.Stderr // pipe errors to stderr for visibility

	logger.Log.Info("Running Trivy scan...")

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Log.Error("Trivy scan timed out")
			return nil, errors.New("trivy scan timed out")
		}
		logger.Log.Error("Trivy scan failed", "err", err)
		return nil, err
	}

	// Step 3: Read output from file
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		logger.Log.Error("Failed to read Trivy output", "err", err)
		return nil, err
	}

	// Step 4: Parse JSON
	var report TrivyReport
	if err := json.Unmarshal(content, &report); err != nil {
		logger.Log.Error("JSON parsing failed", "err", err)
		return nil, err
	}

	logger.Log.Info("Trivy scan completed", "file", tmpFile.Name())
	return &report, nil
}
