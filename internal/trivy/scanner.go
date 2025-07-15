package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

const (
	TRIVY_TIMEOUT       time.Duration = 120 * time.Second
	TRIVY_SCAN_PATH     string        = "."
	TRIVY_SEVERITY      string        = "HIGH"
	TRIVY_OUTPUT_FORMAT string        = "json"
)

func Scan(ctx context.Context) (*TrivyReport, error) {
	ctx, cancel := context.WithTimeout(ctx, TRIVY_TIMEOUT)
	defer cancel()
	var stdout, stderr bytes.Buffer
	logger.Log.Debug("starting trivy scan...")

	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--exit-code", "0",
		"--severity", TRIVY_SEVERITY,
		"--format", TRIVY_OUTPUT_FORMAT,
		TRIVY_SCAN_PATH,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Log.Debug("executing trivy binary...")

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	logger.Log.Debug("parsing trivy scan results...")
	var report TrivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, err
	}

	logger.Log.Debug("trivy scan completed successfully")
	return &report, nil
}
