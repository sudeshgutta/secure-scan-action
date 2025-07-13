package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	logger.Log.Info("Running Trivy scan...")

	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--exit-code", "0",
		"--severity", TRIVY_SEVERITY,
		"--format", TRIVY_OUTPUT_FORMAT,
		TRIVY_SCAN_PATH,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			logger.Log.Error("Trivy scan timed out")
			return nil, err
		}
		logger.Log.Error("Trivy scan failed", "err", err, "stderr", stderr.String())
		return nil, err
	}

	var report TrivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		logger.Log.Error("JSON parsing failed", "err", err)
		return nil, err
	}

	logger.Log.Info("Trivy scan completed successfully")
	return &report, nil
}
