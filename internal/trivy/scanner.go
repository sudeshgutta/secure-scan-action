package trivy

import (
	"bytes"
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

	var outputBuffer bytes.Buffer

	logger.Log.Info("Running Trivy scan...")

	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--exit-code", "0",
		"--severity", TRIVY_SEVERITY,
		"--format", TRIVY_OUTPUT_FORMAT,
		TRIVY_SCAN_PATH,
	)
	cmd.Stdout = &outputBuffer
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			logger.Log.Error("Trivy scan timed out")
			return nil, errors.New("trivy scan timed out")
		}
		logger.Log.Error("Trivy scan failed", "err", err)
		return nil, err
	}

	var report TrivyReport
	if err := json.Unmarshal(outputBuffer.Bytes(), &report); err != nil {
		logger.Log.Error("JSON parsing failed", "err", err)
		return nil, err
	}

	logger.Log.Info("Trivy scan completed successfully")
	return &report, nil
}
