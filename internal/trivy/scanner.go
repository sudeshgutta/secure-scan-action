package trivy

import (
	"bytes"
	"encoding/json"
	"os/exec"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

func Scan() (*TrivyReport, error) {
	logger.Log.Debug("executing trivy")
	cmd := exec.Command("trivy", "fs", "--exit-code", "0", "--severity", "HIGH", "--format", "json", ".")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Log.Error("trivy scan failed", "err", err, "stderr", stderr.String())
		return nil, err
	}

	var report TrivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		logger.Log.Error("json unmarshal error", "err", err, "stdout", stdout.String())
		return nil, err
	}

	logger.Log.Debug("generated trivy scan report", "report", report)
	return &report, nil
}
