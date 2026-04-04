package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/report"
	"github.com/sudeshgutta/secure-scan-action/internal/sarif"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func main() {
	logger.Init()
	logger.Log.Info("🔍 Scanning for vulnerable packages")

	ctx := context.Background()

	trivyReport, err := trivy.Scan(ctx)
	if err != nil {
		logger.Log.Error("Trivy scan failed", "error", err)
		os.Exit(1)
	}
	logger.Log.Info("Trivy analysis complete")

	findings := astgrep.ProcessTrivyReport(ctx, *trivyReport)
	logger.Log.Info("ASTGrep analysis complete")

	report.Print(findings, os.Stdout)

	if sarifPath := os.Getenv("INPUT_SARIF_OUTPUT"); sarifPath != "" {
		// Docker actions run in a container; relative paths resolve inside the container.
		// Anchor to GITHUB_WORKSPACE so the file is visible on the host runner after exit.
		if !filepath.IsAbs(sarifPath) {
			if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
				sarifPath = filepath.Join(ws, sarifPath)
			}
		}
		if err := sarif.Write(findings, sarifPath); err != nil {
			logger.Log.Warn("Failed to write SARIF output", "path", sarifPath, "error", err)
		} else {
			logger.Log.Info("SARIF report written", "path", sarifPath)
		}
	}

	if len(findings) > 0 {
		logger.Log.Info("🚨 Vulnerable package(s) usage found", "count", len(findings))
		os.Exit(2)
	}

	logger.Log.Info("✅ No vulnerable package(s) usage found")
	logger.Log.Info("⚡️ Scan finished successfully")
}
