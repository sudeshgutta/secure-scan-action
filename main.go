package main

import (
	"context"
	"os"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
	"github.com/sudeshgutta/secure-scan-action/internal/logger"
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
	if len(findings) > 0 {
		logger.Log.Info("🚨 Vulnerable package(s) usage found", "count", len(findings), "findings", findings)
		os.Exit(2)
	} else {
		logger.Log.Info("✅ No vulnerable package(s) usage found")
	}

	logger.Log.Info("⚡️ Scan finished successfully")
}
