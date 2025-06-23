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
	logger.Log.Info("🔍 Started security analysis")

	ctx := context.Background()

	trivyReport, err := trivy.Scan(ctx)
	if err != nil {
		logger.Log.Error("Trivy scan failed", "error", err)
		os.Exit(1)
	}
	logger.Log.Info("✅ Trivy analysis complete", "targets", len(trivyReport.Results))

	findings := astgrep.ProcessTrivyReport(ctx, *trivyReport)

	logger.Log.Info("Total grep findings", "count", len(findings), "findings", findings)

	logger.Log.Info("✅ Security analysis finished successfully")
}
