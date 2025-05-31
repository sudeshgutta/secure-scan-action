package main

import (
	"context"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func main() {
	token := jwt.New(jwt.SigningMethodHS256)
	if token != nil {
		fmt.Println(token.Raw)
	}

	logger.Init()
	logger.Log.Info("🔍 Started security analysis")

	ctx := context.Background()

	// Run Trivy scan
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
