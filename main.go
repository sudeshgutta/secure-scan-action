package main

import (
	"os"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func main() {
	logger.Init()
	logger.Log.Info("scanning...")

	trivyReport, err := trivy.Scan()
	if trivyReport != nil {
		hasVulns := false

		if len(trivyReport.Results) == 0 {
			logger.Log.Warn("trivy scan completed, but no results were found")
		} else {
			for _, result := range trivyReport.Results {
				if len(result.Vulnerabilities) > 0 {
					logger.Log.Info("scan found vulnerabilities", "target", result.Target, "count", len(result.Vulnerabilities))
					hasVulns = true
					break
				}
			}
		}

		if hasVulns {
			os.Exit(1)
		} else if err != nil {
			logger.Log.Error("error running scanner", "err", err)
			os.Exit(2)
		} else {
			logger.Log.Info("finished scan, no vulnerabilities")
			os.Exit(0)
		}
	}

	// This catches nil report — likely a failed Trivy execution or parsing error
	logger.Log.Error("trivy failed to generate report", "err", err)
	os.Exit(3)
}
