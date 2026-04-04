package main

import (
"context"
"fmt"
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

exitCode, findings := run()
writeSARIF(findings)
os.Exit(exitCode)
}

// run performs the scan and returns the exit code and findings.
// Separating it from main ensures writeSARIF always executes before os.Exit.
func run() (int, []astgrep.Finding) {
ctx := context.Background()

trivyReport, err := trivy.Scan(ctx)
if err != nil {
logger.Log.Error("Trivy scan failed", "error", err)
return 1, nil
}
logger.Log.Info("Trivy analysis complete")

findings := astgrep.ProcessTrivyReport(ctx, *trivyReport)
logger.Log.Info("ASTGrep analysis complete")

report.Print(findings, os.Stdout)

if len(findings) > 0 {
logger.Log.Info("🚨 Vulnerable package(s) usage found", "count", len(findings))
return 2, findings
}

logger.Log.Info("✅ No vulnerable package(s) usage found")
logger.Log.Info("⚡️ Scan finished successfully")
return 0, findings
}

func writeSARIF(findings []astgrep.Finding) {
sarifPath := os.Getenv("INPUT_SARIF_OUTPUT")
if sarifPath == "" {
return
}
// Anchor relative paths to GITHUB_WORKSPACE so the file lands on the
// host runner filesystem and survives after the Docker container exits.
// WORKDIR /github/workspace in the Dockerfile provides the same guarantee
// when GITHUB_WORKSPACE is not set (e.g. local dev via make scan).
if !filepath.IsAbs(sarifPath) {
if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
sarifPath = filepath.Join(ws, sarifPath)
}
}
if err := sarif.Write(findings, sarifPath); err != nil {
fmt.Fprintf(os.Stderr, "SARIF write failed: %v\n", err)
} else {
logger.Log.Info("SARIF report written", "path", sarifPath)
}
}
