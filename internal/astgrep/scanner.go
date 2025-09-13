package astgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep/rules"
	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

const (
	ASTGREP_TIMEOUT time.Duration = 120 * time.Second
)

func ProcessTrivyReport(ctx context.Context, trivyReport trivy.TrivyReport) []string {
	vulnPkgs := extractVulnerablePackages(trivyReport)
	logger.Log.Debug("setting up astgrep scan for trivy identified vulnerable packages", "count", len(vulnPkgs))

	detectedPackages := make([]string, 0)
	for pkg := range vulnPkgs {
		result, err := scanWithASTGrep(ctx, pkg)
		if err != nil {
			logger.Log.Warn("astgrep scan failed or timed out for package", "pkg", pkg, "err", err)
			continue
		}
		detectedPackages = append(detectedPackages, result.GetSummaryString())
	}
	return detectedPackages
}

func scanWithASTGrep(ctx context.Context, pkg string) (*PackageDetectionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, ASTGREP_TIMEOUT)
	defer cancel()

	// Build AST-Grep rule
	logger.Log.Debug("building ast-grep rule")
	ruleJSON, err := rules.BuildRule(pkg)
	if err != nil {
		return nil, err
	}

	// Execute AST-Grep command
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sg", "scan",
		"--inline-rules", ruleJSON,
		"--json",
		".",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Log.Debug("executing ast-grep to find vulnerable packages")
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	// Parse results
	logger.Log.Debug("parsing astgrep result json")
	var matches []ASTGrepMatch
	if err := json.Unmarshal(stdout.Bytes(), &matches); err != nil {
		return nil, err
	}

	// Analyze matches
	logger.Log.Debug("analysing astgrep matches")
	result := AnalyzePackageMatches(matches, pkg)

	logger.Log.Debug("completed astgrep analysis", "pkg", pkg)
	return result, nil
}

func extractVulnerablePackages(trivyReport trivy.TrivyReport) map[string]struct{} {
	vulnPkgs := make(map[string]struct{})

	for _, result := range trivyReport.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.PkgName != "" {
				vulnPkgs[vuln.PkgName] = struct{}{}
			}
		}
	}

	return vulnPkgs
}
