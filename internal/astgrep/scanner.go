package astgrep

import (
	"bytes"
	"context"
	"os/exec"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep/rules"
	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func ProcessTrivyReport(ctx context.Context, trivyReport trivy.TrivyReport) []string {
	vulnPkgs := extractVulnerablePackages(trivyReport)
	logger.Log.Info("Trivy identified vulnerable packages", "count", len(vulnPkgs))

	var detectedPackages []string
	for pkg := range vulnPkgs {
		result, err := scanWithASTGrep(ctx, pkg)
		if err != nil {
			logger.Log.Warn("AST-Grep scan failed or timed out", "pkg", pkg, "err", err)
			continue
		}
		logger.Log.Info(result.GetSummaryString())
		detectedPackages = append(detectedPackages, result.PackageName)
	}
	return detectedPackages
}

func scanWithASTGrep(ctx context.Context, pkg string) (*PackageDetectionResult, error) {
	//TODO: Add support for other languages
	ruleJSON, err := rules.BuildRule(pkg)
	if err != nil {
		logger.Log.Error("Failed to parse ast grep rule")
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sg", "scan",
		"--inline-rules", ruleJSON,
		"--json",
		".",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Log.Error("AST-Grep stderr", "err", err, "stderr", stderr.String())
		return nil, err
	}

	output, err := ParseASTGrepJSON(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	result := output.AnalyzePackage(pkg)
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
