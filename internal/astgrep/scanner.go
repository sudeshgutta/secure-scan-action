package astgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func scanWithASTGrep(ctx context.Context, pkg string) (*Report, error) {
	ruleJSON, err := BuildASTGrepInlineRule(pkg)
	if err != nil {
		logger.Log.Error("Failed to parse ast grep rule")
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "ast-grep", "scan",
		"--inline-rules", ruleJSON,
		"--json",
		".",
	)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Log.Error("AST-Grep stderr", "stderr", stderr.String())
		return nil, err
	}

	var matches []Match
	if err := json.Unmarshal(stdout.Bytes(), &matches); err != nil {
		logger.Log.Error("Failed to parse ast-grep output", "err", err)
		return nil, err
	}

	return &Report{Matches: matches}, nil
}

func ProcessTrivyReport(ctx context.Context, trivyReport trivy.TrivyReport) Report {
	// Extract vulnerable packages
	vulnPkgs := make(map[string]struct{})
	for _, result := range trivyReport.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.PkgName != "" {
				vulnPkgs[vuln.PkgName] = struct{}{}
			}
		}
	}
	logger.Log.Info("Trivy identified vulnerable packages", "count", len(vulnPkgs))

	var output Report
	for pkg := range vulnPkgs {
		report, err := scanWithASTGrep(ctx, pkg)
		if err != nil {
			logger.Log.Warn("AST-Grep scan failed or timed out", "pkg", pkg, "err", err)
			continue
		}
		if len(report.Matches) == 0 {
			logger.Log.Info("✅ No usage found for vulnerable package", "pkg", pkg, "report", report)
		}
	}
	return output
}
