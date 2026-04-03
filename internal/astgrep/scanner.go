package astgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	for pkg, languages := range vulnPkgs {
		for _, language := range languages {
			result, err := scanWithASTGrep(ctx, pkg, language)
			if err != nil {
				logger.Log.Warn("astgrep scan failed or timed out for package", "pkg", pkg, "language", language, "err", err)
				continue
			}
			if result.IsFound() {
				detectedPackages = append(detectedPackages, result.GetSummaryString())
			}
		}
	}
	return detectedPackages
}

func scanWithASTGrep(ctx context.Context, pkg, language string) (*PackageDetectionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, ASTGREP_TIMEOUT)
	defer cancel()

	// Build AST-Grep rule
	logger.Log.Debug("building ast-grep rule")
	ruleJSON, err := rules.BuildRule(pkg, language)
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
		return nil, fmt.Errorf("ast-grep failed: %w: %s", err, stderr.String())
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

func extractVulnerablePackages(trivyReport trivy.TrivyReport) map[string][]string {
	pkgLanguages := make(map[string]map[string]struct{})

	for _, result := range trivyReport.Results {
		languages := rules.LanguagesForEcosystem(result.Type)
		if languages == nil {
			continue
		}
		for _, vuln := range result.Vulnerabilities {
			if vuln.PkgName == "" {
				continue
			}
			if _, exists := pkgLanguages[vuln.PkgName]; !exists {
				pkgLanguages[vuln.PkgName] = make(map[string]struct{})
			}
			for _, lang := range languages {
				pkgLanguages[vuln.PkgName][lang] = struct{}{}
			}
		}
	}

	result := make(map[string][]string, len(pkgLanguages))
	for pkg, langSet := range pkgLanguages {
		langs := make([]string, 0, len(langSet))
		for lang := range langSet {
			langs = append(langs, lang)
		}
		result[pkg] = langs
	}
	return result
}
