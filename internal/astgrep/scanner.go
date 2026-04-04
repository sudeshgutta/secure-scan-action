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

// pkgMeta holds aggregated vulnerability metadata for a package.
type pkgMeta struct {
	languages []string
	cveIDs    []string
	severity  string // worst severity seen
}

func ProcessTrivyReport(ctx context.Context, trivyReport trivy.TrivyReport) []Finding {
	pkgs := extractVulnerablePackages(trivyReport)
	logger.Log.Debug("setting up astgrep scan for trivy identified vulnerable packages", "count", len(pkgs))

	var findings []Finding
	for pkg, meta := range pkgs {
		for _, language := range meta.languages {
			result, err := scanWithASTGrep(ctx, pkg, language)
			if err != nil {
				logger.Log.Warn("astgrep scan failed or timed out for package", "pkg", pkg, "language", language, "err", err)
				continue
			}
			if result.IsFound() {
				findings = append(findings, Finding{
					Package:           pkg,
					Language:          language,
					CVEIDs:            meta.cveIDs,
					Severity:          meta.severity,
					DetectionResult:   result,
					ReachabilityScore: computeReachability(result.UniqueFiles),
				})
			}
		}
	}
	return findings
}

func scanWithASTGrep(ctx context.Context, pkg, language string) (*PackageDetectionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, ASTGREP_TIMEOUT)
	defer cancel()

	logger.Log.Debug("building ast-grep rule")
	ruleYAML, err := rules.BuildRule(pkg, language)
	if err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sg", "scan",
		"--inline-rules", ruleYAML,
		"--json",
		".",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Log.Debug("executing ast-grep to find vulnerable packages")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ast-grep failed: %w: %s", err, stderr.String())
	}

	logger.Log.Debug("parsing astgrep result json")
	var matches []ASTGrepMatch
	if err := json.Unmarshal(stdout.Bytes(), &matches); err != nil {
		return nil, err
	}

	logger.Log.Debug("analysing astgrep matches")
	result := AnalyzePackageMatches(matches, pkg)

	logger.Log.Debug("completed astgrep analysis", "pkg", pkg)
	return result, nil
}

// severityRank returns a numeric rank for severity comparison (higher = worse).
func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func extractVulnerablePackages(trivyReport trivy.TrivyReport) map[string]*pkgMeta {
	pkgs := make(map[string]*pkgMeta)

	for _, result := range trivyReport.Results {
		languages := rules.LanguagesForEcosystem(result.Type)
		if languages == nil {
			continue
		}
		for _, vuln := range result.Vulnerabilities {
			if vuln.PkgName == "" {
				continue
			}
			meta, exists := pkgs[vuln.PkgName]
			if !exists {
				meta = &pkgMeta{languages: languages}
				pkgs[vuln.PkgName] = meta
			}
			if vuln.VulnerabilityID != "" {
				meta.cveIDs = append(meta.cveIDs, vuln.VulnerabilityID)
			}
			if severityRank(vuln.Severity) > severityRank(meta.severity) {
				meta.severity = vuln.Severity
			}
		}
	}

	return pkgs
}
