package astgrep

import (
	"strings"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

// AnalyzePackageMatches analyzes AST-Grep output for a specific package.
// Returns the detection result; reachability is computed separately via computeReachability.
func AnalyzePackageMatches(matches []ASTGrepMatch, pkg string) *PackageDetectionResult {
	logger.Log.Debug("analysing astgrep result")

	result := &PackageDetectionResult{
		PackageName:   pkg,
		UniqueFiles:   []string{},
		Versions:      []string{},
		ScanTimestamp: time.Now(),
	}

	if len(matches) == 0 {
		return result
	}

	result.RuleId = matches[0].RuleId
	fileSet := make(map[string]bool)
	versionSet := make(map[string]bool)
	var firstMatch *Location

	for _, match := range matches {
		if !strings.Contains(match.GetPackageName(), pkg) {
			continue
		}
		result.TotalMatches++
		if firstMatch == nil {
			loc := match.GetLocation()
			firstMatch = &loc
		}
		fileSet[match.File] = true
		if v := match.GetVersion(); v != "" {
			versionSet[v] = true
		}
	}

	for k := range fileSet {
		result.UniqueFiles = append(result.UniqueFiles, k)
	}
	for k := range versionSet {
		result.Versions = append(result.Versions, k)
	}

	result.Found = result.TotalMatches > 0
	result.FirstMatch = firstMatch
	result.HasMultipleFiles = len(result.UniqueFiles) > 1
	result.HasVersions = len(result.Versions) > 0

	logger.Log.Debug("completed analysis, returning updated result")
	return result
}
