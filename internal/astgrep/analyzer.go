package astgrep

import (
	"strings"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

// AnalyzePackageMatches analyzes AST-Grep output for a specific package
func AnalyzePackageMatches(matches []ASTGrepMatch, pkg string) *PackageDetectionResult {
	logger.Log.Debug("analysing astgrep result")
	result := &PackageDetectionResult{
		PackageName:   pkg,
		Found:         false,
		TotalMatches:  0,
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
		matchPackage := match.GetPackageName()
		if !strings.Contains(matchPackage, pkg) {
			continue
		}

		result.TotalMatches++
		if firstMatch == nil {
			loc := match.GetLocation()
			firstMatch = &loc
		}
		fileSet[match.File] = true
		if version := match.GetVersion(); version != "" {
			versionSet[version] = true
		}
	}

	for file := range fileSet {
		result.UniqueFiles = append(result.UniqueFiles, file)
	}
	for version := range versionSet {
		result.Versions = append(result.Versions, version)
	}

	result.Found = result.TotalMatches > 0
	result.FirstMatch = firstMatch
	result.HasMultipleFiles = len(result.UniqueFiles) > 1
	result.HasVersions = len(result.Versions) > 0

	logger.Log.Debug("completed analysis, returning updated result")
	return result
}
