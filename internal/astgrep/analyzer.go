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

	// Process all matches
	for _, match := range matches {
		if !isPackageMatch(match, pkg) {
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

	// Convert sets to slices
	result.UniqueFiles = mapKeysToSlice(fileSet)
	result.Versions = mapKeysToSlice(versionSet)

	// Set result flags
	result.Found = result.TotalMatches > 0
	result.FirstMatch = firstMatch
	result.HasMultipleFiles = len(result.UniqueFiles) > 1
	result.HasVersions = len(result.Versions) > 0

	logger.Log.Debug("completed analysis, returning updated result")
	return result
}

// isPackageMatch checks if a match is for the specified package
func isPackageMatch(match ASTGrepMatch, pkg string) bool {
	return strings.Contains(match.GetPackageName(), pkg)
}

// mapKeysToSlice converts map keys to a slice
func mapKeysToSlice(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
