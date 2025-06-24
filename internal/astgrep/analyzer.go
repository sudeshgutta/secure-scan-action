package astgrep

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ASTGrepOutput represents the complete JSON output from AST-Grep
type ASTGrepOutput []ASTGrepMatch

// ParseASTGrepJSON unmarshals JSON data into ASTGrepOutput
func ParseASTGrepJSON(jsonData []byte) (ASTGrepOutput, error) {
	var output ASTGrepOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		return nil, fmt.Errorf("failed to parse AST-Grep JSON: %w", err)
	}
	return output, nil
}

// PackageAnalyzer handles the analysis of package detection results
type PackageAnalyzer struct {
	result *PackageDetectionResult
}

// NewPackageAnalyzer creates a new PackageAnalyzer instance
func NewPackageAnalyzer(packageName string) *PackageAnalyzer {
	return &PackageAnalyzer{
		result: &PackageDetectionResult{
			PackageName:   packageName,
			Found:         false,
			TotalMatches:  0,
			UniqueFiles:   []string{},
			Versions:      []string{},
			ScanTimestamp: time.Now(),
		},
	}
}

// isMatchForPackage checks if a match belongs to the specified package
func (pa *PackageAnalyzer) isMatchForPackage(match ASTGrepMatch, packageName string) bool {
	matchPackage := match.GetPackageName()
	return strings.Contains(matchPackage, packageName)
}

// trackFirstMatch records the first occurrence of a match
func (pa *PackageAnalyzer) trackFirstMatch(match ASTGrepMatch, firstMatch **Location) {
	if *firstMatch == nil {
		location := match.GetLocation()
		*firstMatch = &location
	}
}

// trackVersion adds a version to the version set if it exists
func (pa *PackageAnalyzer) trackVersion(match ASTGrepMatch, versionSet map[string]bool) {
	if version := match.GetVersion(); version != "" {
		versionSet[version] = true
	}
}

// updateResultMetadata updates the result with processed metadata
func (pa *PackageAnalyzer) updateResultMetadata(fileSet, versionSet map[string]bool, firstMatch *Location) {
	// Convert file set to slice
	for file := range fileSet {
		pa.result.UniqueFiles = append(pa.result.UniqueFiles, file)
	}

	// Convert version set to slice
	for version := range versionSet {
		pa.result.Versions = append(pa.result.Versions, version)
	}

	// Update result flags
	pa.result.Found = pa.result.TotalMatches > 0
	pa.result.FirstMatch = firstMatch
	pa.result.HasMultipleFiles = len(pa.result.UniqueFiles) > 1
	pa.result.HasVersions = len(pa.result.Versions) > 0
}

// processMatches processes all matches and updates the result
func (pa *PackageAnalyzer) processMatches(output ASTGrepOutput, packageName string) {
	fileSet := make(map[string]bool)
	versionSet := make(map[string]bool)
	var firstMatch *Location

	for _, match := range output {
		if !pa.isMatchForPackage(match, packageName) {
			continue
		}

		pa.result.TotalMatches++
		pa.trackFirstMatch(match, &firstMatch)
		fileSet[match.File] = true
		pa.trackVersion(match, versionSet)
	}

	pa.updateResultMetadata(fileSet, versionSet, firstMatch)
}

// GetResult returns the current analysis result
func (pa *PackageAnalyzer) GetResult() *PackageDetectionResult {
	return pa.result
}

// AnalyzePackage analyzes AST-Grep output for a specific package
func (output ASTGrepOutput) AnalyzePackage(packageName string) *PackageDetectionResult {
	analyzer := NewPackageAnalyzer(packageName)

	if len(output) == 0 {
		return analyzer.GetResult()
	}

	analyzer.result.RuleId = output[0].RuleId
	analyzer.processMatches(output, packageName)

	return analyzer.GetResult()
}
