package astgrep

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ASTGrepOutput represents the complete JSON output from AST-Grep
type ASTGrepOutput []ASTGrepMatch

// ParseASTGrepJSON parses AST-Grep JSON output
func ParseASTGrepJSON(jsonData []byte) (ASTGrepOutput, error) {
	var output ASTGrepOutput
	if err := json.Unmarshal(jsonData, &output); err != nil {
		return nil, fmt.Errorf("failed to parse AST-Grep JSON: %w", err)
	}
	return output, nil
}

// AnalyzePackage analyzes the output for a specific package
func (output ASTGrepOutput) AnalyzePackage(packageName string) *PackageDetectionResult {
	result := &PackageDetectionResult{
		PackageName:   packageName,
		Found:         false,
		TotalMatches:  0,
		UniqueFiles:   []string{},
		Versions:      []string{},
		ScanTimestamp: time.Now(),
	}

	if len(output) == 0 {
		return result
	}

	// Set rule ID from first match
	result.RuleId = output[0].RuleId

	// Track unique files and versions
	fileSet := make(map[string]bool)
	versionSet := make(map[string]bool)

	var firstMatch *Location

	for _, match := range output {
		// Check if this match is for our target package
		matchPackage := match.GetPackageName()
		if !strings.Contains(matchPackage, packageName) {
			continue
		}

		result.TotalMatches++

		// Track first match
		if firstMatch == nil {
			location := match.GetLocation()
			firstMatch = &location
		}

		// Track unique files
		fileSet[match.File] = true

		// Track versions
		if version := match.GetVersion(); version != "" {
			versionSet[version] = true
		}
	}

	// Convert sets to slices
	for file := range fileSet {
		result.UniqueFiles = append(result.UniqueFiles, file)
	}
	for version := range versionSet {
		result.Versions = append(result.Versions, version)
	}

	// Set result metadata
	result.Found = result.TotalMatches > 0
	result.FirstMatch = firstMatch
	result.HasMultipleFiles = len(result.UniqueFiles) > 1
	result.HasVersions = len(result.Versions) > 0

	return result
}
