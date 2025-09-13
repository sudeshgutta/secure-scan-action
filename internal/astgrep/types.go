package astgrep

import (
	"fmt"
	"strings"
	"time"
)

// ASTGrepMatch represents a single match found by AST-Grep
type ASTGrepMatch struct {
	Text   string `json:"text"`
	Range  Range  `json:"range"`
	File   string `json:"file"`
	RuleId string `json:"ruleId"`
}

// Position represents a line/column position in source code
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Range represents the location of a match in source code
type Range struct {
	Start Position `json:"start"`
}

// Location represents a simple file location
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// GetPackageName extracts the clean package name from the match text
func (m *ASTGrepMatch) GetPackageName() string {
	return strings.Trim(m.Text, "\" \t\n")
}

// GetVersion extracts version from package path (e.g., "v4", "v5")
func (m *ASTGrepMatch) GetVersion() string {
	packageName := m.GetPackageName()
	parts := strings.Split(packageName, "/")

	for _, part := range parts {
		if isVersionPart(part) {
			return part
		}
	}
	return ""
}

// isVersionPart checks if a string part represents a version (e.g., "v4", "v5")
func isVersionPart(part string) bool {
	return strings.HasPrefix(part, "v") && len(part) > 1 && isDigit(part[1])
}

// isDigit checks if a character is a digit
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// GetLocation returns the file location of this match
func (m *ASTGrepMatch) GetLocation() Location {
	return Location{
		File:   m.File,
		Line:   m.Range.Start.Line,
		Column: m.Range.Start.Column,
	}
}

// GetLocationString returns a human-readable location string
func (m *ASTGrepMatch) GetLocationString() string {
	return fmt.Sprintf("%s:%d:%d", m.File, m.Range.Start.Line, m.Range.Start.Column)
}

// IsInFile checks if this match is in the specified file
func (m *ASTGrepMatch) IsInFile(filename string) bool {
	return m.File == filename
}

// PackageDetectionResult represents the result of package detection
type PackageDetectionResult struct {
	PackageName      string    `json:"packageName"`
	Found            bool      `json:"found"`
	TotalMatches     int       `json:"totalMatches"`
	UniqueFiles      []string  `json:"uniqueFiles"`
	Versions         []string  `json:"versions"`
	FirstMatch       *Location `json:"firstMatch,omitempty"`
	ScanTimestamp    time.Time `json:"scanTimestamp"`
	RuleId           string    `json:"ruleId"`
	HasMultipleFiles bool      `json:"hasMultipleFiles"`
	HasVersions      bool      `json:"hasVersions"`
}

func (r *PackageDetectionResult) IsFound() bool {
	return r.Found && r.TotalMatches > 0
}

func (r *PackageDetectionResult) GetSummaryString() string {
	if !r.Found {
		return fmt.Sprintf("Package '%s' not found", r.PackageName)
	}

	if r.TotalMatches == 1 && r.FirstMatch != nil {
		return fmt.Sprintf("Package '%s' found in %s at line %d",
			r.PackageName, r.FirstMatch.File, r.FirstMatch.Line)
	}

	return fmt.Sprintf("Package '%s' found %d times across %d files",
		r.PackageName, r.TotalMatches, len(r.UniqueFiles))
}
