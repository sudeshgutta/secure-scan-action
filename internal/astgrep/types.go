package astgrep

import (
	"fmt"
	"strings"
	"time"
)

// ASTGrepMatch represents a single match found by AST-Grep.
type ASTGrepMatch struct {
	Text   string `json:"text"`
	Range  Range  `json:"range"`
	File   string `json:"file"`
	RuleId string `json:"ruleId"`
}

// Position represents a line/column position in source code.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Range represents the location of a match in source code.
type Range struct {
	Start Position `json:"start"`
}

// Location represents a simple file location.
type Location struct {
	File   string
	Line   int
	Column int
}

func (m *ASTGrepMatch) GetPackageName() string {
	return strings.Trim(m.Text, "\" \t\n")
}

func (m *ASTGrepMatch) GetVersion() string {
	for _, part := range strings.Split(m.GetPackageName(), "/") {
		if len(part) > 1 && part[0] == 'v' && part[1] >= '0' && part[1] <= '9' {
			return part
		}
	}
	return ""
}

func (m *ASTGrepMatch) GetLocation() Location {
	return Location{File: m.File, Line: m.Range.Start.Line, Column: m.Range.Start.Column}
}

// PackageDetectionResult represents the result of package detection.
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
