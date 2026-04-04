package astgrep

import (
	"fmt"
	"strings"
	"time"
)

// ReachabilityScore indicates how widely a vulnerable package is used in non-test source files.
type ReachabilityScore int

const (
	ReachabilityLow    ReachabilityScore = 1 // imported only in test files
	ReachabilityMedium ReachabilityScore = 2 // 1-2 non-test source files
	ReachabilityHigh   ReachabilityScore = 3 // 3+ non-test source files
)

func (r ReachabilityScore) String() string {
	switch r {
	case ReachabilityLow:
		return "LOW"
	case ReachabilityMedium:
		return "MEDIUM"
	case ReachabilityHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// isTestFile returns true if the file path looks like a test file across supported languages.
func isTestFile(path string) bool {
	base := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		base = path[i+1:]
	}
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasPrefix(base, "test_") ||
		strings.HasSuffix(base, "_test.py") ||
		strings.HasSuffix(base, "Test.java") ||
		(strings.HasPrefix(base, "Test") && strings.HasSuffix(base, ".java"))
}

// computeReachability scores how reachable a package is based on how many
// non-test source files import it.
func computeReachability(files []string) ReachabilityScore {
	count := 0
	for _, f := range files {
		if !isTestFile(f) {
			count++
		}
	}
	switch {
	case count == 0:
		return ReachabilityLow
	case count <= 2:
		return ReachabilityMedium
	default:
		return ReachabilityHigh
	}
}

// Finding is an enriched scan result combining CVE metadata with AST-Grep detection.
type Finding struct {
	Package           string
	Language          string
	CVEIDs            []string
	Severity          string // worst severity across all CVEs for this package
	DetectionResult   *PackageDetectionResult
	ReachabilityScore ReachabilityScore
}

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
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
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
