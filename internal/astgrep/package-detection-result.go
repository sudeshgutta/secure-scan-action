package astgrep

import (
	"fmt"
	"time"
)

// PackageDetectionResult provides high-level analysis of package detection
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

// IsFound returns true if the package was found
func (r *PackageDetectionResult) IsFound() bool {
	return r.Found && r.TotalMatches > 0
}

// GetSummaryString returns a human-readable summary
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
