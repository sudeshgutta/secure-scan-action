package astgrep

import (
	"testing"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
)

func TestAnalyzePackageMatches_EmptyMatches(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{}
	pkg := "test-package"

	result := AnalyzePackageMatches(matches, pkg)

	if result.PackageName != pkg {
		t.Errorf("Expected PackageName to be '%s', got '%s'", pkg, result.PackageName)
	}

	if result.Found {
		t.Error("Expected Found to be false for empty matches")
	}

	if result.TotalMatches != 0 {
		t.Errorf("Expected TotalMatches to be 0, got %d", result.TotalMatches)
	}

	if len(result.UniqueFiles) != 0 {
		t.Errorf("Expected UniqueFiles to be empty, got %v", result.UniqueFiles)
	}

	if len(result.Versions) != 0 {
		t.Errorf("Expected Versions to be empty, got %v", result.Versions)
	}

	if result.FirstMatch != nil {
		t.Error("Expected FirstMatch to be nil for empty matches")
	}

	if result.HasMultipleFiles {
		t.Error("Expected HasMultipleFiles to be false for empty matches")
	}

	if result.HasVersions {
		t.Error("Expected HasVersions to be false for empty matches")
	}
}

func TestAnalyzePackageMatches_SingleMatch(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{
		{
			Text:   "github.com/test/package",
			File:   "test.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 10, Column: 5},
			},
		},
	}
	pkg := "github.com/test/package"

	result := AnalyzePackageMatches(matches, pkg)

	if result.PackageName != pkg {
		t.Errorf("Expected PackageName to be '%s', got '%s'", pkg, result.PackageName)
	}

	if !result.Found {
		t.Error("Expected Found to be true")
	}

	if result.TotalMatches != 1 {
		t.Errorf("Expected TotalMatches to be 1, got %d", result.TotalMatches)
	}

	if len(result.UniqueFiles) != 1 {
		t.Errorf("Expected UniqueFiles to have 1 file, got %d", len(result.UniqueFiles))
	}

	if result.UniqueFiles[0] != "test.go" {
		t.Errorf("Expected UniqueFiles[0] to be 'test.go', got '%s'", result.UniqueFiles[0])
	}

	if result.RuleId != "test-rule" {
		t.Errorf("Expected RuleId to be 'test-rule', got '%s'", result.RuleId)
	}

	if result.FirstMatch == nil {
		t.Error("Expected FirstMatch to be set")
	} else {
		if result.FirstMatch.File != "test.go" {
			t.Errorf("Expected FirstMatch.File to be 'test.go', got '%s'", result.FirstMatch.File)
		}
		if result.FirstMatch.Line != 10 {
			t.Errorf("Expected FirstMatch.Line to be 10, got %d", result.FirstMatch.Line)
		}
		if result.FirstMatch.Column != 5 {
			t.Errorf("Expected FirstMatch.Column to be 5, got %d", result.FirstMatch.Column)
		}
	}

	if result.HasMultipleFiles {
		t.Error("Expected HasMultipleFiles to be false for single file")
	}

	if result.HasVersions {
		t.Error("Expected HasVersions to be false for package without version")
	}
}

func TestAnalyzePackageMatches_MultipleMatches(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{
		{
			Text:   "github.com/test/package/v1",
			File:   "file1.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 10, Column: 5},
			},
		},
		{
			Text:   "github.com/test/package/v1",
			File:   "file2.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 20, Column: 10},
			},
		},
		{
			Text:   "github.com/test/package/v2",
			File:   "file1.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 30, Column: 15},
			},
		},
	}
	pkg := "github.com/test/package"

	result := AnalyzePackageMatches(matches, pkg)

	if result.PackageName != pkg {
		t.Errorf("Expected PackageName to be '%s', got '%s'", pkg, result.PackageName)
	}

	if !result.Found {
		t.Error("Expected Found to be true")
	}

	if result.TotalMatches != 3 {
		t.Errorf("Expected TotalMatches to be 3, got %d", result.TotalMatches)
	}

	if len(result.UniqueFiles) != 2 {
		t.Errorf("Expected UniqueFiles to have 2 files, got %d", len(result.UniqueFiles))
	}

	// Check that both files are present
	files := make(map[string]bool)
	for _, file := range result.UniqueFiles {
		files[file] = true
	}
	if !files["file1.go"] || !files["file2.go"] {
		t.Error("Expected both file1.go and file2.go to be in UniqueFiles")
	}

	if len(result.Versions) != 2 {
		t.Errorf("Expected Versions to have 2 versions, got %d", len(result.Versions))
	}

	// Check that both versions are present
	versions := make(map[string]bool)
	for _, version := range result.Versions {
		versions[version] = true
	}
	if !versions["v1"] || !versions["v2"] {
		t.Error("Expected both v1 and v2 to be in Versions")
	}

	if !result.HasMultipleFiles {
		t.Error("Expected HasMultipleFiles to be true for multiple files")
	}

	if !result.HasVersions {
		t.Error("Expected HasVersions to be true for packages with versions")
	}
}

func TestAnalyzePackageMatches_PackageNameMismatch(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{
		{
			Text:   "github.com/other/package",
			File:   "test.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 10, Column: 5},
			},
		},
	}
	pkg := "github.com/test/package"

	result := AnalyzePackageMatches(matches, pkg)

	if result.PackageName != pkg {
		t.Errorf("Expected PackageName to be '%s', got '%s'", pkg, result.PackageName)
	}

	if result.Found {
		t.Error("Expected Found to be false for package name mismatch")
	}

	if result.TotalMatches != 0 {
		t.Errorf("Expected TotalMatches to be 0, got %d", result.TotalMatches)
	}

	if len(result.UniqueFiles) != 0 {
		t.Errorf("Expected UniqueFiles to be empty, got %v", result.UniqueFiles)
	}

	if len(result.Versions) != 0 {
		t.Errorf("Expected Versions to be empty, got %v", result.Versions)
	}
}

func TestAnalyzePackageMatches_PartialPackageNameMatch(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{
		{
			Text:   "github.com/test/package/subpackage",
			File:   "test.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 10, Column: 5},
			},
		},
	}
	pkg := "github.com/test/package"

	result := AnalyzePackageMatches(matches, pkg)

	if result.PackageName != pkg {
		t.Errorf("Expected PackageName to be '%s', got '%s'", pkg, result.PackageName)
	}

	if !result.Found {
		t.Error("Expected Found to be true for partial package name match")
	}

	if result.TotalMatches != 1 {
		t.Errorf("Expected TotalMatches to be 1, got %d", result.TotalMatches)
	}
}

func TestAnalyzePackageMatches_ScanTimestamp(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{
		{
			Text:   "github.com/test/package",
			File:   "test.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 10, Column: 5},
			},
		},
	}
	pkg := "github.com/test/package"

	before := time.Now()
	result := AnalyzePackageMatches(matches, pkg)
	after := time.Now()

	if result.ScanTimestamp.Before(before) || result.ScanTimestamp.After(after) {
		t.Error("Expected ScanTimestamp to be set to current time")
	}
}

func TestAnalyzePackageMatches_EmptyVersions(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	matches := []ASTGrepMatch{
		{
			Text:   "github.com/test/package",
			File:   "test.go",
			RuleId: "test-rule",
			Range: Range{
				Start: Position{Line: 10, Column: 5},
			},
		},
	}
	pkg := "github.com/test/package"

	result := AnalyzePackageMatches(matches, pkg)

	if result.HasVersions {
		t.Error("Expected HasVersions to be false for package without version")
	}

	if len(result.Versions) != 0 {
		t.Errorf("Expected Versions to be empty, got %v", result.Versions)
	}
}
