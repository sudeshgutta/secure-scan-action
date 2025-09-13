package astgrep

import (
	"testing"
)

func TestASTGrepMatch_GetPackageName(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected string
	}{
		{
			name:     "simple package name",
			text:     "github.com/example/package",
			expected: "github.com/example/package",
		},
		{
			name:     "package name with quotes",
			text:     "\"github.com/example/package\"",
			expected: "github.com/example/package",
		},
		{
			name:     "package name with whitespace",
			text:     "  github.com/example/package  ",
			expected: "github.com/example/package",
		},
		{
			name:     "package name with tabs and newlines",
			text:     "\tgithub.com/example/package\n",
			expected: "github.com/example/package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := &ASTGrepMatch{Text: tt.text}
			result := match.GetPackageName()
			if result != tt.expected {
				t.Errorf("GetPackageName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestASTGrepMatch_GetVersion(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected string
	}{
		{
			name:     "package with v4 version",
			text:     "github.com/example/package/v4",
			expected: "v4",
		},
		{
			name:     "package with v5 version",
			text:     "github.com/example/package/v5",
			expected: "v5",
		},
		{
			name:     "package with v12 version",
			text:     "github.com/example/package/v12",
			expected: "v12",
		},
		{
			name:     "package without version",
			text:     "github.com/example/package",
			expected: "",
		},
		{
			name:     "package with non-numeric version",
			text:     "github.com/example/package/vbeta",
			expected: "",
		},
		{
			name:     "package with single v",
			text:     "github.com/example/package/v",
			expected: "",
		},
		{
			name:     "package with v0 version",
			text:     "github.com/example/package/v0",
			expected: "v0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := &ASTGrepMatch{Text: tt.text}
			result := match.GetVersion()
			if result != tt.expected {
				t.Errorf("GetVersion() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestASTGrepMatch_GetLocation(t *testing.T) {
	match := &ASTGrepMatch{
		File: "test.go",
		Range: Range{
			Start: Position{Line: 10, Column: 5},
		},
	}

	location := match.GetLocation()
	expected := Location{
		File:   "test.go",
		Line:   10,
		Column: 5,
	}

	if location != expected {
		t.Errorf("GetLocation() = %v, want %v", location, expected)
	}
}

func TestASTGrepMatch_GetLocationString(t *testing.T) {
	match := &ASTGrepMatch{
		File: "test.go",
		Range: Range{
			Start: Position{Line: 10, Column: 5},
		},
	}

	result := match.GetLocationString()
	expected := "test.go:10:5"

	if result != expected {
		t.Errorf("GetLocationString() = %v, want %v", result, expected)
	}
}

func TestASTGrepMatch_IsInFile(t *testing.T) {
	match := &ASTGrepMatch{File: "test.go"}

	if !match.IsInFile("test.go") {
		t.Error("Expected IsInFile('test.go') to return true")
	}

	if match.IsInFile("other.go") {
		t.Error("Expected IsInFile('other.go') to return false")
	}
}

func TestPackageDetectionResult_IsFound(t *testing.T) {
	tests := []struct {
		name     string
		result   PackageDetectionResult
		expected bool
	}{
		{
			name: "found with matches",
			result: PackageDetectionResult{
				Found:        true,
				TotalMatches: 5,
			},
			expected: true,
		},
		{
			name: "found but no matches",
			result: PackageDetectionResult{
				Found:        true,
				TotalMatches: 0,
			},
			expected: false,
		},
		{
			name: "not found",
			result: PackageDetectionResult{
				Found:        false,
				TotalMatches: 0,
			},
			expected: false,
		},
		{
			name: "not found but has matches",
			result: PackageDetectionResult{
				Found:        false,
				TotalMatches: 5,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result.IsFound()
			if result != tt.expected {
				t.Errorf("IsFound() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPackageDetectionResult_GetSummaryString(t *testing.T) {
	tests := []struct {
		name     string
		result   PackageDetectionResult
		expected string
	}{
		{
			name: "not found",
			result: PackageDetectionResult{
				PackageName: "test-package",
				Found:       false,
			},
			expected: "Package 'test-package' not found",
		},
		{
			name: "found once with location",
			result: PackageDetectionResult{
				PackageName:  "test-package",
				Found:        true,
				TotalMatches: 1,
				FirstMatch: &Location{
					File: "test.go",
					Line: 10,
				},
			},
			expected: "Package 'test-package' found in test.go at line 10",
		},
		{
			name: "found multiple times",
			result: PackageDetectionResult{
				PackageName:  "test-package",
				Found:        true,
				TotalMatches: 5,
				UniqueFiles:  []string{"file1.go", "file2.go"},
			},
			expected: "Package 'test-package' found 5 times across 2 files",
		},
		{
			name: "found once without location",
			result: PackageDetectionResult{
				PackageName:  "test-package",
				Found:        true,
				TotalMatches: 1,
				UniqueFiles:  []string{"file1.go"},
			},
			expected: "Package 'test-package' found 1 times across 1 files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result.GetSummaryString()
			if result != tt.expected {
				t.Errorf("GetSummaryString() = %v, want %v", result, tt.expected)
			}
		})
	}
}
