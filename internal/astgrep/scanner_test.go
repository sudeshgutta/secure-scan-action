package astgrep

import (
	"context"
	"testing"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func TestExtractVulnerablePackages(t *testing.T) {
	tests := []struct {
		name     string
		report   trivy.TrivyReport
		expected map[string][]string
	}{
		{
			name: "empty report",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{},
			},
			expected: map[string][]string{},
		},
		{
			name: "report with vulnerabilities",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Type: "gomod",
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: "vulnerable-pkg1"},
							{PkgName: "vulnerable-pkg2"},
						},
					},
					{
						Type: "gomod",
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: "vulnerable-pkg3"},
							{PkgName: "vulnerable-pkg1"}, // duplicate
						},
					},
				},
			},
			expected: map[string][]string{
				"vulnerable-pkg1": {"Go"},
				"vulnerable-pkg2": {"Go"},
				"vulnerable-pkg3": {"Go"},
			},
		},
		{
			name: "report with empty vulnerabilities",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Type: "gomod",
						Vulnerabilities: []*trivy.Vulnerability{},
					},
				},
			},
			expected: map[string][]string{},
		},
		{
			name: "report with empty package names",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Type: "gomod",
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: ""},
							{PkgName: "valid-pkg"},
						},
					},
				},
			},
			expected: map[string][]string{
				"valid-pkg": {"Go"},
			},
		},
		{
			name: "report with unsupported ecosystem type",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Type: "rubygems",
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: "rack"},
						},
					},
				},
			},
			expected: map[string][]string{},
		},
		{
			name: "report with npm ecosystem",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Type: "npm",
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: "lodash"},
						},
					},
				},
			},
			expected: map[string][]string{
				"lodash": {"JavaScript", "TypeScript"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVulnerablePackages(tt.report)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d packages, got %d", len(tt.expected), len(result))
			}

			for pkg, expectedLangs := range tt.expected {
				resultLangs, exists := result[pkg]
				if !exists {
					t.Errorf("Expected package '%s' to be in result", pkg)
					continue
				}

				if len(resultLangs) != len(expectedLangs) {
					t.Errorf("For package '%s': expected %d languages, got %d", pkg, len(expectedLangs), len(resultLangs))
					continue
				}

				// Check if languages match (order may differ)
				langMap := make(map[string]bool)
				for _, lang := range resultLangs {
					langMap[lang] = true
				}

				for _, expectedLang := range expectedLangs {
					if !langMap[expectedLang] {
						t.Errorf("For package '%s': expected language '%s' not found", pkg, expectedLang)
					}
				}
			}

			for pkg := range result {
				if _, exists := tt.expected[pkg]; !exists {
					t.Errorf("Unexpected package '%s' in result", pkg)
				}
			}
		})
	}
}

func TestProcessTrivyReport_EmptyReport(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx := context.Background()
	report := trivy.TrivyReport{
		Results: []*trivy.Result{},
	}

	findings := ProcessTrivyReport(ctx, report)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty report, got %d", len(findings))
	}
}

func TestProcessTrivyReport_WithVulnerabilities(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx := context.Background()
	report := trivy.TrivyReport{
		Results: []*trivy.Result{
			{
				Type: "gomod",
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package"},
				},
			},
		},
	}

	// This test will likely fail if ast-grep is not available,
	// but we can test the structure and error handling
	findings := ProcessTrivyReport(ctx, report)

	// The exact behavior depends on whether ast-grep is available
	// We just verify that the function doesn't panic and returns a slice
	if findings == nil {
		t.Error("Expected findings to be a slice, got nil")
	}
}

func TestProcessTrivyReport_WithCancelledContext(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	report := trivy.TrivyReport{
		Results: []*trivy.Result{
			{
				Type: "gomod",
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package"},
				},
			},
		},
	}

	findings := ProcessTrivyReport(ctx, report)

	// Should handle cancelled context gracefully
	// When context is cancelled, scanWithASTGrep fails and we get an empty slice
	if findings == nil {
		t.Error("Expected findings to be a slice, got nil")
	}

	// With cancelled context, we should get an empty slice since scanWithASTGrep fails
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings with cancelled context, got %d", len(findings))
	}
}

func TestProcessTrivyReport_WithTimeout(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	report := trivy.TrivyReport{
		Results: []*trivy.Result{
			{
				Type: "gomod",
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package"},
				},
			},
		},
	}

	findings := ProcessTrivyReport(ctx, report)

	// Should handle timeout gracefully
	// With timeout, scanWithASTGrep fails and we get an empty slice
	if findings == nil {
		t.Error("Expected findings to be a slice, got nil")
	}

	// With timeout, we should get an empty slice since scanWithASTGrep fails
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings with timeout, got %d", len(findings))
	}
}

// TestScanWithASTGrep tests the scanWithASTGrep function
// This test will likely fail if ast-grep is not available,
// but we can test the timeout and error handling
func TestScanWithASTGrep_WithTimeout(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err := scanWithASTGrep(ctx, "github.com/test/package", "Go")

	// Should timeout or fail due to missing ast-grep
	if err == nil {
		t.Error("Expected scanWithASTGrep to fail with timeout or missing ast-grep")
	}
}

func TestScanWithASTGrep_WithCancelledContext(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := scanWithASTGrep(ctx, "github.com/test/package", "Go")

	// Should fail due to cancelled context
	if err == nil {
		t.Error("Expected scanWithASTGrep to fail with cancelled context")
	}
}

// TestScanWithASTGrep_WithoutASTGrep tests behavior when ast-grep is not available
func TestScanWithASTGrep_WithoutASTGrep(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx := context.Background()

	// This test will fail if ast-grep is not available
	_, err := scanWithASTGrep(ctx, "github.com/test/package", "Go")

	// Should fail due to missing ast-grep command
	if err == nil {
		t.Skip("Skipping test because ast-grep is available")
	}
}

func TestProcessTrivyReport_MultiplePackages(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx := context.Background()
	report := trivy.TrivyReport{
		Results: []*trivy.Result{
			{
				Type: "gomod",
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package1"},
					{PkgName: "github.com/test/package2"},
					{PkgName: "github.com/test/package3"},
				},
			},
		},
	}

	findings := ProcessTrivyReport(ctx, report)

	// Should attempt to scan all packages
	// The exact number of findings depends on ast-grep availability
	if findings == nil {
		t.Error("Expected findings to be a slice, got nil")
	}
}

func TestProcessTrivyReport_DuplicatePackages(t *testing.T) {
	// Initialize logger for tests
	logger.Init()

	ctx := context.Background()
	report := trivy.TrivyReport{
		Results: []*trivy.Result{
			{
				Type: "gomod",
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package"},
				},
			},
			{
				Type: "gomod",
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package"}, // duplicate
				},
			},
		},
	}

	findings := ProcessTrivyReport(ctx, report)

	// Should only scan each unique package once
	// The exact number of findings depends on ast-grep availability
	if findings == nil {
		t.Error("Expected findings to be a slice, got nil")
	}
}
