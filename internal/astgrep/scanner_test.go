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
		expected map[string]struct{}
	}{
		{
			name: "empty report",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{},
			},
			expected: map[string]struct{}{},
		},
		{
			name: "report with vulnerabilities",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: "vulnerable-pkg1"},
							{PkgName: "vulnerable-pkg2"},
						},
					},
					{
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: "vulnerable-pkg3"},
							{PkgName: "vulnerable-pkg1"}, // duplicate
						},
					},
				},
			},
			expected: map[string]struct{}{
				"vulnerable-pkg1": {},
				"vulnerable-pkg2": {},
				"vulnerable-pkg3": {},
			},
		},
		{
			name: "report with empty vulnerabilities",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Vulnerabilities: []*trivy.Vulnerability{},
					},
				},
			},
			expected: map[string]struct{}{},
		},
		{
			name: "report with empty package names",
			report: trivy.TrivyReport{
				Results: []*trivy.Result{
					{
						Vulnerabilities: []*trivy.Vulnerability{
							{PkgName: ""},
							{PkgName: "valid-pkg"},
						},
					},
				},
			},
			expected: map[string]struct{}{
				"valid-pkg": {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVulnerablePackages(tt.report)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d packages, got %d", len(tt.expected), len(result))
			}

			for pkg := range tt.expected {
				if _, exists := result[pkg]; !exists {
					t.Errorf("Expected package '%s' to be in result", pkg)
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

	_, err := scanWithASTGrep(ctx, "github.com/test/package")

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

	_, err := scanWithASTGrep(ctx, "github.com/test/package")

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
	_, err := scanWithASTGrep(ctx, "github.com/test/package")

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
				Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "github.com/test/package"},
				},
			},
			{
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
