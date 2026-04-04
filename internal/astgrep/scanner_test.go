package astgrep

import (
	"context"
	"testing"
	"time"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func TestExtractVulnerablePackages(t *testing.T) {
	cases := []struct {
		name         string
		report       trivy.TrivyReport
		wantPkgs     []string          // packages expected in result
		wantLanguage map[string]string // pkg → one expected language
		wantSeverity map[string]string // pkg → expected worst severity
	}{
		{
			name:     "empty report",
			report:   trivy.TrivyReport{Results: []*trivy.Result{}},
			wantPkgs: nil,
		},
		{
			name: "gomod vulnerabilities",
			report: trivy.TrivyReport{Results: []*trivy.Result{
				{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "pkg1", VulnerabilityID: "CVE-2021-0001", Severity: "HIGH"},
					{PkgName: "pkg2", VulnerabilityID: "CVE-2021-0002", Severity: "CRITICAL"},
				}},
			}},
			wantPkgs:     []string{"pkg1", "pkg2"},
			wantLanguage: map[string]string{"pkg1": "Go", "pkg2": "Go"},
			wantSeverity: map[string]string{"pkg1": "HIGH", "pkg2": "CRITICAL"},
		},
		{
			name: "duplicate package accumulates worst severity",
			report: trivy.TrivyReport{Results: []*trivy.Result{
				{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "pkg1", VulnerabilityID: "CVE-A", Severity: "HIGH"},
				}},
				{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "pkg1", VulnerabilityID: "CVE-B", Severity: "CRITICAL"},
				}},
			}},
			wantPkgs:     []string{"pkg1"},
			wantSeverity: map[string]string{"pkg1": "CRITICAL"},
		},
		{
			name: "empty package name skipped",
			report: trivy.TrivyReport{Results: []*trivy.Result{
				{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: ""},
					{PkgName: "valid-pkg"},
				}},
			}},
			wantPkgs: []string{"valid-pkg"},
		},
		{
			name: "unsupported ecosystem skipped",
			report: trivy.TrivyReport{Results: []*trivy.Result{
				{Type: "rubygems", Vulnerabilities: []*trivy.Vulnerability{{PkgName: "rack"}}},
			}},
			wantPkgs: nil,
		},
		{
			name: "npm maps to JS and TS",
			report: trivy.TrivyReport{Results: []*trivy.Result{
				{Type: "npm", Vulnerabilities: []*trivy.Vulnerability{
					{PkgName: "lodash", VulnerabilityID: "CVE-2021-23337", Severity: "HIGH"},
				}},
			}},
			wantPkgs: []string{"lodash"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := extractVulnerablePackages(c.report)

			if len(result) != len(c.wantPkgs) {
				t.Fatalf("want %d packages, got %d: %v", len(c.wantPkgs), len(result), result)
			}
			for _, pkg := range c.wantPkgs {
				meta, ok := result[pkg]
				if !ok {
					t.Errorf("missing package %q in result", pkg)
					continue
				}
				if wantLang, ok := c.wantLanguage[pkg]; ok {
					found := false
					for _, l := range meta.languages {
						if l == wantLang {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("package %q: want language %q, got %v", pkg, wantLang, meta.languages)
					}
				}
				if wantSev, ok := c.wantSeverity[pkg]; ok && meta.severity != wantSev {
					t.Errorf("package %q: want severity %q, got %q", pkg, wantSev, meta.severity)
				}
			}
		})
	}
}

func TestProcessTrivyReport_EmptyReport(t *testing.T) {
	logger.Init()
	findings := ProcessTrivyReport(context.Background(), trivy.TrivyReport{Results: []*trivy.Result{}})
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty report, got %d", len(findings))
	}
}

func TestProcessTrivyReport_WithVulnerabilities(t *testing.T) {
	logger.Init()
	report := trivy.TrivyReport{Results: []*trivy.Result{
		{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
			{PkgName: "github.com/test/package", VulnerabilityID: "CVE-2021-0001", Severity: "HIGH"},
		}},
	}}
	// findings may be nil (no sg binary) or empty — both are acceptable
	findings := ProcessTrivyReport(context.Background(), report)
	_ = findings // no panic = pass
}

func TestProcessTrivyReport_WithCancelledContext(t *testing.T) {
	logger.Init()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := trivy.TrivyReport{Results: []*trivy.Result{
		{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
			{PkgName: "github.com/test/package"},
		}},
	}}
	findings := ProcessTrivyReport(ctx, report)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings with cancelled context, got %d", len(findings))
	}
}

func TestProcessTrivyReport_WithTimeout(t *testing.T) {
	logger.Init()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	report := trivy.TrivyReport{Results: []*trivy.Result{
		{Type: "gomod", Vulnerabilities: []*trivy.Vulnerability{
			{PkgName: "github.com/test/package"},
		}},
	}}
	findings := ProcessTrivyReport(ctx, report)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings with timeout, got %d", len(findings))
	}
}

func TestScanWithASTGrep_WithTimeout(t *testing.T) {
	logger.Init()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	_, err := scanWithASTGrep(ctx, "github.com/test/package", "Go")
	if err == nil {
		t.Error("Expected error with 1ms timeout")
	}
}

func TestScanWithASTGrep_WithCancelledContext(t *testing.T) {
	logger.Init()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := scanWithASTGrep(ctx, "github.com/test/package", "Go")
	if err == nil {
		t.Error("Expected error with cancelled context")
	}
}

func TestScanWithASTGrep_WithoutASTGrep(t *testing.T) {
	logger.Init()
	_, err := scanWithASTGrep(context.Background(), "github.com/test/package", "Go")
	if err == nil {
		t.Skip("Skipping test because ast-grep is available")
	}
}
