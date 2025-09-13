package trivy

import (
	"testing"
)

func TestTrivyReport(t *testing.T) {
	report := TrivyReport{
		Results: []*Result{
			{
				Vulnerabilities: []*Vulnerability{
					{PkgName: "test-package"},
					{PkgName: "another-package"},
				},
			},
		},
	}

	if len(report.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(report.Results))
	}

	if len(report.Results[0].Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(report.Results[0].Vulnerabilities))
	}

	if report.Results[0].Vulnerabilities[0].PkgName != "test-package" {
		t.Errorf("Expected first vulnerability to be 'test-package', got '%s'", report.Results[0].Vulnerabilities[0].PkgName)
	}
}
