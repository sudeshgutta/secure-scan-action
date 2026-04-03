package trivy

import (
	"encoding/json"
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

func TestResult_WithType(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		expected string
	}{
		{
			name:     "empty type",
			jsonData: `{"Type":""}`,
			expected: "",
		},
		{
			name:     "gomod type",
			jsonData: `{"Type":"gomod"}`,
			expected: "gomod",
		},
		{
			name:     "npm type",
			jsonData: `{"Type":"npm"}`,
			expected: "npm",
		},
		{
			name:     "pip type",
			jsonData: `{"Type":"pip"}`,
			expected: "pip",
		},
		{
			name:     "pom type",
			jsonData: `{"Type":"pom"}`,
			expected: "pom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result Result
			if err := json.Unmarshal([]byte(tt.jsonData), &result); err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			if result.Type != tt.expected {
				t.Errorf("Expected Type to be '%s', got '%s'", tt.expected, result.Type)
			}
		})
	}
}
