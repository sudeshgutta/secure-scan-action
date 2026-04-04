package rules

import (
	"strings"
	"testing"
)

func TestBuildPythonRule(t *testing.T) {
	pkg := "requests"
	ruleYAML, err := BuildPythonRule(pkg)
	if err != nil {
		t.Fatalf("BuildPythonRule() error = %v", err)
	}

	checks := []struct {
		desc string
		want string
	}{
		{"contains expected id", "id: detect-vuln-requests"},
		{"contains Python language", "language: Python"},
		{"contains error severity", "severity: error"},
		{"contains message", "message:"},
		{"contains import_statement", "import_statement"},
		{"contains import_from_statement", "import_from_statement"},
		{"contains escaped regex", `regex: "requests"`},
	}
	for _, c := range checks {
		t.Run(c.desc, func(t *testing.T) {
			if !strings.Contains(ruleYAML, c.want) {
				t.Errorf("expected YAML to contain %q\ngot:\n%s", c.want, ruleYAML)
			}
		})
	}
}

func TestBuildPythonRule_WithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name       string
		pkg        string
		expectedID string
	}{
		{"package with hyphens", "scikit-learn", "detect-vuln-scikit-learn"},
		{"package with dots", "google.cloud", "detect-vuln-google-cloud"},
		{"simple package", "numpy", "detect-vuln-numpy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleYAML, err := BuildPythonRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildPythonRule() error = %v", err)
			}
			if !strings.Contains(ruleYAML, "id: "+tt.expectedID) {
				t.Errorf("expected id %q in:\n%s", tt.expectedID, ruleYAML)
			}
		})
	}
}

func TestBuildPythonRule_EmptyPackage(t *testing.T) {
	ruleYAML, err := BuildPythonRule("")
	if err != nil {
		t.Fatalf("BuildPythonRule() error = %v", err)
	}
	if !strings.Contains(ruleYAML, "id: detect-vuln-") {
		t.Errorf("expected id prefix in:\n%s", ruleYAML)
	}
}

func TestBuildPythonRule_YAMLValidity(t *testing.T) {
	pkg := "requests"
	ruleYAML, err := BuildPythonRule(pkg)
	if err != nil {
		t.Fatalf("BuildPythonRule() error = %v", err)
	}
	// Verify all required YAML keys are present
	for _, key := range []string{"id:", "language:", "severity:", "message:", "rule:"} {
		if !strings.Contains(ruleYAML, key) {
			t.Errorf("missing required YAML key %q in:\n%s", key, ruleYAML)
		}
	}
}
