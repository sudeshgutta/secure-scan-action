package rules

import (
	"encoding/json"
	"testing"
)

func TestBuildRule(t *testing.T) {
	pkg := "github.com/test/package"
	ruleJSON, err := BuildRule(pkg)

	if err != nil {
		t.Fatalf("BuildRule() error = %v", err)
	}

	// Parse the JSON to verify structure
	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	// Verify rule structure
	expectedID := "detect-vuln-github-com-test-package"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}

	if rule.Language != "go" {
		t.Errorf("Expected Language to be 'go', got '%s'", rule.Language)
	}

	// Verify rule content
	importSpecRule, ok := rule.Rule.(map[string]interface{})
	if !ok {
		t.Fatal("Expected rule to be a map")
	}

	if importSpecRule["kind"] != "import_spec" {
		t.Errorf("Expected kind to be 'import_spec', got '%v'", importSpecRule["kind"])
	}

	has, ok := importSpecRule["has"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'has' to be a map")
	}

	if has["regex"] != pkg {
		t.Errorf("Expected regex to be '%s', got '%v'", pkg, has["regex"])
	}
}

func TestBuildRule_WithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{
			name:     "package with slashes",
			pkg:      "github.com/test/package",
			expected: "detect-vuln-github-com-test-package",
		},
		{
			name:     "package with dots",
			pkg:      "github.com/test.package",
			expected: "detect-vuln-github-com-test-package",
		},
		{
			name:     "package with both slashes and dots",
			pkg:      "github.com/test.package/v1",
			expected: "detect-vuln-github-com-test-package-v1",
		},
		{
			name:     "package with multiple dots",
			pkg:      "github.com/test.package.subpackage",
			expected: "detect-vuln-github-com-test-package-subpackage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON, err := BuildRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildRule() error = %v", err)
			}

			var rule ASTGrepRule
			if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
				t.Fatalf("Failed to unmarshal rule JSON: %v", err)
			}

			if rule.ID != tt.expected {
				t.Errorf("Expected ID to be '%s', got '%s'", tt.expected, rule.ID)
			}
		})
	}
}

func TestBuildRule_EmptyPackage(t *testing.T) {
	pkg := ""
	ruleJSON, err := BuildRule(pkg)

	if err != nil {
		t.Fatalf("BuildRule() error = %v", err)
	}

	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	expectedID := "detect-vuln-"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}
}

func TestBuildRule_JSONValidity(t *testing.T) {
	pkg := "github.com/test/package"
	ruleJSON, err := BuildRule(pkg)

	if err != nil {
		t.Fatalf("BuildRule() error = %v", err)
	}

	// Verify that the JSON is valid
	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Generated JSON is invalid: %v", err)
	}

	// Verify that we can marshal it back to the same JSON
	expectedJSON, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("Failed to marshal rule back to JSON: %v", err)
	}

	// The JSON should be equivalent (order might differ, but content should be same)
	var originalRule, expectedRule ASTGrepRule
	json.Unmarshal([]byte(ruleJSON), &originalRule)
	json.Unmarshal(expectedJSON, &expectedRule)

	if originalRule.ID != expectedRule.ID {
		t.Error("Rule ID mismatch after round-trip JSON conversion")
	}

	if originalRule.Language != expectedRule.Language {
		t.Error("Rule Language mismatch after round-trip JSON conversion")
	}
}
