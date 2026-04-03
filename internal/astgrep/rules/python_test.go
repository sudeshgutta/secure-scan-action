package rules

import (
	"encoding/json"
	"testing"
)

func TestBuildPythonRule(t *testing.T) {
	pkg := "requests"
	ruleJSON, err := BuildPythonRule(pkg)

	if err != nil {
		t.Fatalf("BuildPythonRule() error = %v", err)
	}

	// Parse the JSON to verify structure
	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	// Verify rule structure
	expectedID := "detect-vuln-requests"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}

	if rule.Language != "Python" {
		t.Errorf("Expected Language to be 'Python', got '%s'", rule.Language)
	}

	// Verify rule content
	anyRule, ok := rule.Rule.(map[string]interface{})
	if !ok {
		t.Fatal("Expected rule to be a map")
	}

	anyArray, ok := anyRule["any"].([]interface{})
	if !ok {
		t.Fatal("Expected 'any' to be an array")
	}

	if len(anyArray) != 2 {
		t.Errorf("Expected 'any' array to have 2 patterns, got %d", len(anyArray))
	}

	// Verify first pattern (import_statement)
	pattern1, ok := anyArray[0].(map[string]interface{})
	if !ok {
		t.Fatal("Expected first pattern to be a map")
	}

	if pattern1["kind"] != "import_statement" {
		t.Errorf("Expected first pattern kind to be 'import_statement', got '%v'", pattern1["kind"])
	}

	// Verify second pattern (import_from_statement)
	pattern2, ok := anyArray[1].(map[string]interface{})
	if !ok {
		t.Fatal("Expected second pattern to be a map")
	}

	if pattern2["kind"] != "import_from_statement" {
		t.Errorf("Expected second pattern kind to be 'import_from_statement', got '%v'", pattern2["kind"])
	}
}

func TestBuildPythonRule_WithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{
			name:     "package with hyphens",
			pkg:      "scikit-learn",
			expected: "detect-vuln-scikit-learn",
		},
		{
			name:     "package with dots",
			pkg:      "google.cloud",
			expected: "detect-vuln-google-cloud",
		},
		{
			name:     "package with hyphens and dots",
			pkg:      "scikit-learn.dev",
			expected: "detect-vuln-scikit-learn-dev",
		},
		{
			name:     "simple package name",
			pkg:      "numpy",
			expected: "detect-vuln-numpy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON, err := BuildPythonRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildPythonRule() error = %v", err)
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

func TestBuildPythonRule_EmptyPackage(t *testing.T) {
	pkg := ""
	ruleJSON, err := BuildPythonRule(pkg)

	if err != nil {
		t.Fatalf("BuildPythonRule() error = %v", err)
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

func TestBuildPythonRule_JSONValidity(t *testing.T) {
	pkg := "requests"
	ruleJSON, err := BuildPythonRule(pkg)

	if err != nil {
		t.Fatalf("BuildPythonRule() error = %v", err)
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
