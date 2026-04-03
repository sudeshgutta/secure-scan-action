package rules

import (
	"encoding/json"
	"testing"
)

func TestBuildJavaScriptRule(t *testing.T) {
	pkg := "express"
	ruleJSON, err := BuildJavaScriptRule(pkg)

	if err != nil {
		t.Fatalf("BuildJavaScriptRule() error = %v", err)
	}

	// Parse the JSON to verify structure
	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	// Verify rule structure
	expectedID := "detect-vuln-express"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}

	if rule.Language != "JavaScript" {
		t.Errorf("Expected Language to be 'JavaScript', got '%s'", rule.Language)
	}

	// Verify rule contains "any" array with 2 patterns
	ruleMap, ok := rule.Rule.(map[string]interface{})
	if !ok {
		t.Fatal("Expected rule to be a map")
	}

	anyArray, ok := ruleMap["any"].([]interface{})
	if !ok {
		t.Fatal("Expected 'any' to be an array")
	}

	if len(anyArray) != 2 {
		t.Errorf("Expected 'any' array to have 2 patterns, got %d", len(anyArray))
	}
}

func TestBuildJavaScriptRule_WithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{
			name:     "scoped package",
			pkg:      "@angular/core",
			expected: "detect-vuln-angular-core",
		},
		{
			name:     "package with slashes",
			pkg:      "lodash/map",
			expected: "detect-vuln-lodash-map",
		},
		{
			name:     "package with dots",
			pkg:      "lib.module",
			expected: "detect-vuln-lib-module",
		},
		{
			name:     "package with both slashes and dots",
			pkg:      "@scope/lib.module",
			expected: "detect-vuln-scope-lib-module",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON, err := BuildJavaScriptRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildJavaScriptRule() error = %v", err)
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

func TestBuildTypeScriptRule(t *testing.T) {
	pkg := "typescript"
	ruleJSON, err := BuildTypeScriptRule(pkg)

	if err != nil {
		t.Fatalf("BuildTypeScriptRule() error = %v", err)
	}

	// Parse the JSON to verify structure
	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	// Verify TypeScript language
	if rule.Language != "TypeScript" {
		t.Errorf("Expected Language to be 'TypeScript', got '%s'", rule.Language)
	}

	// Verify rule contains "any" array with 2 patterns (same as JS)
	ruleMap, ok := rule.Rule.(map[string]interface{})
	if !ok {
		t.Fatal("Expected rule to be a map")
	}

	anyArray, ok := ruleMap["any"].([]interface{})
	if !ok {
		t.Fatal("Expected 'any' to be an array")
	}

	if len(anyArray) != 2 {
		t.Errorf("Expected 'any' array to have 2 patterns, got %d", len(anyArray))
	}

	expectedID := "detect-vuln-typescript"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}
}

func TestBuildJavaScriptRule_EmptyPackage(t *testing.T) {
	pkg := ""
	ruleJSON, err := BuildJavaScriptRule(pkg)

	if err != nil {
		t.Fatalf("BuildJavaScriptRule() error = %v", err)
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

func TestBuildJavaScriptRule_JSONValidity(t *testing.T) {
	pkg := "express"
	ruleJSON, err := BuildJavaScriptRule(pkg)

	if err != nil {
		t.Fatalf("BuildJavaScriptRule() error = %v", err)
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
