package rules

import (
	"encoding/json"
	"testing"
)

func TestBuildJavaRule(t *testing.T) {
	pkg := "org.apache.logging.log4j:log4j-core"
	ruleJSON, err := BuildJavaRule(pkg)

	if err != nil {
		t.Fatalf("BuildJavaRule() error = %v", err)
	}

	// Parse the JSON to verify structure
	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	// Verify rule structure
	expectedID := "detect-vuln-org-apache-logging-log4j-log4j-core"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}

	if rule.Language != "Java" {
		t.Errorf("Expected Language to be 'Java', got '%s'", rule.Language)
	}

	// Verify rule content
	importSpecRule, ok := rule.Rule.(map[string]interface{})
	if !ok {
		t.Fatal("Expected rule to be a map")
	}

	if importSpecRule["kind"] != "import_declaration" {
		t.Errorf("Expected kind to be 'import_declaration', got '%v'", importSpecRule["kind"])
	}

	has, ok := importSpecRule["has"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'has' to be a map")
	}

	expectedRegex := "org\\.apache\\.logging\\.log4j"
	if has["regex"] != expectedRegex {
		t.Errorf("Expected regex to be '%s', got '%v'", expectedRegex, has["regex"])
	}
}

func TestBuildJavaRule_MavenFormat(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expectedID string
		expectedRegex string
	}{
		{
			name:     "Maven package with groupId and artifactId",
			pkg:      "org.apache.logging.log4j:log4j-core",
			expectedID: "detect-vuln-org-apache-logging-log4j-log4j-core",
			expectedRegex: "org\\.apache\\.logging\\.log4j",
		},
		{
			name:     "Google Guava Maven package",
			pkg:      "com.google.guava:guava",
			expectedID: "detect-vuln-com-google-guava-guava",
			expectedRegex: "com\\.google\\.guava",
		},
		{
			name:     "Spring Framework package",
			pkg:      "org.springframework:spring-core",
			expectedID: "detect-vuln-org-springframework-spring-core",
			expectedRegex: "org\\.springframework",
		},
		{
			name:     "Plain package without colon",
			pkg:      "com.example",
			expectedID: "detect-vuln-com-example",
			expectedRegex: "com\\.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON, err := BuildJavaRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildJavaRule() error = %v", err)
			}

			var rule ASTGrepRule
			if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
				t.Fatalf("Failed to unmarshal rule JSON: %v", err)
			}

			if rule.ID != tt.expectedID {
				t.Errorf("Expected ID to be '%s', got '%s'", tt.expectedID, rule.ID)
			}

			importSpecRule, ok := rule.Rule.(map[string]interface{})
			if !ok {
				t.Fatal("Expected rule to be a map")
			}

			has, ok := importSpecRule["has"].(map[string]interface{})
			if !ok {
				t.Fatal("Expected 'has' to be a map")
			}

			if has["regex"] != tt.expectedRegex {
				t.Errorf("Expected regex to be '%s', got '%v'", tt.expectedRegex, has["regex"])
			}
		})
	}
}

func TestBuildJavaRule_EmptyPackage(t *testing.T) {
	pkg := ""
	ruleJSON, err := BuildJavaRule(pkg)

	if err != nil {
		t.Fatalf("BuildJavaRule() error = %v", err)
	}

	var rule ASTGrepRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		t.Fatalf("Failed to unmarshal rule JSON: %v", err)
	}

	expectedID := "detect-vuln-"
	if rule.ID != expectedID {
		t.Errorf("Expected ID to be '%s', got '%s'", expectedID, rule.ID)
	}

	if rule.Language != "Java" {
		t.Errorf("Expected Language to be 'Java', got '%s'", rule.Language)
	}
}

func TestBuildJavaRule_JSONValidity(t *testing.T) {
	pkg := "org.apache.logging.log4j:log4j-core"
	ruleJSON, err := BuildJavaRule(pkg)

	if err != nil {
		t.Fatalf("BuildJavaRule() error = %v", err)
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
