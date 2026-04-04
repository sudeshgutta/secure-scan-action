package rules

import (
	"strings"
	"testing"
)

func TestBuildJavaRule(t *testing.T) {
	pkg := "org.apache.logging.log4j:log4j-core"
	ruleYAML, err := BuildJavaRule(pkg)
	if err != nil {
		t.Fatalf("BuildJavaRule() error = %v", err)
	}

	checks := []struct {
		desc string
		want string
	}{
		{"contains expected id", "id: detect-vuln-org-apache-logging-log4j-log4j-core"},
		{"contains Java language", "language: Java"},
		{"contains error severity", "severity: error"},
		{"contains message", "message:"},
		{"contains import_declaration", "import_declaration"},
		{"contains escaped regex", `regex: "org\\.apache\\.logging\\.log4j"`},
	}
	for _, c := range checks {
		t.Run(c.desc, func(t *testing.T) {
			if !strings.Contains(ruleYAML, c.want) {
				t.Errorf("expected YAML to contain %q\ngot:\n%s", c.want, ruleYAML)
			}
		})
	}
}

func TestBuildJavaRule_MavenFormat(t *testing.T) {
	tests := []struct {
		name           string
		pkg            string
		expectedID     string
		expectedRegex  string
	}{
		{
			name:          "Maven package with groupId and artifactId",
			pkg:           "org.apache.logging.log4j:log4j-core",
			expectedID:    "detect-vuln-org-apache-logging-log4j-log4j-core",
			expectedRegex: `org\\.apache\\.logging\\.log4j`,
		},
		{
			name:          "Google Guava Maven package",
			pkg:           "com.google.guava:guava",
			expectedID:    "detect-vuln-com-google-guava-guava",
			expectedRegex: `com\\.google\\.guava`,
		},
		{
			name:          "Spring Framework package",
			pkg:           "org.springframework:spring-core",
			expectedID:    "detect-vuln-org-springframework-spring-core",
			expectedRegex: `org\\.springframework`,
		},
		{
			name:          "Plain package without colon",
			pkg:           "com.example",
			expectedID:    "detect-vuln-com-example",
			expectedRegex: `com\\.example`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleYAML, err := BuildJavaRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildJavaRule() error = %v", err)
			}
			if !strings.Contains(ruleYAML, "id: "+tt.expectedID) {
				t.Errorf("expected id %q in:\n%s", tt.expectedID, ruleYAML)
			}
			if !strings.Contains(ruleYAML, "regex: \""+tt.expectedRegex+"\"") {
				t.Errorf("expected regex %q in:\n%s", tt.expectedRegex, ruleYAML)
			}
		})
	}
}

func TestBuildJavaRule_EmptyPackage(t *testing.T) {
	ruleYAML, err := BuildJavaRule("")
	if err != nil {
		t.Fatalf("BuildJavaRule() error = %v", err)
	}
	if !strings.Contains(ruleYAML, "id: detect-vuln-") {
		t.Errorf("expected id prefix in:\n%s", ruleYAML)
	}
}

func TestBuildJavaRule_YAMLValidity(t *testing.T) {
	pkg := "org.apache.logging.log4j:log4j-core"
	ruleYAML, err := BuildJavaRule(pkg)
	if err != nil {
		t.Fatalf("BuildJavaRule() error = %v", err)
	}
	// Verify all required YAML keys are present
	for _, key := range []string{"id:", "language:", "severity:", "message:", "rule:"} {
		if !strings.Contains(ruleYAML, key) {
			t.Errorf("missing required YAML key %q in:\n%s", key, ruleYAML)
		}
	}
}
