package rules

import (
	"strings"
	"testing"
)

func TestBuildGoRule(t *testing.T) {
	pkg := "github.com/test/package"
	ruleYAML, err := BuildGoRule(pkg)
	if err != nil {
		t.Fatalf("BuildGoRule() error = %v", err)
	}

	checks := []struct {
		desc string
		want string
	}{
		{"contains expected id", "id: detect-vuln-github-com-test-package"},
		{"contains Go language", "language: Go"},
		{"contains error severity", "severity: error"},
		{"contains message", "message:"},
		{"contains import_spec kind", "kind: import_spec"},
		{"contains escaped regex", `regex: "github\\.com/test/package"`},
	}
	for _, c := range checks {
		t.Run(c.desc, func(t *testing.T) {
			if !strings.Contains(ruleYAML, c.want) {
				t.Errorf("expected YAML to contain %q\ngot:\n%s", c.want, ruleYAML)
			}
		})
	}
}

func TestBuildGoRule_WithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name        string
		pkg         string
		expectedID  string
	}{
		{"package with slashes", "github.com/test/package", "detect-vuln-github-com-test-package"},
		{"package with dots", "github.com/test.package", "detect-vuln-github-com-test-package"},
		{"package with both", "github.com/test.package/v1", "detect-vuln-github-com-test-package-v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleYAML, err := BuildGoRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildGoRule() error = %v", err)
			}
			if !strings.Contains(ruleYAML, "id: "+tt.expectedID) {
				t.Errorf("expected id %q in:\n%s", tt.expectedID, ruleYAML)
			}
		})
	}
}

func TestBuildGoRule_EmptyPackage(t *testing.T) {
	ruleYAML, err := BuildGoRule("")
	if err != nil {
		t.Fatalf("BuildGoRule() error = %v", err)
	}
	if !strings.Contains(ruleYAML, "id: detect-vuln-") {
		t.Errorf("expected id prefix in:\n%s", ruleYAML)
	}
}

func TestBuildGoRule_YAMLInjection(t *testing.T) {
	tests := []struct {
		name        string
		pkg         string
		mustContain string
		mustNotContain string
	}{
		{
			name:           "double-quote in package name is escaped",
			pkg:            `evil"pkg`,
			mustContain:    `evil\"pkg`,
			mustNotContain: `evil"pkg`,
		},
		{
			name:        "newline in package name is stripped",
			pkg:         "evil\npkg",
			mustContain: "id: detect-vuln-evil-pkg",
		},
		{
			name:        "non-id chars in package name are sanitized in id field",
			pkg:         "pkg!name#here",
			mustContain: "id: detect-vuln-pkg-name-here",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleYAML, err := BuildGoRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildGoRule() error = %v", err)
			}
			if tt.mustContain != "" && !strings.Contains(ruleYAML, tt.mustContain) {
				t.Errorf("expected YAML to contain %q\ngot:\n%s", tt.mustContain, ruleYAML)
			}
			if tt.mustNotContain != "" && strings.Contains(ruleYAML, tt.mustNotContain) {
				t.Errorf("expected YAML to NOT contain %q\ngot:\n%s", tt.mustNotContain, ruleYAML)
			}
		})
	}
}

func TestBuildGoRule_YAMLValidity(t *testing.T) {
	pkg := "github.com/test/package"
	ruleYAML, err := BuildGoRule(pkg)
	if err != nil {
		t.Fatalf("BuildGoRule() error = %v", err)
	}
	// Verify all required YAML keys are present
	for _, key := range []string{"id:", "language:", "severity:", "message:", "rule:"} {
		if !strings.Contains(ruleYAML, key) {
			t.Errorf("missing required YAML key %q in:\n%s", key, ruleYAML)
		}
	}
}
