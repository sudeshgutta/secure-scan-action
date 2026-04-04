package rules

import (
	"strings"
	"testing"
)

func TestBuildJavaScriptRule(t *testing.T) {
	pkg := "express"
	ruleYAML, err := BuildJavaScriptRule(pkg)
	if err != nil {
		t.Fatalf("BuildJavaScriptRule() error = %v", err)
	}

	checks := []struct {
		desc string
		want string
	}{
		{"contains expected id", "id: detect-vuln-express"},
		{"contains JavaScript language", "language: JavaScript"},
		{"contains error severity", "severity: error"},
		{"contains message", "message:"},
		{"contains import_statement", "import_statement"},
		{"contains call_expression", "call_expression"},
		{"contains escaped regex", `regex: "express"`},
	}
	for _, c := range checks {
		t.Run(c.desc, func(t *testing.T) {
			if !strings.Contains(ruleYAML, c.want) {
				t.Errorf("expected YAML to contain %q\ngot:\n%s", c.want, ruleYAML)
			}
		})
	}
}

func TestBuildJavaScriptRule_WithSpecialCharacters(t *testing.T) {
	tests := []struct {
		name       string
		pkg        string
		expectedID string
	}{
		{"scoped package", "@angular/core", "detect-vuln-angular-core"},
		{"package with slashes", "lodash/map", "detect-vuln-lodash-map"},
		{"package with dots", "lib.module", "detect-vuln-lib-module"},
		{"package with both slashes and dots", "@scope/lib.module", "detect-vuln-scope-lib-module"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleYAML, err := BuildJavaScriptRule(tt.pkg)
			if err != nil {
				t.Fatalf("BuildJavaScriptRule() error = %v", err)
			}
			if !strings.Contains(ruleYAML, "id: "+tt.expectedID) {
				t.Errorf("expected id %q in:\n%s", tt.expectedID, ruleYAML)
			}
		})
	}
}

func TestBuildTypeScriptRule(t *testing.T) {
	pkg := "typescript"
	ruleYAML, err := BuildTypeScriptRule(pkg)
	if err != nil {
		t.Fatalf("BuildTypeScriptRule() error = %v", err)
	}

	if !strings.Contains(ruleYAML, "language: TypeScript") {
		t.Errorf("expected YAML to contain 'language: TypeScript'\ngot:\n%s", ruleYAML)
	}
}

func TestBuildJavaScriptRule_EmptyPackage(t *testing.T) {
	ruleYAML, err := BuildJavaScriptRule("")
	if err != nil {
		t.Fatalf("BuildJavaScriptRule() error = %v", err)
	}
	if !strings.Contains(ruleYAML, "id: detect-vuln-") {
		t.Errorf("expected id prefix in:\n%s", ruleYAML)
	}
}

func TestBuildJavaScriptRule_YAMLValidity(t *testing.T) {
	pkg := "express"
	ruleYAML, err := BuildJavaScriptRule(pkg)
	if err != nil {
		t.Fatalf("BuildJavaScriptRule() error = %v", err)
	}
	// Verify all required YAML keys are present
	for _, key := range []string{"id:", "language:", "severity:", "message:", "rule:"} {
		if !strings.Contains(ruleYAML, key) {
			t.Errorf("missing required YAML key %q in:\n%s", key, ruleYAML)
		}
	}
}
