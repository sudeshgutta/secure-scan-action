package rules

import (
	"strings"
	"testing"
)

// languageCases covers the basic expected YAML fields per supported language.
var languageCases = []struct {
	language   string
	pkg        string
	wantID     string
	wantKind   string
	wantFields []string // additional strings that must appear in the YAML
}{
	{
		language: "Go",
		pkg:      "github.com/foo/bar",
		wantID:   "detect-vuln-github-com-foo-bar",
		wantKind: "import_spec",
	},
	{
		language: "JavaScript",
		pkg:      "express",
		wantID:   "detect-vuln-express",
		wantKind: "import_statement",
		wantFields: []string{"call_expression"},
	},
	{
		language: "TypeScript",
		pkg:      "typescript",
		wantID:   "detect-vuln-typescript",
		wantKind: "import_statement",
	},
	{
		language: "Python",
		pkg:      "requests",
		wantID:   "detect-vuln-requests",
		wantKind: "import_statement",
		wantFields: []string{"import_from_statement"},
	},
	{
		language: "Java",
		pkg:      "org.apache.commons:commons-lang3",
		wantID:   "detect-vuln-org-apache-commons-commons-lang3",
		wantKind: "import_declaration",
	},
}

func TestBuildRule(t *testing.T) {
	requiredKeys := []string{"id:", "language:", "severity:", "message:", "rule:"}

	for _, tc := range languageCases {
		t.Run(tc.language, func(t *testing.T) {
			yaml, err := BuildRule(tc.pkg, tc.language)
			if err != nil {
				t.Fatalf("BuildRule() error = %v", err)
			}
			if !strings.Contains(yaml, "id: "+tc.wantID) {
				t.Errorf("want id %q in:\n%s", tc.wantID, yaml)
			}
			if !strings.Contains(yaml, "language: "+tc.language) {
				t.Errorf("want 'language: %s' in:\n%s", tc.language, yaml)
			}
			if !strings.Contains(yaml, "severity: error") {
				t.Errorf("want 'severity: error' in:\n%s", yaml)
			}
			if !strings.Contains(yaml, tc.wantKind) {
				t.Errorf("want kind %q in:\n%s", tc.wantKind, yaml)
			}
			for _, f := range tc.wantFields {
				if !strings.Contains(yaml, f) {
					t.Errorf("want %q in:\n%s", f, yaml)
				}
			}
			for _, k := range requiredKeys {
				if !strings.Contains(yaml, k) {
					t.Errorf("missing required YAML key %q in:\n%s", k, yaml)
				}
			}
		})
	}
}

func TestBuildRule_Unsupported(t *testing.T) {
	if _, err := BuildRule("rack", "Ruby"); err == nil {
		t.Error("expected error for unsupported language Ruby")
	}
}

func TestBuildRule_SafeID(t *testing.T) {
	cases := []struct {
		language string
		pkg      string
		wantID   string
	}{
		{"Go", "github.com/test/package", "detect-vuln-github-com-test-package"},
		{"Go", "github.com/test.package/v1", "detect-vuln-github-com-test-package-v1"},
		{"JavaScript", "@angular/core", "detect-vuln-angular-core"},
		{"JavaScript", "@scope/lib.module", "detect-vuln-scope-lib-module"},
		{"Python", "google.cloud", "detect-vuln-google-cloud"},
		{"Python", "scikit-learn", "detect-vuln-scikit-learn"},
		{"Java", "org.apache.logging.log4j:log4j-core", "detect-vuln-org-apache-logging-log4j-log4j-core"},
		{"Java", "com.google.guava:guava", "detect-vuln-com-google-guava-guava"},
	}
	for _, c := range cases {
		t.Run(c.language+"/"+c.pkg, func(t *testing.T) {
			yaml, err := BuildRule(c.pkg, c.language)
			if err != nil {
				t.Fatalf("BuildRule() error = %v", err)
			}
			if !strings.Contains(yaml, "id: "+c.wantID) {
				t.Errorf("want id %q in:\n%s", c.wantID, yaml)
			}
		})
	}
}

func TestBuildRule_Regex(t *testing.T) {
	cases := []struct {
		language  string
		pkg       string
		wantRegex string // as it appears in the YAML double-quoted scalar
	}{
		{"Go", "github.com/test/package", `regex: "github\\.com/test/package"`},
		{"Java", "org.apache.logging.log4j:log4j-core", `regex: "org\\.apache\\.logging\\.log4j"`},
		{"Java", "com.google.guava:guava", `regex: "com\\.google\\.guava"`},
		{"Java", "com.example", `regex: "com\\.example"`}, // no colon: whole pkg as groupId
	}
	for _, c := range cases {
		t.Run(c.language+"/"+c.pkg, func(t *testing.T) {
			yaml, err := BuildRule(c.pkg, c.language)
			if err != nil {
				t.Fatalf("BuildRule() error = %v", err)
			}
			if !strings.Contains(yaml, c.wantRegex) {
				t.Errorf("want %q in:\n%s", c.wantRegex, yaml)
			}
		})
	}
}

func TestBuildRule_YAMLInjection(t *testing.T) {
	cases := []struct {
		name           string
		pkg            string
		mustContain    string
		mustNotContain string
	}{
		{
			name:           "double-quote escaped in message",
			pkg:            `evil"pkg`,
			mustContain:    `evil\"pkg`,
			mustNotContain: `evil"pkg`,
		},
		{
			name:        "newline stripped from id",
			pkg:         "evil\npkg",
			mustContain: "id: detect-vuln-evil-pkg",
		},
		{
			name:        "non-id chars sanitized",
			pkg:         "pkg!name#here",
			mustContain: "id: detect-vuln-pkg-name-here",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml, err := BuildRule(c.pkg, "Go")
			if err != nil {
				t.Fatalf("BuildRule() error = %v", err)
			}
			if c.mustContain != "" && !strings.Contains(yaml, c.mustContain) {
				t.Errorf("want %q in:\n%s", c.mustContain, yaml)
			}
			if c.mustNotContain != "" && strings.Contains(yaml, c.mustNotContain) {
				t.Errorf("want NOT %q in:\n%s", c.mustNotContain, yaml)
			}
		})
	}
}

func TestBuildRule_Empty(t *testing.T) {
	for _, tc := range languageCases {
		t.Run(tc.language, func(t *testing.T) {
			yaml, err := BuildRule("", tc.language)
			if err != nil {
				t.Fatalf("BuildRule() error = %v", err)
			}
			if !strings.Contains(yaml, "id: detect-vuln-") {
				t.Errorf("want id prefix in:\n%s", yaml)
			}
		})
	}
}

func TestLanguagesForEcosystem(t *testing.T) {
	cases := []struct {
		ecosystem string
		want      []string
	}{
		{"gomod", []string{"Go"}},
		{"npm", []string{"JavaScript", "TypeScript"}},
		{"yarn", []string{"JavaScript", "TypeScript"}},
		{"pip", []string{"Python"}},
		{"pom", []string{"Java"}},
		{"gradle", []string{"Java"}},
		{"unknown", nil},
	}
	for _, c := range cases {
		t.Run(c.ecosystem, func(t *testing.T) {
			got := LanguagesForEcosystem(c.ecosystem)
			if len(got) != len(c.want) {
				t.Fatalf("LanguagesForEcosystem(%q) = %v, want %v", c.ecosystem, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
