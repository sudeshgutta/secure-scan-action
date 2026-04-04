package rules

import (
	"strings"
	"testing"
)

func TestBuildRule(t *testing.T) {
	tests := []struct {
		name        string
		pkg         string
		language    string
		expectError bool
		expectLang  string
	}{
		{
			name:        "Go language",
			pkg:         "github.com/foo/bar",
			language:    "Go",
			expectError: false,
			expectLang:  "Go",
		},
		{
			name:        "JavaScript language",
			pkg:         "express",
			language:    "JavaScript",
			expectError: false,
			expectLang:  "JavaScript",
		},
		{
			name:        "TypeScript language",
			pkg:         "typescript",
			language:    "TypeScript",
			expectError: false,
			expectLang:  "TypeScript",
		},
		{
			name:        "Python language",
			pkg:         "requests",
			language:    "Python",
			expectError: false,
			expectLang:  "Python",
		},
		{
			name:        "Java language",
			pkg:         "org.apache.commons:commons-lang3",
			language:    "Java",
			expectError: false,
			expectLang:  "Java",
		},
		{
			name:        "Ruby unsupported language",
			pkg:         "rack",
			language:    "Ruby",
			expectError: true,
			expectLang:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleYAML, err := BuildRule(tt.pkg, tt.language)

			if (err != nil) != tt.expectError {
				t.Errorf("BuildRule() error = %v, expectError = %v", err, tt.expectError)
			}

			if tt.expectError {
				return
			}

			// Verify language is in the YAML
			expectedLangLine := "language: " + tt.expectLang
			if !strings.Contains(ruleYAML, expectedLangLine) {
				t.Errorf("Expected YAML to contain %q\ngot:\n%s", expectedLangLine, ruleYAML)
			}
		})
	}
}

func TestLanguagesForEcosystem(t *testing.T) {
	tests := []struct {
		name              string
		ecosystem         string
		expectedLanguages []string
	}{
		{
			name:              "gomod ecosystem",
			ecosystem:         "gomod",
			expectedLanguages: []string{"Go"},
		},
		{
			name:              "npm ecosystem",
			ecosystem:         "npm",
			expectedLanguages: []string{"JavaScript", "TypeScript"},
		},
		{
			name:              "pip ecosystem",
			ecosystem:         "pip",
			expectedLanguages: []string{"Python"},
		},
		{
			name:              "pom ecosystem",
			ecosystem:         "pom",
			expectedLanguages: []string{"Java"},
		},
		{
			name:              "gradle ecosystem",
			ecosystem:         "gradle",
			expectedLanguages: []string{"Java"},
		},
		{
			name:              "yarn ecosystem",
			ecosystem:         "yarn",
			expectedLanguages: []string{"JavaScript", "TypeScript"},
		},
		{
			name:              "unknown ecosystem",
			ecosystem:         "unknown",
			expectedLanguages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LanguagesForEcosystem(tt.ecosystem)

			if len(result) != len(tt.expectedLanguages) {
				t.Errorf("Expected %d languages, got %d", len(tt.expectedLanguages), len(result))
				return
			}

			// Check that all expected languages are present
			for i, lang := range tt.expectedLanguages {
				if result[i] != lang {
					t.Errorf("Expected language '%s' at index %d, got '%s'", lang, i, result[i])
				}
			}
		})
	}
}
