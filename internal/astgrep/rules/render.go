package rules

import (
	"bytes"
	"embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

//go:embed templates/*.yml
var templateFS embed.FS

// nonIDRe matches any character that is not safe for an ast-grep rule id.
var nonIDRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// yamlDQReplacer escapes strings for safe embedding in YAML double-quoted scalars.
var yamlDQReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", "", "\r", "")

func sanitizeID(s string) string   { return nonIDRe.ReplaceAllString(s, "-") }
func yamlDQEscape(s string) string { return yamlDQReplacer.Replace(s) }

// RuleData holds the values substituted into a YAML rule template.
type RuleData struct {
	SafeID       string
	Package      string
	Regex        string
	GroupIDRegex string // Java only: QuoteMeta of Maven groupId
}

// renderTemplate renders the embedded YAML template for the given language.
// Sanitizes all fields before execution to prevent YAML injection.
func renderTemplate(language string, data RuleData) (string, error) {
	content, err := templateFS.ReadFile("templates/" + language + ".yml")
	if err != nil {
		return "", fmt.Errorf("rule template not found for language %q: %w", language, err)
	}
	tmpl, err := template.New(language).Parse(string(content))
	if err != nil {
		return "", fmt.Errorf("failed to parse rule template for language %q: %w", language, err)
	}
	data.SafeID = sanitizeID(data.SafeID)
	data.Package = yamlDQEscape(data.Package)
	data.Regex = yamlDQEscape(data.Regex)
	data.GroupIDRegex = yamlDQEscape(data.GroupIDRegex)
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render rule template for language %q: %w", language, err)
	}
	return buf.String(), nil
}
