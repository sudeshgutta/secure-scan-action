package rules

import (
	"bytes"
	"embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

// nonIDRe matches any character that is not safe for an ast-grep rule id.
var nonIDRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeID replaces any character that is not alphanumeric, hyphen, or
// underscore with a hyphen, preventing newlines or special chars from breaking
// the unquoted YAML id field.
func sanitizeID(s string) string {
	return nonIDRe.ReplaceAllString(s, "-")
}

// yamlDQEscape escapes a string for safe embedding inside a YAML double-quoted
// scalar. Backslashes are doubled and double-quotes are escaped. Newlines and
// carriage returns are stripped because they would break the single-line scalar.
func yamlDQEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

//go:embed templates/*.yml
var templateFS embed.FS

// RuleData holds the values substituted into a YAML rule template.
type RuleData struct {
	SafeID       string // package name with /, ., @, : replaced by -
	Package      string // original package name
	Regex        string // regexp.QuoteMeta(Package)
	GroupIDRegex string // regexp.QuoteMeta of Maven groupId (Java only)
}

// renderTemplate loads the embedded YAML template for the given language name
// and executes it with the provided data. Language names map to template files:
// "go" → templates/go.yml, "javascript" → templates/javascript.yml, etc.
func renderTemplate(language string, data RuleData) (string, error) {
	templatePath := fmt.Sprintf("templates/%s.yml", language)

	content, err := templateFS.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("rule template not found for language %q: %w", language, err)
	}

	tmpl, err := template.New(language).Parse(string(content))
	if err != nil {
		return "", fmt.Errorf("failed to parse rule template for language %q: %w", language, err)
	}

	// Sanitize all fields before rendering to prevent YAML injection from
	// malicious package names in scanned repositories.
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
