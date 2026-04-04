package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// ecosystemLanguages maps Trivy ecosystem Type values to AST-Grep language identifiers.
var ecosystemLanguages = map[string][]string{
	"gomod":           {"Go"},
	"npm":             {"JavaScript", "TypeScript"},
	"yarn":            {"JavaScript", "TypeScript"},
	"pnpm":            {"JavaScript", "TypeScript"},
	"node-pkg":        {"JavaScript", "TypeScript"},
	"pip":             {"Python"},
	"poetry":          {"Python"},
	"pipenv":          {"Python"},
	"uv":              {"Python"},
	"pom":             {"Java"},
	"gradle":          {"Java"},
	"gradle-lockfile": {"Java"},
}

// safeIDReplacer normalises package name characters that are unsafe in an ast-grep rule id.
var safeIDReplacer = strings.NewReplacer("@", "", "/", "-", ".", "-", ":", "-")

// LanguagesForEcosystem returns the AST-Grep language identifiers for a given Trivy ecosystem type.
func LanguagesForEcosystem(ecosystem string) []string {
	return ecosystemLanguages[ecosystem]
}

// BuildRule generates an AST-Grep YAML rule for the given package and language.
// Language must be one of: "Go", "JavaScript", "TypeScript", "Python", "Java".
func BuildRule(pkg, language string) (string, error) {
	data := RuleData{
		SafeID:  safeIDReplacer.Replace(pkg),
		Package: pkg,
		Regex:   regexp.QuoteMeta(pkg),
	}
	switch language {
	case "Go", "Python", "JavaScript", "TypeScript":
		return renderTemplate(strings.ToLower(language), data)
	case "Java":
		groupID := pkg
		if i := strings.IndexByte(pkg, ':'); i >= 0 {
			groupID = pkg[:i]
		}
		data.GroupIDRegex = regexp.QuoteMeta(groupID)
		return renderTemplate("java", data)
	default:
		return "", fmt.Errorf("unsupported language: %s", language)
	}
}
