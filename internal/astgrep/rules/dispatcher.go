package rules

import "fmt"

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

// LanguagesForEcosystem returns the AST-Grep language identifiers for a given Trivy ecosystem type.
// Returns nil if the ecosystem is not supported.
func LanguagesForEcosystem(ecosystem string) []string {
	return ecosystemLanguages[ecosystem]
}

// BuildRule generates an AST-Grep rule JSON for the given package and language.
// Language must be one of: "Go", "JavaScript", "TypeScript", "Python", "Java".
// Returns an error for unsupported languages.
func BuildRule(pkg, language string) (string, error) {
	switch language {
	case "Go":
		return BuildGoRule(pkg)
	case "JavaScript":
		return BuildJavaScriptRule(pkg)
	case "TypeScript":
		return BuildTypeScriptRule(pkg)
	case "Python":
		return BuildPythonRule(pkg)
	case "Java":
		return BuildJavaRule(pkg)
	default:
		return "", fmt.Errorf("unsupported language: %s", language)
	}
}
