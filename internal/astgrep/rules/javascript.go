package rules

import (
	"encoding/json"
	"regexp"
	"strings"
)

// JavaScript/TypeScript import/require pattern with "any" array
type ASTGrepJSRulePattern struct {
	Any []interface{} `json:"any"`
}

// String node inside import_statement
type ASTGrepJSImportPattern struct {
	Kind   string `json:"kind"`
	Regex  string `json:"regex"`
	Inside struct {
		Kind string `json:"kind"`
	} `json:"inside"`
}

// String node inside call_expression with require identifier
type ASTGrepJSRequirePattern struct {
	Kind   string `json:"kind"`
	Regex  string `json:"regex"`
	Inside struct {
		Kind string          `json:"kind"`
		Has  ASTGrepHasRegex `json:"has"`
	} `json:"inside"`
}

func buildJavaScriptTypeScriptRule(pkg, language string) (string, error) {
	safeID := strings.NewReplacer("@", "", "/", "-", ".", "-").Replace(pkg)
	escapedPkg := regexp.QuoteMeta(pkg)

	// Create import pattern
	importPattern := ASTGrepJSImportPattern{
		Kind:  "string",
		Regex: escapedPkg,
	}
	importPattern.Inside.Kind = "import_statement"

	// Create require pattern
	requirePattern := ASTGrepJSRequirePattern{
		Kind:  "string",
		Regex: escapedPkg,
	}
	requirePattern.Inside.Kind = "call_expression"
	requirePattern.Inside.Has = ASTGrepHasRegex{
		Regex: "^require$",
	}

	rule := ASTGrepRule{
		ID:       "detect-vuln-" + safeID,
		Language: language,
		Rule: ASTGrepJSRulePattern{
			Any: []interface{}{
				importPattern,
				requirePattern,
			},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func BuildJavaScriptRule(pkg string) (string, error) {
	return buildJavaScriptTypeScriptRule(pkg, "JavaScript")
}

func BuildTypeScriptRule(pkg string) (string, error) {
	return buildJavaScriptTypeScriptRule(pkg, "TypeScript")
}
