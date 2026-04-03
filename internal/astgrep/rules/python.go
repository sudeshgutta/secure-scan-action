package rules

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Python import rule with 'any' array for multiple patterns
type ASTGrepAnyRule struct {
	Any []ASTGrepImportSpecRule `json:"any"`
}

func BuildPythonRule(pkg string) (string, error) {
	safeID := strings.NewReplacer("/", "-", ".", "-").Replace(pkg)

	rule := ASTGrepRule{
		ID:       "detect-vuln-" + safeID,
		Language: "Python",
		Rule: ASTGrepAnyRule{
			Any: []ASTGrepImportSpecRule{
				{
					Kind: "import_statement",
					Has: ASTGrepHasRegex{
						Regex: regexp.QuoteMeta(pkg),
					},
				},
				{
					Kind: "import_from_statement",
					Has: ASTGrepHasRegex{
						Regex: regexp.QuoteMeta(pkg),
					},
				},
			},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
