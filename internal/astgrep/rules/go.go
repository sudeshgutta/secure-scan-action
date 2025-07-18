package rules

import (
	"encoding/json"
	"strings"
)

type ASTGrepRule struct {
	ID       string      `json:"id"`
	Language string      `json:"language"`
	Rule     interface{} `json:"rule"`
}

// Import Spec Kind
type ASTGrepImportSpecRule struct {
	Kind string          `json:"kind,omitempty"`
	Has  ASTGrepHasRegex `json:"has,omitempty"`
}

// Matches regex value/expression
type ASTGrepHasRegex struct {
	Regex string `json:"regex,omitempty"`
}

func BuildRule(pkg string) (string, error) {
	safeID := strings.NewReplacer("/", "-", ".", "-").Replace(pkg)

	rule := ASTGrepRule{
		ID:       "detect-vuln-" + safeID,
		Language: "go",
		Rule: ASTGrepImportSpecRule{
			Kind: "import_spec",
			Has: ASTGrepHasRegex{
				Regex: pkg,
			},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
