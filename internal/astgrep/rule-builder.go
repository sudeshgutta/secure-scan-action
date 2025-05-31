package astgrep

import (
	"encoding/json"
	"fmt"
	"strings"
)

func BuildASTGrepInlineRule(pkg string) (string, error) {
	safeID := strings.ReplaceAll(pkg, "/", "-")
	safeID = strings.ReplaceAll(safeID, ".", "-")

	rule := ASTGrepRule{
		ID:       "detect-vuln-" + safeID,
		Language: "go",
		Rule: ASTGrepRuleContent{
			Pattern: fmt.Sprintf(`"%s"`, pkg), // Exact match for the import string
			Inside: &ASTGrepRuleContent{
				Kind: "import_spec", // This is the individual import line inside import()
			},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AST-Grep rule: %w", err)
	}

	return string(data), nil
}
