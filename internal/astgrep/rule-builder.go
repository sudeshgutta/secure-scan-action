package astgrep

import (
	"encoding/json"
	"fmt"
	"strings"
)

func BuildASTGrepInlineRule(pkg string) (string, error) {
	safeID := strings.ReplaceAll(pkg, "/", "-")
	safeID = strings.ReplaceAll(safeID, ".", "-")

	ruleContent := ASTGrepImportSpecRule{
		Kind: "import_spec",
		Has: ASTGrepHasRegex{
			Regex: pkg,
		},
	}

	rule := ASTGrepRule{
		ID:       "detect-vuln-" + safeID,
		Language: "go",
		Rule:     ruleContent,
	}

	data, err := json.Marshal(rule)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AST-Grep rule: %w", err)
	}

	return string(data), nil
}
