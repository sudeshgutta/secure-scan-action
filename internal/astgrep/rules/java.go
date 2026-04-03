package rules

import (
	"encoding/json"
	"regexp"
	"strings"
)

// BuildJavaRule generates an AST-Grep rule for detecting Maven package imports in Java files.
// Maven packages use groupId:artifactId format (e.g., org.apache.logging.log4j:log4j-core).
// Java imports use the groupId as the package namespace prefix.
func BuildJavaRule(pkg string) (string, error) {
	// Extract groupId from Maven package format (groupId:artifactId)
	groupID := pkg
	if idx := strings.Index(pkg, ":"); idx != -1 {
		groupID = pkg[:idx]
	}

	// Escape all regex metacharacters in groupId for precise import matching
	escapedGroupID := regexp.QuoteMeta(groupID)

	// Build safeID from original package string
	safeID := strings.NewReplacer("/", "-", ".", "-", ":", "-").Replace(pkg)

	rule := ASTGrepRule{
		ID:       "detect-vuln-" + safeID,
		Language: "Java",
		Rule: ASTGrepImportSpecRule{
			Kind: "import_declaration",
			Has: ASTGrepHasRegex{
				Regex: escapedGroupID,
			},
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
