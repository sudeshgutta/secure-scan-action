package rules

import (
	"regexp"
	"strings"
)

// BuildJavaRule generates an AST-Grep YAML rule for detecting Maven package imports in Java files.
// Maven packages use groupId:artifactId format (e.g., org.apache.logging.log4j:log4j-core).
// Java imports use the groupId as the package namespace prefix.
func BuildJavaRule(pkg string) (string, error) {
	groupID := pkg
	if idx := strings.Index(pkg, ":"); idx != -1 {
		groupID = pkg[:idx]
	}

	safeID := strings.NewReplacer("/", "-", ".", "-", ":", "-").Replace(pkg)

	return renderTemplate("java", RuleData{
		SafeID:       safeID,
		Package:      pkg,
		Regex:        regexp.QuoteMeta(pkg),
		GroupIDRegex: regexp.QuoteMeta(groupID),
	})
}
