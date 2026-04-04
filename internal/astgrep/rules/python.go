package rules

import (
	"regexp"
	"strings"
)

func BuildPythonRule(pkg string) (string, error) {
	safeID := strings.NewReplacer("/", "-", ".", "-").Replace(pkg)
	return renderTemplate("python", RuleData{
		SafeID:  safeID,
		Package: pkg,
		Regex:   regexp.QuoteMeta(pkg),
	})
}
