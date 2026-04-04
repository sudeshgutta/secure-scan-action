package rules

import (
	"regexp"
	"strings"
)

func BuildGoRule(pkg string) (string, error) {
	safeID := strings.NewReplacer("/", "-", ".", "-").Replace(pkg)
	return renderTemplate("go", RuleData{
		SafeID:  safeID,
		Package: pkg,
		Regex:   regexp.QuoteMeta(pkg),
	})
}

