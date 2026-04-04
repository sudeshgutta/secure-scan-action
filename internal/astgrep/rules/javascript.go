package rules

import (
	"regexp"
	"strings"
)

func buildJavaScriptTypeScriptRule(pkg, language string) (string, error) {
	safeID := strings.NewReplacer("@", "", "/", "-", ".", "-").Replace(pkg)
	return renderTemplate(language, RuleData{
		SafeID:  safeID,
		Package: pkg,
		Regex:   regexp.QuoteMeta(pkg),
	})
}

func BuildJavaScriptRule(pkg string) (string, error) {
	return buildJavaScriptTypeScriptRule(pkg, "javascript")
}

func BuildTypeScriptRule(pkg string) (string, error) {
	return buildJavaScriptTypeScriptRule(pkg, "typescript")
}
