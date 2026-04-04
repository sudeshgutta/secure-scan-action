package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
)

func TestPrint_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	Print(nil, &buf)
	if !strings.Contains(buf.String(), "No vulnerable") {
		t.Errorf("expected clean message, got: %q", buf.String())
	}
}

func TestPrint_WithFindings(t *testing.T) {
	result := &astgrep.PackageDetectionResult{
		PackageName: "lodash",
		UniqueFiles: []string{"src/utils.js", "src/helpers.js"},
	}
	findings := []astgrep.Finding{
		{
			Package:           "lodash",
			Language:          "JavaScript",
			CVEIDs:            []string{"CVE-2021-23337"},
			Severity:          "HIGH",
			DetectionResult:   result,
			ReachabilityScore: astgrep.ReachabilityMedium,
		},
	}

	var buf bytes.Buffer
	Print(findings, &buf)
	out := buf.String()

	for _, want := range []string{"lodash", "HIGH", "MEDIUM", "CVE-2021-23337"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPrint_NoCVEs(t *testing.T) {
	result := &astgrep.PackageDetectionResult{
		PackageName: "somepkg",
		UniqueFiles: []string{"main.go"},
	}
	findings := []astgrep.Finding{{
		Package:           "somepkg",
		Language:          "Go",
		CVEIDs:            nil,
		Severity:          "LOW",
		DetectionResult:   result,
		ReachabilityScore: astgrep.ReachabilityLow,
	}}

	var buf bytes.Buffer
	Print(findings, &buf)
	if !strings.Contains(buf.String(), "somepkg") {
		t.Error("expected package name in output")
	}
}
