package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
)

func TestWrite_EmptyFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := Write(nil, path); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("want version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("want 0 results, got %d", len(log.Runs[0].Results))
	}
	// Ensure results and rules marshal as [] not null (SARIF schema requires arrays)
	if !bytes.Contains(data, []byte(`"results": []`)) {
		t.Errorf("expected results to be JSON array [], got null or missing")
	}
	if !bytes.Contains(data, []byte(`"rules": []`)) {
		t.Errorf("expected rules to be JSON array [], got null or missing")
	}
}

func TestWrite_SingleFinding(t *testing.T) {
	result := &astgrep.PackageDetectionResult{
		PackageName: "lodash",
		UniqueFiles: []string{"src/utils.js"},
	}
	findings := []astgrep.Finding{{
		Package:           "lodash",
		Language:          "JavaScript",
		CVEIDs:            []string{"CVE-2021-23337"},
		Severity:          "HIGH",
		DetectionResult:   result,
		ReachabilityScore: astgrep.ReachabilityMedium,
	}}

	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := Write(findings, path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("want 1 rule, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "CVE-2021-23337" {
		t.Errorf("unexpected rule ID %q", run.Tool.Driver.Rules[0].ID)
	}
	if len(run.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(run.Results))
	}
	res := run.Results[0]
	if res.Level != "error" {
		t.Errorf("HIGH severity should map to 'error', got %q", res.Level)
	}
	if res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/utils.js" {
		t.Errorf("unexpected URI %q", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestSeverityToLevel(t *testing.T) {
	cases := []struct{ sev, want string }{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"UNKNOWN", "note"},
		{"", "note"},
	}
	for _, c := range cases {
		if got := severityToLevel(c.sev); got != c.want {
			t.Errorf("severityToLevel(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestWrite_MultipleCVEs(t *testing.T) {
	result := &astgrep.PackageDetectionResult{
		PackageName: "vuln-pkg",
		UniqueFiles: []string{"main.go", "lib/util.go"},
	}
	findings := []astgrep.Finding{{
		Package:           "vuln-pkg",
		Language:          "Go",
		CVEIDs:            []string{"CVE-2021-0001", "CVE-2021-0002"},
		Severity:          "CRITICAL",
		DetectionResult:   result,
		ReachabilityScore: astgrep.ReachabilityHigh,
	}}

	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := Write(findings, path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	// 2 CVEs × 2 files = 4 results
	if len(log.Runs[0].Results) != 4 {
		t.Fatalf("want 4 results (2 CVEs × 2 files), got %d", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("want 2 rules, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestWrite_InvalidPath(t *testing.T) {
	err := Write(nil, "/no/such/directory/results.sarif")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}
