package trivy

import (
	"encoding/json"
	"testing"
)

func TestTrivyReport(t *testing.T) {
	report := TrivyReport{
		Results: []*Result{
			{
				Target: "go.sum",
				Type:   "gomod",
				Vulnerabilities: []*Vulnerability{
					{VulnerabilityID: "CVE-2021-0001", PkgName: "test-package", Severity: "HIGH"},
					{VulnerabilityID: "CVE-2021-0002", PkgName: "another-package", Severity: "CRITICAL"},
				},
			},
		},
	}

	if len(report.Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(report.Results))
	}
	if report.Results[0].Target != "go.sum" {
		t.Errorf("Expected Target 'go.sum', got %q", report.Results[0].Target)
	}
	if report.Results[0].Vulnerabilities[0].VulnerabilityID != "CVE-2021-0001" {
		t.Errorf("Unexpected VulnerabilityID: %s", report.Results[0].Vulnerabilities[0].VulnerabilityID)
	}
}

func TestVulnerability_JSON(t *testing.T) {
	raw := `{
		"VulnerabilityID": "CVE-2021-23337",
		"PkgName":         "lodash",
		"Severity":        "HIGH",
		"Description":     "Prototype pollution in lodash",
		"References":      ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
	}`
	var v Vulnerability
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if v.VulnerabilityID != "CVE-2021-23337" {
		t.Errorf("VulnerabilityID = %q", v.VulnerabilityID)
	}
	if v.Severity != "HIGH" {
		t.Errorf("Severity = %q", v.Severity)
	}
	if v.Description != "Prototype pollution in lodash" {
		t.Errorf("Description = %q", v.Description)
	}
	if len(v.References) != 1 {
		t.Errorf("References len = %d", len(v.References))
	}
}

func TestResult_WithType(t *testing.T) {
	cases := []struct{ ecosystem, want string }{
		{"", ""},
		{"gomod", "gomod"},
		{"npm", "npm"},
		{"pip", "pip"},
		{"pom", "pom"},
	}
	for _, c := range cases {
		t.Run(c.ecosystem, func(t *testing.T) {
			data, _ := json.Marshal(map[string]string{"Type": c.ecosystem})
			var r Result
			if err := json.Unmarshal(data, &r); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if r.Type != c.want {
				t.Errorf("Type = %q, want %q", r.Type, c.want)
			}
		})
	}
}
