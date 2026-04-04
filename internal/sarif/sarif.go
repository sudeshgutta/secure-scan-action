package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
)

// SARIF 2.1.0 structures (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

type sarifLog struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// severityToLevel maps Trivy severity to SARIF level.
func severityToLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

// severityToScore maps Trivy severity to CVSS-like numeric score for GitHub Security tab.
func severityToScore(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "7.0"
	case "MEDIUM":
		return "4.0"
	default:
		return "1.0"
	}
}

// Write generates a SARIF 2.1.0 file at the given path from the provided findings.
func Write(findings []astgrep.Finding, path string) error {
	rules, results := buildRulesAndResults(findings)

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "secure-scan-action", Rules: rules}},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("sarif: write %q: %w", path, err)
	}
	return nil
}

func buildRulesAndResults(findings []astgrep.Finding) ([]sarifRule, []sarifResult) {
	ruleSet := make(map[string]sarifRule)
	results := make([]sarifResult, 0)

	for _, f := range findings {
		for _, cve := range f.CVEIDs {
			if _, seen := ruleSet[cve]; !seen {
				ruleSet[cve] = sarifRule{
					ID:               cve,
					Name:             "VulnerableDependency",
					ShortDescription: sarifMessage{Text: fmt.Sprintf("Vulnerable package %q (%s)", f.Package, cve)},
					Properties: sarifRuleProperties{
						Tags:     []string{"security", "dependency"},
						Severity: severityToScore(f.Severity),
					},
				}
			}

			if f.DetectionResult == nil {
				continue
			}
			for _, file := range f.DetectionResult.UniqueFiles {
				results = append(results, sarifResult{
					RuleID: cve,
					Level:  severityToLevel(f.Severity),
					Message: sarifMessage{Text: fmt.Sprintf(
						"Vulnerable package %q (%s, %s) is imported here. Reachability: %s",
						f.Package, cve, f.Severity, f.ReachabilityScore,
					)},
					Locations: []sarifLocation{{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{URI: file, URIBaseID: "%SRCROOT%"},
							Region:           sarifRegion{StartLine: 1},
						},
					}},
				})
			}
		}
	}

	// Collect rules in deterministic order
	ruleSlice := make([]sarifRule, 0, len(ruleSet))
	for _, r := range ruleSet {
		ruleSlice = append(ruleSlice, r)
	}
	sort.Slice(ruleSlice, func(i, j int) bool { return ruleSlice[i].ID < ruleSlice[j].ID })

	// Sort results by RuleID, then by URI for determinism
	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		uri1 := ""
		uri2 := ""
		if len(results[i].Locations) > 0 {
			uri1 = results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		if len(results[j].Locations) > 0 {
			uri2 = results[j].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		return uri1 < uri2
	})

	return ruleSlice, results
}
