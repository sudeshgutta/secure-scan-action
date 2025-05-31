package astgrep

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/sudeshgutta/secure-scan-action/internal/logger"
	"github.com/sudeshgutta/secure-scan-action/internal/trivy"
)

func scanWithASTGrep(ctx context.Context, pkg string) (*PackageDetectionResult, error) {
	ruleJSON, err := BuildASTGrepInlineRule(pkg)
	if err != nil {
		logger.Log.Error("Failed to parse ast grep rule")
		return nil, err
	}

	// Create temporary output file
	outputFile, err := os.CreateTemp("", "astgrep-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	cmd := exec.CommandContext(ctx, "sg", "scan",
		"--inline-rules", ruleJSON,
		"--json",
		".",
	)

	// Redirect stdout to file
	outFile, err := os.OpenFile(outputFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}
	defer outFile.Close()

	cmd.Stdout = outFile

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Log.Error("AST-Grep stderr", "stderr", stderr.String())
		return nil, err
	}

	outFile.Close() // Close before reading

	// Read from file instead of memory buffer
	data, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	output, err := ParseASTGrepJSON(data)
	if err != nil {
		return nil, err
	}

	// Analyze for the specific package
	result := output.AnalyzePackage(pkg)

	return result, nil
}

func ProcessTrivyReport(ctx context.Context, trivyReport trivy.TrivyReport) []string {
	// Extract vulnerable packages
	vulnPkgs := make(map[string]struct{})
	for _, result := range trivyReport.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.PkgName != "" {
				vulnPkgs[vuln.PkgName] = struct{}{}
			}
		}
	}
	logger.Log.Info("Trivy identified vulnerable packages", "count", len(vulnPkgs))

	var output []string

	for pkg := range vulnPkgs {
		result, err := scanWithASTGrep(ctx, pkg)
		if err != nil {
			logger.Log.Warn("AST-Grep scan failed or timed out", "pkg", pkg, "err", err)
			continue
		}
		logger.Log.Info(result.GetSummaryString())
		output = append(output, result.PackageName)
	}
	return output
}
