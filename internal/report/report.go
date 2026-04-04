package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sudeshgutta/secure-scan-action/internal/astgrep"
)

// Print writes a human-readable findings table to w and, if $GITHUB_STEP_SUMMARY
// is set, also appends a Markdown table to that file for the GitHub Actions summary.
func Print(findings []astgrep.Finding, w io.Writer) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "✅ No vulnerable package usage detected.")
		writeSummary("## Secure Scan Results\n\n✅ No vulnerable package usage detected.\n")
		return
	}

	fmt.Fprintf(w, "\n🚨 Found %d vulnerable package usage(s):\n\n", len(findings))
	fmt.Fprintln(w, "  Package                          Severity    Reachability  CVEs                     Files")
	fmt.Fprintln(w, "  "+strings.Repeat("-", 95))

	var sb strings.Builder
	sb.WriteString("## Secure Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("🚨 **%d vulnerable package usage(s) detected.**\n\n", len(findings)))
	sb.WriteString("| Package | Severity | Reachability | CVE IDs | Files |\n")
	sb.WriteString("|---------|----------|--------------|---------|-------|\n")

	for _, f := range findings {
		cves := strings.Join(f.CVEIDs, ", ")
		if cves == "" {
			cves = "—"
		}
		var files []string
		if f.DetectionResult != nil {
			files = f.DetectionResult.UniqueFiles
		}
		fileCount := fmt.Sprintf("%d file(s)", len(files))
		if len(files) > 0 {
			fileCount = fmt.Sprintf("%d file(s): %s", len(files), strings.Join(files, ", "))
		}

		fmt.Fprintf(w, "  %-32s %-11s %-13s %-24s %s\n",
			truncate(f.Package, 32),
			f.Severity,
			f.ReachabilityScore.String(),
			truncate(cves, 24),
			fileCount,
		)
		sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s |\n",
			f.Package, f.Severity, f.ReachabilityScore, cves, fileCount))
	}

	writeSummary(sb.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func writeSummary(md string) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprint(f, md)
}
