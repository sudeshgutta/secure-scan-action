# Copilot Instructions

## Project Overview

**Secure Scan Action** is a GitHub Action that detects security vulnerabilities in Go repository dependencies using a two-stage pipeline:
1. **Trivy** scans for known CVEs in dependency packages
2. **AST-Grep** finds where those vulnerable packages are actually imported and used in source code

The action runs inside a Docker container and exits with code `0` (clean), `1` (internal error), or `2` (vulnerable usage found).

## Commands

```bash
# Build the Docker image
make build

# Build and run against the current directory
make scan

# Run tests
go test ./...

# Run a single test function
go test -v ./internal/trivy -run TestScanConstants
go test -v ./internal/astgrep -run TestAnalyzePackageMatches_SingleMatch

# Run tests in a specific package
go test -v ./internal/logger
```

There are no separate lint commands in this repo. Tests require no external tooling beyond the Go toolchain.

## Architecture

```
main.go
  ├── logger.Init()                    # Structured JSON logging via log/slog
  ├── trivy.Scan(ctx)                  # Runs trivy CLI → TrivyReport
  └── astgrep.ProcessTrivyReport(ctx, report)
        ├── extractVulnerablePackages() # Deduplicates PkgNames into a map
        ├── rules.BuildRule(pkg, language) # Renders YAML from embedded templates
        ├── scanWithASTGrep(ctx, pkg)   # Executes `sg scan --inline-rules ...`
        └── AnalyzePackageMatches()     # Parses JSON output → PackageDetectionResult
```

`internal/` package layout:
- `trivy/` — Trivy CLI wrapper and report types (`TrivyReport`, `Result`, `Vulnerability`)
- `astgrep/` — AST-Grep orchestration, output analysis, and result types (`ASTGrepMatch`, `PackageDetectionResult`)
- `astgrep/rules/` — Rule generation per language; renders YAML templates per language
- `logger/` — Singleton `log/slog` logger with JSON output; debug level enabled via `DEBUG=1` env var

## Key Conventions

### Constants (UPPER_SNAKE_CASE)
Tool timeouts and configuration are defined as package-level constants:
```go
const TRIVY_TIMEOUT = 120 * time.Second
const ASTGREP_TIMEOUT = 120 * time.Second
const TRIVY_SEVERITY = "CRITICAL,HIGH"
```

### Error Handling
Errors during per-package scans are logged as warnings and skipped — the action degrades gracefully rather than failing hard:
```go
if err != nil {
    logger.Log.Warn("...", "error", err)
    continue
}
```
Fatal errors (e.g., Trivy failing entirely) call `os.Exit(1)`.

### Testing Patterns
- **Table-driven tests** are standard — see `types_test.go` files for examples
- Tests always call `logger.Init()` first to avoid nil logger panics
- Integration tests use very short timeouts (e.g., `1*time.Millisecond`) to avoid hanging when tools aren't available in CI

### Adding Language Support
To add scanning support for a new language (JS, Python, etc.), add a new file under `internal/astgrep/rules/` that implements a `BuildXxxRule(packageName string) (string, error)` function and wire it into `dispatcher.go`.

### Rule Templates (YAML)
AST-Grep rules are defined as Go `text/template`-based YAML files in `internal/astgrep/rules/templates/`:
- `go.yml`, `javascript.yml`, `typescript.yml`, `python.yml`, `java.yml`
- Templates are embedded in the binary via `//go:embed` — no file-system dependency at runtime
- Template variables: `{{.SafeID}}`, `{{.Package}}`, `{{.Regex}}`, `{{.GroupIDRegex}}` (Java only)
- Each template includes `severity: error`, `message`, and `note` fields per ast-grep best practices
- To add a new language: create a template file in `templates/`, add a `BuildXxxRule` function, and wire it into `dispatcher.go`

## Docker Build

Three-stage Dockerfile:
1. `golang:1.24-alpine` — compiles static binary with `CGO_ENABLED=0`, strips debug symbols (`-ldflags='-w -s'`)
2. `aquasec/trivy:0.64.1` — source for the trivy binary
3. `node:lts-bookworm-slim` — runtime; installs `ast-grep` via npm, adds non-root `scanner` user, copies binaries from stages 1 & 2

The action uses no Go module dependencies beyond the standard library.

## GitHub Action

Defined in `action.yml` — runs as a Docker action with no inputs or outputs exposed. The action is self-contained: it always scans `.` (the checked-out repo) with `CRITICAL,HIGH` severity. The workflow in `.github/workflows/vuln-pkg-scan.yml` shows canonical usage.
