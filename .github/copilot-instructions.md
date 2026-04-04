# Copilot Instructions

## Project Overview

**Secure Scan Action** is a GitHub Action that detects security vulnerabilities in Go repository dependencies using a two-stage pipeline:
1. **Trivy** scans for known CVEs in dependency packages
2. **AST-Grep** finds where those vulnerable packages are actually imported and used in source code

The action runs inside a Docker container and exits with code `0` (clean), `1` (internal error), or `2` (vulnerable usage found).

## Agent Workflow

All non-trivial code changes follow a **coding → review → iterate** loop using two specialized sub-agents.

### Agents

| Agent | Model | Role |
|-------|-------|------|
| **coding-agent** | `claude-haiku-4.5` | Implements the change: writes/edits Go source, tests, and docs |
| **review-agent** | `claude-opus-4.6` | Reviews the diff produced by the coding agent; reports bugs, security issues, and logic errors only — no style comments |

### Workflow

```
┌──────────────────────────────────────────────────────────────┐
│ For each feature / fix / refactor:                           │
│                                                              │
│  1. coding-agent  →  implements change, runs go test ./...  │
│  2. review-agent  →  reviews staged diff, outputs findings   │
│  3. Repeat steps 1-2 up to 3 cycles (15 min cap per cycle)  │
│  4. If all cycles pass with no blockers → commit             │
└──────────────────────────────────────────────────────────────┘
```

### Rules

- **Cycle limit**: maximum **3 coding → review cycles** per task. If blockers remain after cycle 3, surface them to the user instead of continuing.
- **Time limit**: each cycle must complete within **15 minutes**. If a cycle times out, stop and report partial results.
- **Review scope**: the review agent only surfaces **bugs**, **security vulnerabilities**, and **logic errors**. Style, formatting, and naming are out of scope.
- **Feedback format**: the review agent outputs a concise numbered list of actionable findings. Each finding includes the file, line range, and a clear description of the problem.
- **Passing criteria**: a cycle passes when the review agent reports zero blocking findings. Warnings (non-blocking) are noted but do not trigger another cycle.
- **Test gate**: the coding agent must run `go test ./...` and confirm all tests pass before handing off to the review agent.

### Prompt Templates

**Coding agent prompt:**
```
You are implementing the following task in the secure-scan-action Go repository:

<task>
{TASK_DESCRIPTION}
</task>

Prior review feedback (cycle {N} of 3):
{REVIEW_FEEDBACK or "None — this is cycle 1"}

Instructions:
1. Make the necessary code changes to address the task (and any prior feedback).
2. Run `go test ./...` and confirm all tests pass.
3. Output a summary of what you changed and why.
4. Do NOT commit.
```

**Review agent prompt:**
```
You are reviewing a code change in the secure-scan-action Go repository (cycle {N} of 3).

Diff to review:
{GIT_DIFF}

Instructions:
1. Focus only on bugs, security vulnerabilities, and logic errors.
2. Output a numbered list of blocking findings (empty list = pass).
3. For each finding include: file path, line range, and a clear description.
4. Do NOT comment on style, formatting, naming, or test coverage.
5. Label each finding as BLOCKING or WARNING.
```

---

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
- `astgrep/` — AST-Grep orchestration, output analysis, and result types (`ASTGrepMatch`, `PackageDetectionResult`, `Finding`, `ReachabilityScore`)
- `astgrep/rules/` — Rule generation per language; renders YAML templates per language
- `sarif/` — SARIF 2.1.0 writer for GitHub Security tab integration
- `report/` — Console table + GitHub Actions step summary reporter
- `logger/` — Singleton `log/slog` logger with JSON output; debug level enabled via `DEBUG=1` env var

## Key Conventions

### Constants (UPPER_SNAKE_CASE)
Tool timeouts and configuration are defined as package-level constants:
```go
const TRIVY_TIMEOUT = 120 * time.Second
const ASTGREP_TIMEOUT = 120 * time.Second
const TRIVY_SEVERITY = "HIGH,CRITICAL"
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

Defined in `action.yml` — runs as a Docker action. Inputs:
- `severity` (default `HIGH,CRITICAL`) — comma-separated Trivy severity levels
- `sarif-output` (default `results.sarif`) — path for the SARIF 2.1.0 output file

The workflow in `.github/workflows/vuln-pkg-scan.yml` shows canonical usage.


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
