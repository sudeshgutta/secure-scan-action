Secure Scan Action is your intelligent security gatekeeper for GitHub repositories. Powered by [Trivy](https://github.com/aquasecurity/trivy) and [AST-Grep](https://github.com/ast-grep/ast-grep), it not only detects known vulnerabilities in your dependencies but also shows exactly where they are used in your code. By combining deep vulnerability scanning with smart code analysis, Secure Scan helps you focus on what truly matters -- fixing real risks, not false alarms. Shift security left and ship safer code with every commit.

![Secure Scan Action](https://github.com/sudeshgutta/secure-scan-action/actions/workflows/vuln-pkg-scan.yml/badge.svg)

## Quick Start

Add the following workflow file to your repository at `.github/workflows/vuln-pkg-scan.yml`:

```yaml
name: Vulnerable Package Scan

on:
  push:
  workflow_dispatch:

jobs:
  vuln-pkg-scan:
    name: Vulnerable Package Scan Job
    runs-on: ubuntu-latest

    steps:
      - name: Checkout source
        uses: actions/checkout@v4

      - name: Run Vulnerable Package Scan
        uses: sudeshgutta/secure-scan-action@v1.0.0-beta
```

## Features

- **Multi-language support**: Scans Go, JavaScript, TypeScript, Python, and Java codebases
- **Vulnerability scanning**: Uses Trivy to detect `HIGH` and `CRITICAL` CVEs in dependencies
- **Usage analysis**: Uses AST-Grep to find exactly where vulnerable packages are imported in your source code -- no false alarms from transitive-only dependencies
- **Ecosystem-aware**: Automatically maps Trivy ecosystems (`gomod`, `npm`, `yarn`, `pnpm`, `pip`, `poetry`, `uv`, `pom`, `gradle`, ...) to the correct language scanner
- **Containerized**: Runs in a secure Docker container with all tools pre-installed; no setup required
- **Non-root**: Container runs as an unprivileged `scanner` user

## How It Works

1. **Trivy scan** -- scans the checked-out repository for known `HIGH`/`CRITICAL` CVEs across all supported ecosystems
2. **Package extraction** -- deduplicates vulnerable package names and resolves which language(s) to scan for each ecosystem
3. **AST-Grep analysis** -- for each vulnerable package/language pair, renders an inline YAML rule and runs `sg scan` against the source tree
4. **Result reporting** -- prints file locations of actual usages; exits with a non-zero code so CI can gate on real risk

## Supported Languages & Ecosystems

| Language   | Trivy Ecosystems                          | Detects                     |
|------------|-------------------------------------------|-----------------------------|
| Go         | `gomod`                                   | `import` statements         |
| JavaScript | `npm`, `yarn`, `pnpm`, `node-pkg`         | `import` / `require` calls  |
| TypeScript | `npm`, `yarn`, `pnpm`, `node-pkg`         | `import` statements         |
| Python     | `pip`, `poetry`, `pipenv`, `uv`           | `import` / `from ... import`|
| Java       | `pom`, `gradle`, `gradle-lockfile`        | `import` declarations       |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Clean -- no vulnerable packages found in source |
| `1`  | Internal error (Trivy failed, parse error, etc.) |
| `2`  | Vulnerable package usages detected |

Use these codes to block PR merges or deployments when real usage is found.

## Local Development

```bash
# Build the Docker image
make build

# Build image and run scanner against the current directory
make scan

# Run tests
go test ./...
```

## Project Structure

```
secure-scan-action/
├── internal/
│   ├── astgrep/
│   │   ├── rules/
│   │   │   ├── templates/     # YAML rule templates per language (go.yml, javascript.yml, ...)
│   │   │   ├── dispatcher.go  # BuildRule() + ecosystem-to-language mapping
│   │   │   └── render.go      # Template renderer with YAML-injection protection
│   │   ├── scanner.go         # Orchestrates Trivy report -> AST-Grep scans
│   │   ├── analyzer.go        # Parses and aggregates AST-Grep matches
│   │   └── types.go           # ASTGrepMatch, PackageDetectionResult
│   ├── trivy/                 # Trivy CLI wrapper and report types
│   └── logger/                # JSON structured logging (log/slog)
├── main.go                    # Entry point
├── Dockerfile                 # 3-stage build: Go -> Trivy -> node:bookworm-slim runtime
├── action.yml                 # GitHub Action metadata
└── Makefile                   # build / scan targets
```

## Adding a New Language

1. Create `internal/astgrep/rules/templates/<language>.yml` -- a Go `text/template` YAML rule targeting the language's import AST node
2. Add a case to `BuildRule()` in `dispatcher.go` (or extend the existing `switch` for languages that share the simple pattern)
3. Map the relevant Trivy ecosystem(s) to the language in `ecosystemLanguages`
4. Add tests in `dispatcher_test.go`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
