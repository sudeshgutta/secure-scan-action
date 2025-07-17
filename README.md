A GitHub Action that scans your repository for security vulnerabilities using Trivy and analyzes vulnerable package usage with AST-Grep.

![Secure Scan Action](https://github.com/sudeshgutta/secure-scan-action/actions/workflows/vuln-pkg-scan.yml/badge.svg)

## Quick Start

Add the following workflow file to your repository at `.github/workflows/vuln-pkg-scan.yml` to start scanning your code for vulnerable packages using **Secure Scan Action**:

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
      - name: ⬇️ Checkout source
        uses: actions/checkout@v4

      - name: 🔐 Run Vulnerable Package Scan
        uses: sudeshgutta/secure-scan-action@v1.0.0-beta
```

## Features

- **Vulnerability Scanning**: Uses Trivy to detect security vulnerabilities in dependencies
- **Package Usage Analysis**: Uses AST-Grep to find where vulnerable packages are imported in your Go code
- **Containerized**: Runs in a secure Docker container with all tools pre-installed
- **Extensible**: Designed to support multiple programming languages

## How It Works

1. **Trivy Scan**: Scans your repository for known vulnerabilities
2. **Package Extraction**: Extracts vulnerable package names from Trivy results  
3. **AST-Grep Analysis**: Finds where these packages are imported in your codebase
4. **Result Generation**: Provides detailed reports with file locations

## Exit Codes

- **0**: No issues found
- **1**: Internal error occurred
- **2**: Vulnerabilities found

These exit codes can be used in CI/CD pipelines to determine the outcome of the scan and take appropriate actions (e.g., prevent pull request merge if vulnerable usages are found).

## Local Development

```bash
# Build and run locally
make build
make run

# Or with Docker
docker build -t secure-scan-action .
docker run --rm -v $(pwd):/workspace -w /workspace secure-scan-action
```

## Project Structure

```
secure-scan-action/
├── internal/
│   ├── astgrep/           # AST-Grep scanning logic
│   ├── trivy/             # Trivy integration
│   └── logger/            # Logging utilities
├── main.go                # Application entry point
├── Dockerfile             # Container definition
├── action.yml             # GitHub Action metadata
└── Makefile               # Build and run commands
```

## Supported Languages

- **Go**: Import statement detection (implemented)
- **JavaScript**: Import statement detection (planned)
- **Java**: Import declaration detection (planned)
- **Python**: Import statement detection (planned)


## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.