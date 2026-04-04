# Stage 1: Go Build
FROM golang:1.26-alpine AS go-builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o scanner .

# Stage 2: Trivy (use official image)
FROM aquasec/trivy:0.69.3 AS trivy-stage

# Stage 3: Final Runtime
FROM node:lts-bookworm-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    git && \
    # Install AST-Grep
    npm install -g @ast-grep/cli@0.39.5 && \
    npm cache clean --force && \
    # Cleanup
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Go scanner from build stage
COPY --from=go-builder /app/scanner /usr/local/bin/scanner

# Copy Trivy binary from Trivy image
COPY --from=trivy-stage /usr/local/bin/trivy /usr/local/bin/trivy

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/scanner /usr/local/bin/trivy

# Use /tmp for cache directories (writable by any user)
RUN mkdir -p /tmp/trivy

# Set environment variables for cache directories
# Suppress Node.js deprecation warnings from ast-grep CLI internals
ENV NODE_NO_WARNINGS=1
ENV TRIVY_CACHE_DIR=/tmp/trivy
ENV XDG_CACHE_HOME=/tmp

LABEL org.opencontainers.image.title="Secure Scan Action"
LABEL org.opencontainers.image.description="A GitHub Action for scanning vulnerabilities using Trivy and finding their usage with AST-Grep"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Verify all tools work
RUN trivy --version && sg --version

# GitHub Actions mounts the workspace at /github/workspace; writing here makes
# output files (e.g. results.sarif) visible on the host runner after container exit.
WORKDIR /github/workspace

ENTRYPOINT ["/usr/local/bin/scanner"]