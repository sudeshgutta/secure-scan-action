# Stage 1: Go Build
FROM golang:1.24-alpine AS go-builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o scanner .

# Stage 2: Trivy (use official image)
FROM aquasec/trivy:latest AS trivy-stage

# Stage 3: Final Runtime
FROM node:lts-bookworm-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    git && \
    # Install AST-Grep
    npm install -g @ast-grep/cli && \
    npm cache clean --force && \
    # Cleanup
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Go scanner from build stage
COPY --from=go-builder /app/scanner /usr/local/bin/scanner

# Copy Trivy binary from Trivy image
COPY --from=trivy-stage /usr/local/bin/trivy /usr/local/bin/trivy

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/scanner /usr/local/bin/trivy

# Verify all tools work
RUN trivy --version && \
    sg --version && \
    scanner --help || true

# Create non-root user for security
RUN useradd -r -s /bin/false -U scanner

# Set up working directory
RUN mkdir -p /home/scanner && \
    chown -R scanner:scanner /home/scanner

USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["/usr/local/bin/scanner"]