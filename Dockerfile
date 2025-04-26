FROM golang:1.24-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /scanner

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /scanner /usr/local/bin/scanner

ENTRYPOINT ["/usr/local/bin/scanner"]