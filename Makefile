.PHONY: build run scan

build:
	docker build -t secure-scan-action .

run:
	docker run --rm -v $(PWD):/workspace -w /workspace secure-scan-action --scanners trivy

scan: build run
