.PHONY: build run test

build:
	docker build -t secure-scan-action .

run:
	docker run --rm -v $(PWD):/workspace -w /workspace secure-scan-action --scanners trivy --severity HIGH

scan: build run
