.PHONY: fmt vet lint test docker precommit

GOFILES := $(shell find . -name '*.go')

fmt:
	gofmt -w $(GOFILES)

vet:
	go vet ./...


lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi
test:
	go test ./...

docker:
	docker build -t authtranslator .

precommit: fmt vet lint
