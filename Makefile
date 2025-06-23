.PHONY: fmt vet lint test tidy docker precommit ci

GOFILES := $(shell find . -name '*.go' -not -path './.git/*')

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

tidy:
	go mod tidy

docker:
	docker build -t authtranslator .

precommit: fmt vet lint

ci: precommit tidy
	go test -coverprofile=coverage.out ./...
