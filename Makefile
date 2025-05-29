.PHONY: fmt vet test docker

GOFILES := $(shell find . -name '*.go')

fmt:
	gofmt -w $(GOFILES)

vet:
	go vet ./...

test:
	go test ./...

docker:
	docker build -t authtranslator .
