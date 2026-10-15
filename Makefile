# code-detector — local build/test/release shortcuts
BINARY := code-detector
GO := go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt clean snapshot release-check

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l .

# Local test release (builds dist/ without publishing; requires goreleaser)
snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f $(BINARY)
	rm -rf dist/
