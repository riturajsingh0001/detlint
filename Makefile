GO      ?= go
BINARY  ?= detlint
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
PKG     := github.com/riturajsingh0001/detlint/internal/cli
LDFLAGS := -s -w \
	-X $(PKG).Version=$(VERSION) \
	-X $(PKG).Commit=$(COMMIT) \
	-X $(PKG).Date=$(DATE)

.PHONY: all build install test test-race cover vet fmt lint demo clean release-snapshot help

all: build

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/detlint

install:
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/detlint

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

demo:
	$(GO) run ./cmd/detlint demo --color never

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f $(BINARY) $(BINARY).exe coverage.out
	rm -rf dist

help:
	@echo "make build             build ./$(BINARY)"
	@echo "make install           install to GOPATH/bin"
	@echo "make test              run unit tests"
	@echo "make test-race         run tests with the race detector"
	@echo "make cover             write coverage.out and print a summary"
	@echo "make vet               run go vet"
	@echo "make fmt               run gofmt"
	@echo "make lint              run golangci-lint"
	@echo "make demo              run the embedded demo"
	@echo "make release-snapshot  build a local goreleaser snapshot"
	@echo "make clean             remove build artifacts"
