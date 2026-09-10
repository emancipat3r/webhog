# Build webhog with the version and commit stamped in, so `webhog --version`
# and the "webhog" field of every report identify the exact build.
MODULE  := github.com/emancipat3r/webhog
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT)

.PHONY: build install test vet clean

build:
	go build -ldflags "$(LDFLAGS)" -o webhog ./cmd/webhog

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/webhog

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f webhog
