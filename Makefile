SHELL := /bin/sh

VERSION ?= 1.5.0
GO      ?= go
DIST    := dist
LDFLAGS := -s -w -X github.com/subsll/subsoil/internal/model.Version=$(VERSION)

.PHONY: all build local test race vet fmt linux checksums clean

all: build

## build: native binary for the current platform
build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" \
		-o $(DIST)/subsoil ./cmd/subsoil

## local: versioned native binary (used for the smoke test)
local:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" \
		-o $(DIST)/subsoil_$(VERSION)_$(shell $(GO) env GOOS)_$(shell $(GO) env GOARCH) ./cmd/subsoil

## linux: static Linux binaries for amd64, arm64, armv7 and 386
linux:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST)/subsoil_$(VERSION)_linux_amd64 ./cmd/subsoil
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST)/subsoil_$(VERSION)_linux_arm64 ./cmd/subsoil
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST)/subsoil_$(VERSION)_linux_armv7 ./cmd/subsoil
	CGO_ENABLED=0 GOOS=linux GOARCH=386 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST)/subsoil_$(VERSION)_linux_386 ./cmd/subsoil

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

checksums:
	@cd $(DIST) && \
	if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum subsoil_* > SHA256SUMS; \
	else \
		shasum -a 256 subsoil_* > SHA256SUMS; \
	fi && cat SHA256SUMS

clean:
	rm -rf $(DIST)
