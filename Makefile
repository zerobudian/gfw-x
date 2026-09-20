# GFW X - The firewall evolves. So does the gateway.
# Build, test, benchmark and package GFW X.

BINARY   := gfwx
VERSION  ?= 0.1.0
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w \
	-X gfw-x/internal/version.Version=$(VERSION) \
	-X gfw-x/internal/version.Commit=$(COMMIT) \
	-X gfw-x/internal/version.Date=$(DATE)
WEB_DIR  := web
EMBED_DIST := internal/api/dist
GO       ?= go

.PHONY: all web build test vet bench release docker run clean help

all: build

## web: build the React+TS dashboard into internal/api/dist (embedded)
web:
	cd $(WEB_DIR) && npm install && npm run build

## build: build web (if dist missing) then compile the single binary
build: web
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/gfwx

## test: run unit tests + benchmarks
test:
	$(GO) test ./...

## vet: static analysis
vet:
	$(GO) vet ./...

## bench: run the full performance benchmark
bench:
	$(GO) run ./cmd/gfwx bench --flows 20000 --workers 4

## release: cross-compile release artifacts into ./dist
release: web
	@mkdir -p dist
	@set -e; for t in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64"; do \
		set -- $$t; os=$$1; arch=$$2; \
		out=dist/$(BINARY)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out=$$out.exe; fi; \
		echo ">> building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/gfwx; \
	done
	@echo ">> artifacts in ./dist"
	@ls -lh dist

## docker: build the container image
docker:
	docker build -t gfw-x:$(VERSION) .

## run: run the gateway with the default config
run:
	$(GO) run ./cmd/gfwx run --config configs/config.yaml

## clean: remove build artifacts
clean:
	rm -rf $(BINARY) dist
	rm -rf $(WEB_DIR)/node_modules
	rm -rf $(EMBED_DIST)

## help: show this help
help:
	@grep -hE '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk '{printf "%-12s %s\n", $$1, $$2}'