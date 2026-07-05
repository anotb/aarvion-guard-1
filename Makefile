VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST := dist
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: build vet test release clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(DIST)/aarvion-guard ./cmd/guard

vet:
	go vet ./...

test:
	go test ./...

# Cross-compiled release binaries. macOS artifacts still need codesign +
# notarize and Windows needs Authenticode before distribution (see B plan §8).
release:
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o $(DIST)/aarvion-guard_$${os}_$${arch} ./cmd/guard; \
	done

clean:
	rm -rf $(DIST)
