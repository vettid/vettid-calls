GO        ?= go
BIN       ?= bin
DIST      ?= dist
IMAGE     ?= vettid-calls-turn:dev
PLATFORMS ?= linux/amd64,linux/arm64
VERSION   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
LDFLAGS   := -s -w -buildid= -X main.version=$(VERSION)
CONTAINER ?= $(shell command -v docker || command -v podman)
ARCHIVE   := vettid-calls-issuer-linux-arm64.zip
RENEWER   := vettid-calls-renewer-linux-arm64.zip
# The image's and the archive's timestamps: the commit's, so that two
# builds of one commit are the same image and the same archive.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
# IMAGE_MIRROR=REGISTRY/PATH (CI: ghcr.io/vettid/mirror, vettid.org
# .github/mirror): the Dockerfiles' digest-pinned docker.io base images,
# same digests, from that mirror (--build-context); the Dockerfiles and the
# outputs are unchanged.
IMAGE_MIRROR ?=
mirror_contexts = $(if $(IMAGE_MIRROR),$(shell sed -nE 's|^FROM (--platform=[^ ]+ )?(docker\.io/[^ ]*/([^/:@ ]+)(:[^@ ]+)?@(sha256:[0-9a-f]{64})).*|--build-context \2=docker-image://$(IMAGE_MIRROR)/\3@\5|p' $(1)))
# Tests run one package at a time: a developer machine has other work to do.
TESTFLAGS ?= -p 1

.PHONY: all build test race lint vet staticcheck scan image image-multiarch image-repro archive archive-local archive-repro tidy clean

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -p 1 -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN)/vettid-calls ./cmd/vettid-calls
	CGO_ENABLED=0 $(GO) build -p 1 -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN)/turn-agent ./cmd/turn-agent
	CGO_ENABLED=0 $(GO) build -p 1 -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN)/callsctl ./cmd/callsctl
	CGO_ENABLED=0 $(GO) build -p 1 -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN)/calls-renewer ./cmd/calls-renewer

test:
	$(GO) test $(TESTFLAGS) ./...

race:
	$(GO) test -race -p 1 -count=1 ./...

vet:
	$(GO) vet ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

lint: vet staticcheck

scan:
	gitleaks git --redact .

# The TURN/STUN server image (coturn + turn-agent).
image:
	$(CONTAINER) build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

image-multiarch:
	docker buildx build --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# Two clean builds (no layer cache) of the working tree with the commit's
# timestamp; fails unless both give the same image id. podman takes the
# timestamp with --timestamp; docker (BuildKit) takes SOURCE_DATE_EPOCH
# and rewrites layer timestamps.
image-repro:
	@set -e; \
	if $(CONTAINER) --version | grep -qi podman; then \
	  build() { $(CONTAINER) build --no-cache --timestamp $(SOURCE_DATE_EPOCH) $(call mirror_contexts,Dockerfile) --build-arg VERSION=$(VERSION) -t $$1 . >/dev/null; }; \
	else \
	  build() { SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(CONTAINER) buildx build --no-cache $(call mirror_contexts,Dockerfile) --build-arg VERSION=$(VERSION) \
	    --output type=docker,name=$$1,rewrite-timestamp=true . >/dev/null; }; \
	fi; \
	build vettid-calls-turn:repro-a; build vettid-calls-turn:repro-b; \
	a=$$($(CONTAINER) image inspect --format '{{.Id}}' vettid-calls-turn:repro-a); \
	b=$$($(CONTAINER) image inspect --format '{{.Id}}' vettid-calls-turn:repro-b); \
	echo "build A: $$a"; echo "build B: $$b"; \
	$(CONTAINER) rmi vettid-calls-turn:repro-a vettid-calls-turn:repro-b >/dev/null 2>&1 || true; \
	test "$$a" = "$$b" && echo "reproducible" || { echo "NOT reproducible"; exit 1; }

# The function archives (the issuer's and the renewer's), built in the
# pinned toolchain image.
archive:
	@mkdir -p $(DIST)
	$(CONTAINER) build --no-cache -f Dockerfile.issuer --target archive $(call mirror_contexts,Dockerfile.issuer) \
	  --build-arg VERSION=$(VERSION) --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) --output type=local,dest=$(DIST) .
	@cd $(DIST) && sha256sum $(ARCHIVE) $(RENEWER)

# Two clean builds of the archives; fails unless each has one SHA-256.
archive-repro:
	@set -e; rm -rf $(DIST)/repro-a $(DIST)/repro-b; \
	$(MAKE) --no-print-directory archive DIST=$(DIST)/repro-a >/dev/null; \
	$(MAKE) --no-print-directory archive DIST=$(DIST)/repro-b >/dev/null; \
	for z in $(ARCHIVE) $(RENEWER); do \
	  a=$$(sha256sum < $(DIST)/repro-a/$$z | cut -d' ' -f1); \
	  b=$$(sha256sum < $(DIST)/repro-b/$$z | cut -d' ' -f1); \
	  echo "$$z A: $$a"; echo "$$z B: $$b"; \
	  test "$$a" = "$$b" || { echo "$$z NOT reproducible"; exit 1; }; \
	done; echo "reproducible"

# The same archives with the local Go toolchain, without a container
# (their SHA-256 match the container's only with the same Go version).
archive-local:
	@mkdir -p $(DIST)/local/issuer $(DIST)/local/renewer
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -p 1 -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(DIST)/local/issuer/bootstrap ./cmd/vettid-calls
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -p 1 -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(DIST)/local/renewer/bootstrap ./cmd/calls-renewer
	$(GO) run ./tools/mkzip -o $(DIST)/local/$(ARCHIVE) -mtime $(SOURCE_DATE_EPOCH) $(DIST)/local/issuer/bootstrap=bootstrap
	$(GO) run ./tools/mkzip -o $(DIST)/local/$(RENEWER) -mtime $(SOURCE_DATE_EPOCH) $(DIST)/local/renewer/bootstrap=bootstrap
	@cd $(DIST)/local && sha256sum $(ARCHIVE) $(RENEWER)

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN) $(DIST)
