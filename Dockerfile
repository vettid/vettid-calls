# syntax=docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# VettID calling service: the TURN/STUN server image (CALLING-SERVICE 0.2.0
# §4.1, §4.4): coturn 4.18.0, pinned by digest, with turn-agent as the entry
# point. turn-agent renders coturn's configuration (§7.2) from the secret,
# runs coturn and turns its counters into metrics (§10).
#   docker build -t vettid-calls-turn .
#   docker buildx build --platform linux/amd64,linux/arm64 -t vettid-calls-turn .
#   make image-repro        # two clean builds, compared
#
# Run it with host networking (the relay ports are 49152-65535), a read-only
# root, a tmpfs for the rendered configuration, and NO log driver: coturn's
# log is read by turn-agent in memory and never kept (§10):
#   docker run --network host --read-only --log-driver none \
#     --tmpfs /run/vettid-calls:rw,mode=0700,uid=65534,gid=65534 \
#     -e CALLS_TURN_HOST=... -e CALLS_PRIVATE_IPV4=... -e CALLS_PUBLIC_IPV4=... \
#     -e CALLS_IPV6=... -e CALLS_OWN_NETWORKS=... -e CALLS_SECRET_ID=... \
#     -e AWS_REGION=... -e CALLS_METRICS_NAMESPACE=vettid-org/staging/calls \
#     vettid-calls-turn@sha256:<digest>
#
# Reproducible: both base images are pinned by digest, turn-agent is built
# -trimpath with an empty build id and no VCS stamping, and nothing but the
# binary is added to coturn's image. With a fixed SOURCE_DATE_EPOCH (make
# image-repro) two builds of one commit give the same image.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/turn-agent ./cmd/turn-agent

# coturn 4.18.0 (docker/4.18.0-r0, 2026-09-08), Debian trixie, built by the
# coturn project with Prometheus support (libmicrohttpd). Multi-arch index.
FROM docker.io/coturn/coturn:4.18.0-r0@sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3
COPY --from=build /out/turn-agent /usr/local/bin/turn-agent
USER nobody:nogroup
EXPOSE 3478/udp 3478/tcp
ENTRYPOINT ["/usr/local/bin/turn-agent"]
