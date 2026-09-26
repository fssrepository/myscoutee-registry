# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS build

ARG MYSCOUTEE_VERSION=1.3.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -tags netgo,osusergo \
    -ldflags="-s -w -buildid= -X github.com/fssrepository/myscoutee-registry/internal/buildinfo.Version=${MYSCOUTEE_VERSION}" \
    -o /out/registry \
    ./cmd/registry
RUN install -d -o 65532 -g 65532 -m 0700 /runtime/data /runtime/tmp

FROM scratch

ARG MYSCOUTEE_VERSION=1.3.0
LABEL org.opencontainers.image.title="MyScoutee Registry" \
      org.opencontainers.image.description="MyScoutee central Registry" \
      org.opencontainers.image.version="${MYSCOUTEE_VERSION}"

COPY --from=build --chown=65532:65532 /out/registry /registry
COPY --from=build --chown=65532:65532 /runtime/data /data
COPY --from=build --chown=65532:65532 /runtime/tmp /tmp

USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD ["/registry", "healthcheck"]
ENTRYPOINT ["/registry"]
