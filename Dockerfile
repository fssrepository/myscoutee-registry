# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS build

ARG MYSCOUTEE_VERSION=1.5.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY registry/ ./registry/
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X github.com/fssrepository/myscoutee-registry/registry/buildinfo.Version=${MYSCOUTEE_VERSION}" \
    -o /out/registry \
    .
RUN mkdir -p /runtime-data /runtime-tmp /runtime-run/registry-key \
    && chown -R 65532:65532 /runtime-data /runtime-tmp /runtime-run

FROM scratch

ARG MYSCOUTEE_VERSION=1.5.0
LABEL org.opencontainers.image.version="${MYSCOUTEE_VERSION}"

COPY --from=build --chown=65532:65532 /out/registry /registry
COPY --from=build --chown=65532:65532 /runtime-data /data
COPY --from=build --chown=65532:65532 /runtime-tmp /tmp
COPY --from=build --chown=65532:65532 /runtime-run /run

USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD ["/registry", "healthcheck"]

ENTRYPOINT ["/registry"]
