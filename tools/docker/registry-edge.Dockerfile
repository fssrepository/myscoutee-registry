# syntax=docker/dockerfile:1

ARG NGINX_BASE_IMAGE=nginx:1.28-alpine
FROM ${NGINX_BASE_IMAGE}

ARG MYSCOUTEE_VERSION=1.0.0

LABEL org.opencontainers.image.title="MyScoutee Registry Edge" \
      org.opencontainers.image.description="TLS and request-boundary edge for the MyScoutee Registry" \
      org.opencontainers.image.version="${MYSCOUTEE_VERSION}"

COPY --chown=root:root --chmod=0444 tools/docker/registry.conf.template \
    /etc/nginx/templates/registry.conf.template
