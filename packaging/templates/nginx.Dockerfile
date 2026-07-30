# syntax=docker/dockerfile:1

FROM nginx:1.28-alpine

ARG MYSCOUTEE_VERSION=1.0.0
LABEL org.opencontainers.image.title="MyScoutee Registry Nginx" \
      org.opencontainers.image.description="TLS reverse proxy for MyScoutee Registry" \
      org.opencontainers.image.version="${MYSCOUTEE_VERSION}"

RUN mkdir -p /etc/nginx/templates \
    && chmod 0755 /etc/nginx/templates

COPY --chown=root:root --chmod=0444 nginx.conf.template \
    /etc/nginx/templates/registry.conf.template
