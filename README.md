# MyScoutee Registry

The Registry lets independent, compatible applications join a shared operator
network without surrendering their brand, infrastructure, community, business,
or data. It records participation and deployment contributions, providing an
accounting basis if participants pursue a future acquisition, merger, or other
exit. Participation is optional, and clients need only implement the Registry
protocol—not use MyScoutee.

## Downloads

### Manuals

| Manual | Document version | Applies to | PDF |
|---|---:|---:|---|
| Operations Manual | 1.0.0 | MyScoutee 1.0.0 | [PDF](guides/manuals/MyScoutee_Registry_Operations_Manual_v1.0.0_EN.pdf) |
| Protocol Developer Manual | 1.0.0 | MyScoutee 1.0.0 | [PDF](guides/manuals/MyScoutee_Registry_Protocol_Developer_Manual_v1.0.0_EN.pdf) |

The manuals are the authoritative operating and protocol references.

## Compose environments

The standalone development/demo Registry starts explicitly and does not restart
on host boot or container failure:

```sh
docker compose -f compose.dev.yaml up -d --build
```

Plain `docker compose` uses the same development model through `compose.yaml`.
The demo scope, demo database/key paths and existing `registry-demo-data` volume
are preserved. A provisioned development key can still be supplied with:

```sh
REGISTRY_PROVISIONED_KEY_PATH=/absolute/path/registry-signing-key.pem \
  docker compose -f compose.dev.yaml -f compose.provisioned-key.yaml up -d --build
```

For standalone E2E, use the disposable project with its own database, signing
key, VOPRF keyring and volume:

```sh
docker compose -f compose.e2e.yaml up -d --build
# Only this disposable E2E project's state is removed:
docker compose -f compose.e2e.yaml down --volumes
```

E2E uses `myscoutee-registry:1.3.0-e2e` (`REGISTRY_E2E_IMAGE` override),
`restart: "no"`, and loopback port 18081 (`REGISTRY_E2E_PORT` override).
It requires Docker Compose 2.24.4 or later for the explicit port-list override.
Its `myscoutee-registry-e2e_registry-e2e-data` volume is separate from the dev
volume and production bind mount. The repository entrypoints use separate
projects: existing `myscoutee-registry` for dev, `myscoutee-registry-e2e` for
E2E, and `myscoutee-registry-prod` for production.

Production uses the existing packaged Registry + Nginx model, with demo seeding
disabled, its production state/TLS configuration and `restart: unless-stopped`:

```sh
docker compose --env-file /etc/myscoutee-registry/registry.env \
  -f compose.prod.yaml up -d
```

`compose.prod.yaml` includes `packaging/compose/compose.yaml`; it does not define
a second production stack. Prepare the packaged images, production environment
and TLS material using the [production packaging instructions](packaging/README.md).
Do not use the development `.env.example` as production configuration. Installed
packages continue to use their existing `systemctl`/`registry-compose.sh` route.
Use the same environment file and `-f` selection for later lifecycle commands.
The backend's integrated dev/E2E stack continues to use its own Compose files.
