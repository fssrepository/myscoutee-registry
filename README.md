# MyScoutee Registry

MyScoutee Registry is the Go service that provides signed deployment
registration, aggregate reporting, operator-network records, announcements,
settlement evidence, and exit controls. It stores its authoritative state in
SQLite and protects protocol history with Ed25519 signatures, an append-only
hash-linked ledger, and Merkle proofs.

## Controlled manuals

Both released manuals are **Confidential — Internal Distribution Only**.
Keep the documents and the Registry release material inside approved access
and distribution controls.

| Manual | Use | PDF |
|---|---|---|
| Registry Operator Manual 1.0.0 | Installation, host requirements, configuration, security, backup, recovery, and production operation | [PDF](guides/manuals/MyScoutee_Registry_Operator_Manual_v1.0.0_EN.pdf) |
| Registry Protocol Developer Manual 1.0.0 | HTTP contracts, canonical payloads, signatures, protocol rails, and integration behavior | [PDF](guides/manuals/MyScoutee_Registry_Protocol_Developer_Manual_v1.0.0_EN.pdf) |

The manuals are the authoritative operating and protocol references; this
README intentionally does not repeat their procedures.

## Development/demo quick start

The root [`compose.yaml`](compose.yaml) starts the isolated, seeded Registry
demo on loopback:

```bash
cp .env.example .env
docker compose up --build -d
curl --fail --show-error http://127.0.0.1:8081/healthz
```

The container listens on port `8080`; the default host mapping is
`127.0.0.1:8081`. The root Compose stack is for development and demo use, not
production deployment.

## Production release

The sole production release path is documented in
[`packaging/README.md`](packaging/README.md). From the repository root:

```bash
bash packaging/scripts/build-production.sh
bash packaging/scripts/package-production.sh
```

Release outputs:

| Artifact | Path |
|---|---|
| Debian package | `packaging/dist/myscoutee-registry_1.0.0_amd64.deb` |
| Operator client tools | `packaging/dist/myscoutee-registry-client-tools_1.0.0.tar.gz` |

The Debian package contains exactly one byte-identical copy of the versioned
client-tools archive at
`/usr/share/myscoutee-registry/myscoutee-registry-client-tools_1.0.0.tar.gz`.
It does not install extracted client scripts.

The package also carries the versioned Registry and Nginx production images.
Its installed Compose model is build-free and contains no source checkout,
source mount, development hot-sync, or runtime image build. Follow the
Operator Manual and packaging guide for installation and qualification.

## Development and verification

The module requires Go 1.25 and uses the CGo-free `modernc.org/sqlite` driver.
Primary test entry points are:

```bash
go test ./...
go test -tags=e2e -count=1 -v ./e2e
bash packaging/tests/docker-build-context-test.sh
bash packaging/tests/package-contract-test.sh
bash packaging/tests/client-tools-test.sh
bash packaging/tests/verify-deployment-test.sh
```

The standalone Java-to-Go qualification rail is:

```bash
bash tools/qualify-java-rails.sh
```

Set `MYSCOUTEE_BACKEND_ROOT` when the compatible backend checkout is not next
to this repository.

## Source map

| Path | Responsibility |
|---|---|
| [`cmd/registry`](cmd/registry/) | Registry executable and local administrative commands |
| [`internal/httpapi`](internal/httpapi/) | HTTP routing, validation, and response contracts |
| [`internal/protocol`](internal/protocol/) | Canonical protocol types, commitments, and signatures |
| [`internal/service`](internal/service/) | Registry domain rules and signed workflows |
| [`internal/store/sqlite`](internal/store/sqlite/) | SQLite persistence, migrations, integrity, ledger, and Merkle state |
| [`guides/manuals`](guides/manuals/) | Controlled released manuals and protocol evidence |
| [`packaging`](packaging/) | Production images, Debian package, client tools, and release tests |
| [`e2e`](e2e/) | Standalone Registry process tests |
