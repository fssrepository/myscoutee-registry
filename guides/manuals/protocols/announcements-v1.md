# MyScoutee signed announcements and update manifests v1

The registry exposes a public, read-only feed that deployments poll through
their local Java backend. The registry never opens an inbound connection to a
deployment, pushes a command, downloads an artifact, or starts an upgrade.

An announcement can inform operators about the community, maintenance, a
security issue, or an available release. An `UPDATE` announcement contains a
signed manifest. That manifest is an offer to inspect; it is not installation
consent.

The operator UI can derive an “update available” badge from a newer active
`UPDATE`/`AVAILABLE` entry and its locally cached last-seen sequence. Download
bytes, package verification, backup, privileged Debian installation, and
installer/post-upgrade progress belong to the local Java/host-helper workflow.
That local workflow may stream status to its browser, but no progress or shell
command comes from this registry feed.

## Publication boundary

There is deliberately no public publish endpoint. A registry administrator
uses the local binary against the registry's own SQLite volume and signing key:

```text
/registry publish-announcement --file PATH
/registry publish-announcement --file -
```

`--file -` reads one strict UTF-8 JSON object from standard input. The decoder
rejects duplicate fields, unknown fields, multiple JSON values, invalid UTF-8,
and files larger than 256 KiB. `publication_id` is a caller-chosen, printable
idempotency token. Repeating it with identical normalized content returns the
original signed entry with `"duplicate":true`; changing the content is a
conflict.

The command emits one JSON `AnnouncementPublishResult` to standard output:

```json
{
  "duplicate": false,
  "announcement": {
    "sequence": 1,
    "announcement_id": "ann_...",
    "announcement_hash": "sha256:...",
    "signature": "..."
  }
}
```

The abbreviated object above documents the important output fields; the real
result includes the complete signed entry. The command can run while the HTTP
server is active. Both processes use SQLite WAL, the configured busy timeout,
and a short atomic append transaction against the same volume.

Show local help without opening the database:

```bash
/registry publish-announcement --help
```

Against the separately deployed production Compose stack, keep the reviewed
JSON on the registry host and pipe it into the already-running registry
container. The file is not uploaded through HTTP:

```bash
cd /path/to/myscoutee-registry
docker compose \
  --env-file /etc/myscoutee-registry.env \
  -f compose.production.yaml \
  exec -T registry \
  /registry publish-announcement --file - \
  < /secure/reviewed-announcement.json
```

The strict templates are
[`examples/announcement-general.json`](examples/announcement-general.json)
and
[`examples/announcement-update.json`](examples/announcement-update.json).
Replace every `example.invalid`, digest, key ID, detached signature, timestamp,
version, and publication ID before publishing. Templates are files only; no
announcement is seeded into a development or production database.

Publication is append-only and cannot be edited or deleted through supported
operations. Validate the JSON and take a consistent database/key backup before
a production publication. Quiesce the service for a raw filesystem copy, or
use SQLite's online backup API/storage-level atomic snapshots. The database
and registry signing key are one recovery unit. File access must remain
restricted to the registry runtime UID; do not copy the registry private key
into a publication JSON document.

## Announcement JSON

Kinds are:

- `GENERAL`
- `UPDATE`
- `MAINTENANCE`
- `SECURITY`

Severity is `INFO`, `NOTICE`, `WARNING`, or `CRITICAL`.

`published_at` and optional `expires_at` are RFC 3339 UTC timestamps ending in
`Z`; expiry must be after publication. Scheduled future entries remain absent
from feeds until publication time. Expired entries are omitted by default.

Human text uses exactly one of:

- `title_key` plus `body_key`, for a translation bundled by deployments; or
- one to sixteen unique lowercase locale objects containing plain-text
  `title` and `body`.

Links are bounded and must use absolute HTTPS URLs without credentials or
fragments. The service sorts locale/link collections before hashing, so file
ordering does not create different signed content.

## Update manifest

Only `UPDATE` can contain `update_manifest`, and every `UPDATE` must contain
one. The manifest validates:

- schema `manifest_version` `1`;
- canonical Semantic Version values for the release and compatibility range;
- a canonical lowercase release channel;
- a manifest publication time equal to its announcement;
- an absolute HTTPS artifact URL whose path names a `.deb` package;
- artifact size from 1 byte through 16 GiB;
- a lowercase `sha256:` artifact digest;
- a deterministic package-signing key ID and canonical Ed25519 detached
  signature;
- an absolute HTTPS release-notes URL;
- backup requirement and expected downtime; and
- an explicit `AVAILABLE`, `REVOKED`, or `SUPERSEDED` state.

The package-signing identity is independent from the registry identity:

```text
pkey_<first 32 lowercase hex characters of SHA-256 over complete Ed25519 SPKI DER>
```

The detached package signature is Ed25519 over:

```text
myscoutee-release-package-v1
<release_version>
<channel>
<artifact_size_bytes as base-10 integer>
<artifact_sha256>
```

Every line is joined with LF and the message has one final LF. The registry
strictly validates the signature encoding and binds it into the registry-signed
manifest. The deployment verifies it against a separately pinned
package-signing public key after downloading and SHA-256-checking the staged
artifact. A registry key is never accepted as an implicit package key.

An available replacement may set `supersedes_version`. Revocation and
supersession never modify an older row; publish a new entry with a new
`publication_id` and the same exact release/artifact identity:

```json
{
  "status": "REVOKED",
  "revocation_reason": "Package withdrawn after a failed post-upgrade health check."
}
```

For `REVOKED`, remove `supersedes_version` and
`superseded_by_version`. To mark an old release superseded:

```json
{
  "status": "SUPERSEDED",
  "superseded_by_version": "1.2.4"
}
```

For `SUPERSEDED`, remove `supersedes_version` and
`revocation_reason`. All other required manifest fields remain present so the
signed record identifies the exact package being revoked or superseded.

## Public pull feed

```text
GET /v1/announcements
```

Supported single-occurrence query parameters:

- `kind=GENERAL|UPDATE|MAINTENANCE|SECURITY`
- `severity=INFO|NOTICE|WARNING|CRITICAL`
- `channel=<lowercase-channel>` (alone or with `kind=UPDATE`)
- `include_expired=true|false` (default `false`)
- `limit=1..100` (default `20`)
- `cursor=<opaque-registry-signed-cursor>`

Examples:

```bash
curl --fail --show-error \
  'https://registry.example.invalid/v1/announcements?limit=20'

curl --fail --show-error \
  'https://registry.example.invalid/v1/announcements?kind=UPDATE&channel=stable&limit=20'
```

Entries are newest-first. A first page freezes:

- registry scope and signing key ID;
- one `as_of` time used for publication/expiry filtering;
- the append-only announcement sequence and head hash; and
- the kind, severity, channel, and expiry filters.

The response carries a registry-signed snapshot plus individually
registry-signed, hash-linked announcement entries. `next_cursor` contains the
same snapshot/filter boundary and last sequence, signed by the registry. Repeat
the same filters when following a cursor. A changed filter, malformed cursor,
or modified cursor signature fails closed.

Nested content is bound through `content_hash`, `links_hash`, and
`update_manifest_hash`. Each entry hashes the previous announcement hash, and
startup, health, publication, and feed reads verify the complete chain and
every registry signature. The feed never projects or repairs corrupted data.

### Signature verification

All canonical messages below join fields with LF and end with one final LF.
SHA-256 values use the protocol's lowercase `sha256:` format.

Localizations are sorted by `locale`; each title/body is hashed as its raw
UTF-8 bytes so a localized body can safely contain LF:

```text
myscoutee-registry-announcement-content-v1
<title_key>
<body_key>
<localization count>
<locale 1>
<sha256(title 1 UTF-8)>
<sha256(body 1 UTF-8)>
...
```

Links are sorted by `relation`, then URL:

```text
myscoutee-registry-announcement-links-v1
<link count>
<relation 1>
<URL 1>
...
```

An absent update manifest uses the all-zero protocol chain hash. Otherwise,
`update_manifest_hash` hashes:

```text
myscoutee-registry-update-manifest-v1
<manifest_version>
<release_version>
<channel>
<published_at>
<minimum_compatible_version>
<maximum_compatible_version>
<artifact_url>
<artifact_size_bytes>
<artifact_sha256>
<package_signing_key_id>
<package_signature>
<release_notes_url>
<backup_required as true|false>
<expected_downtime_seconds>
<status>
<supersedes_version>
<superseded_by_version>
<revocation_reason>
```

The announcement chain hash is SHA-256 over:

```text
myscoutee-registry-announcement-entry-v1
<protocol_version>
<registry_scope>
<sequence>
<announcement_id>
<publication_id>
<kind>
<severity>
<published_at>
<expires_at>
<content_hash>
<links_hash>
<update_manifest_hash>
<previous_announcement_hash>
<accepted_at>
<registry_key_id>
```

Each entry's `signature` is the registry Ed25519 signature over:

```text
myscoutee-registry-announcement-receipt-v1
<announcement_hash>
<registry_scope>
<registry_key_id>
```

The signed snapshot hash input is:

```text
myscoutee-registry-announcement-snapshot-hash-v1
<snapshot_id>
<as_of>
<through_sequence>
<announcement_head_hash>
<kind filter>
<severity filter>
<channel filter>
<include_expired as true|false>
<created_at>
<registry_scope>
<registry_key_id>
```

Its `signature` covers:

```text
myscoutee-registry-announcement-snapshot-receipt-v1
<snapshot_hash>
<registry_scope>
<registry_key_id>
```

The response intentionally omits a trust-on-first-use public key. Java verifies
entry and snapshot signatures with the registry public key already pinned by
the explicit identity-preflight flow. A cursor is
`base64url(raw JSON payload) + "." + base64url(Ed25519 signature)`; its
signature message is the ASCII prefix
`myscoutee-registry-announcement-cursor-v1\n` followed by the exact payload
bytes. Clients should treat the cursor as opaque.

## Development Compose

For the application development stack, start it normally, then from the
application server directory publish into the already-running `registry`
container and its persistent `registry-dev-demo-data` volume:

```bash
cd /home/raxim/workspace/myscoutee-backend/server

docker compose -f docker-compose-dev.yml exec -T registry \
  /registry publish-announcement --file - \
  < ../../myscoutee-registry/guides/manuals/protocols/examples/announcement-general.json

curl --fail --show-error \
  'http://127.0.0.1:8081/v1/announcements?limit=20'

docker compose -f docker-compose-dev.yml restart registry

curl --fail --show-error \
  'http://127.0.0.1:8081/v1/announcements?limit=20'
```

The second GET demonstrates persistence across restart. To deliberately erase
the complete local registry identity, deployments, ledger, claims, and
announcements, stop the development stack and remove only its named registry
volume:

```bash
cd /home/raxim/workspace/myscoutee-backend/server
docker compose -f docker-compose-dev.yml down
docker volume rm myscoutee-registry-dev-demo-data-v1
```

If `LOCAL_REGISTRY_DEMO_VOLUME_NAME` was overridden, remove that exact volume
name instead. This reset is destructive and is never a production recovery
procedure.
