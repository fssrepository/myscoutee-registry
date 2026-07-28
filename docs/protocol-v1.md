# MyScoutee Registry Protocol v1

This document fixes the wire and signature format for the first registry
milestone. It is intentionally limited to deployment registration, one
installation-test MAU batch, signed receipts, and daily checkpoints.

## Encoding rules

- HTTP JSON is UTF-8 with `Content-Type: application/json`.
- Protocol version is the JSON string `"1"`.
- Timestamps are RFC 3339 UTC timestamps ending in the literal `Z`.
- Periods use `YYYY-MM`.
- Checkpoint dates use `YYYY-MM-DD` in UTC.
- Binary values use standard padded RFC 4648 base64.
- SHA-256 values use `sha256:` followed by 64 lowercase hexadecimal digits.
- Deployment IDs are `dep_` followed by exactly 32 lowercase hexadecimal
  characters.
- Batch IDs are `batch_` followed by exactly 32 lowercase hexadecimal
  characters.
- Canonical values must not contain CR or LF.
- Every canonical message is its listed fields joined with LF (`\n`) and has
  one final LF.
- Signatures are Ed25519 signatures over the canonical message bytes, not over
  incidental JSON serialization.
- Public keys are X.509 SubjectPublicKeyInfo DER values containing an Ed25519
  public key.

The fingerprint of a public key is:

```text
sha256:<lowercase SHA-256 hex of the complete SPKI DER value>
```

A registry signing key ID is deterministic:

```text
rkey_<first 32 hexadecimal characters of the public-key fingerprint digest>
```

The all-zero chain hash is:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

## Sovereign registry scope

Every registry instance has one mandatory, immutable `registry_scope`. There
are no built-in product, geography, or parent modes and there is no default.
The infrastructure owner chooses an explicit deployment-specific value, for
example:

```text
example:region-a
```

Different scope values are separate sovereign namespaces. Deployments choose
one registry and communicate with it directly. Registry servers do not
forward, relay, or synchronize signed requests across a scope boundary.
Operators use separate databases, signing keys, volumes, backups, and public
endpoints for independently governed scopes.

Scope values are 3-128 characters, begin with a lowercase ASCII letter or
digit, and otherwise contain only lowercase ASCII letters, digits, `.`, `:`,
`_`, or `-`. The scope is persisted with the registry identity and cannot be
changed for an existing database. It is included in every signature and hash
listed below, preventing a request, receipt, ledger entry, or checkpoint for
one parent domain from being accepted as belonging to another.

## Registry identity preflight

Before an operator confirms enrollment, a deployment can inspect the
registry's immutable public identity without creating any central state:

```text
GET /v1/registry/identity
```

The response is:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64 SPKI DER>",
  "signature": "<base64 Ed25519 signature>"
}
```

The registry identity signature input is:

```text
myscoutee-registry-identity-v1
<protocol_version>
<registry_scope>
<registry_key_id>
<registry_public_key>
```

The response is self-signed by `registry_public_key`. A client must verify that
the public key parses as Ed25519, that `registry_key_id` is derived from its
complete SPKI DER value as specified above, and that `signature` verifies over
the canonical message before displaying or pinning the identity. This proves
the endpoint controls the advertised key; the operator must still compare and
explicitly approve the intended endpoint, scope, and key ID.

The endpoint is read-only, rejects query strings and percent-encoded path
aliases, and appends no ledger record. It fails closed when full registry
integrity verification fails.

## Generic signed request

The request signature input is:

```text
myscoutee-registry-request-v1
<uppercase HTTP method>
<request path>
<protocol_version>
<registry_scope>
<signer>
<timestamp>
<nonce>
<idempotency_key>
<payload_hash>
```

For registration, `signer` is the submitted public-key fingerprint. For a batch,
it is the assigned deployment ID.

The default accepted timestamp skew is five minutes. Nonces and idempotency keys
are printable ASCII tokens between 8 and 128 characters.

Idempotency behavior is:

1. The signature and timestamp are always validated first.
2. Repeating the same signer/idempotency key with the same payload hash returns
   the original stored result and does not append another ledger entry.
3. Repeating that idempotency key with a different payload hash is a conflict.
4. Reusing an accepted nonce for a different request is a replay conflict.
5. A retry may use a fresh timestamp, nonce, and signature while preserving the
   original idempotency key and payload.

## Deployment registration

Endpoint:

```text
POST /v1/deployments/register
```

Registration payload hash input:

```text
myscoutee-registry-registration-payload-v1
<key_algorithm>
<public_key>
<software_version>
```

`key_algorithm` must be `Ed25519`. The request is:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "timestamp": "2026-07-28T00:00:00Z",
  "nonce": "nonce_...",
  "idempotency_key": "registration_...",
  "key_algorithm": "Ed25519",
  "public_key": "<base64 SPKI DER>",
  "software_version": "1.0.0",
  "payload_hash": "sha256:...",
  "signature": "<base64 Ed25519 signature>"
}
```

The request signature uses the generic request format with the registration
path and public-key fingerprint as signer. This proves possession of the
submitted private key. Registration is additionally idempotent by public-key
fingerprint, so the same key can never create two deployments.

The central registration receipt signature input is:

```text
myscoutee-registry-registration-receipt-v1
<protocol_version>
<registry_scope>
<deployment_id>
<public_key_fingerprint>
<registered_at>
<registry_key_id>
```

Response:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "registered_at": "2026-07-28T00:00:01Z",
  "public_key_fingerprint": "sha256:...",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64 SPKI DER>",
  "receipt_signature": "<base64 Ed25519 signature>",
  "duplicate": false
}
```

`deployment_id` is the public installation/deployment code in milestone 1. It
is not an operator login secret or a future claim bearer token. Possession of
the deployment private key is the proof of deployment control.

## Installation-test MAU batch

Endpoint:

```text
POST /v1/mau/batches
```

Protocol v1 accepts only the non-accounting installation test:

```text
kind                = installation-test
ruleset_version     = installation-test-v1
qualified_mau_count = 0
```

The test commitment hash input is:

```text
myscoutee-registry-installation-test-v1
<deployment_id>
<idempotency_key>
```

The batch payload hash input is:

```text
myscoutee-registry-mau-batch-payload-v1
<kind>
<period>
<ruleset_version>
<qualified_mau_count as base-10 integer>
<commitment_hash>
```

Request:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "timestamp": "2026-07-28T00:00:02Z",
  "nonce": "nonce_...",
  "idempotency_key": "installation_...",
  "kind": "installation-test",
  "period": "2026-07",
  "ruleset_version": "installation-test-v1",
  "qualified_mau_count": 0,
  "commitment_hash": "sha256:...",
  "payload_hash": "sha256:...",
  "signature": "<base64 Ed25519 signature>"
}
```

Accepted installation tests use ledger entry type:

```text
INSTALLATION_TEST_BATCH_ACCEPTED
```

They must never contribute to MAU weight or a leaderboard.

The immutable ledger-entry hash input is:

```text
myscoutee-registry-ledger-entry-v1
<protocol_version>
<registry_scope>
<ledger_index>
<entry_type>
<deployment_id>
<batch_id>
<kind>
<period>
<ruleset_version>
<qualified_mau_count>
<batch_hash>
<previous_entry_hash>
<accepted_at>
```

`batch_hash` is the verified request `payload_hash`. The entry hash is the
SHA-256 hash of this canonical message.

The central MAU receipt signature input is:

```text
myscoutee-registry-mau-receipt-v1
<protocol_version>
<registry_scope>
<batch_id>
<deployment_id>
<ledger_index>
<entry_hash>
<previous_entry_hash>
<batch_hash>
<kind>
<period>
<ruleset_version>
<qualified_mau_count>
<accepted_at>
<checkpoint_date>
<registry_key_id>
```

Response:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "batch_id": "batch_...",
  "deployment_id": "dep_...",
  "idempotency_key": "installation_...",
  "duplicate": false,
  "receipt": {
    "ledger_index": 1,
    "entry_hash": "sha256:...",
    "previous_entry_hash": "sha256:...",
    "batch_hash": "sha256:...",
    "kind": "installation-test",
    "period": "2026-07",
    "ruleset_version": "installation-test-v1",
    "qualified_mau_count": 0,
    "accepted_at": "2026-07-28T00:00:03Z",
    "checkpoint_date": "2026-07-28",
    "registry_scope": "example:region-a",
    "registry_key_id": "rkey_...",
    "registry_public_key": "<base64 SPKI DER>",
    "signature": "<base64 Ed25519 signature>"
  }
}
```

Receipt lookup:

```text
GET /v1/mau/batches/{batch_id}/receipt
```

The immediate receipt names the UTC checkpoint date that will cover the entry.
That daily checkpoint is immutable and is finalized only after the UTC date has
closed.

## Daily checkpoint

Endpoint:

```text
GET /v1/ledger/checkpoints/{YYYY-MM-DD}
```

A checkpoint commits to the ledger head at the end of a completed UTC day. Its
`entry_count` is the total number of ledger entries through that point.

Checkpoint signature/hash input:

```text
myscoutee-registry-checkpoint-v1
<registry_scope>
<checkpoint_date>
<through_ledger_index>
<entry_count>
<ledger_head_hash>
<previous_checkpoint_hash>
<generated_at>
<registry_key_id>
```

`checkpoint_hash` is the SHA-256 hash of that canonical message. `signature` is
the registry Ed25519 signature over the same canonical message.

```json
{
  "registry_scope": "example:region-a",
  "checkpoint_date": "2026-07-28",
  "through_ledger_index": 123,
  "entry_count": 123,
  "ledger_head_hash": "sha256:...",
  "previous_checkpoint_hash": "sha256:...",
  "checkpoint_hash": "sha256:...",
  "generated_at": "2026-07-29T00:00:05Z",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64 SPKI DER>",
  "signature": "<base64 Ed25519 signature>"
}
```

## Trust boundary

This protocol begins only after a deployment has been explicitly initialized
and its Ed25519 key exists. It does not authorize automatic installer-time key
creation, registry selection, discovery, or outbound enrollment. A browser may
display the deployment public-key fingerprint but must never receive the
private key.

Registration proves possession of a deployment key. Batch signatures prove
which registered deployment made an unchanged claim. Central signatures and
hash chains make accepted history tamper-evident. None of these prove that the
operator reported truthful activity or that a local account is one human.

No raw email, Firebase UID, access token, profile, chat, location, payment
detail, or other direct user identifier is accepted by protocol v1.

The later registry-signed, read-only operator announcement and update-manifest
extension is specified separately in
[`announcements-v1.md`](announcements-v1.md). It adds no public mutation or
remote-install endpoint and does not change deployment-registration or
accounting signatures.
