# Privacy-safe global identity and QMAU deduplication v1

This extension lets separately operated deployments recognize the same
verified person without sending the registry that person's email, phone
number, Firebase UID, provider subject, local profile ID, or a plain hash of
one of those values.

It uses RFC 9497 verifiable oblivious pseudorandom functions (VOPRF), mode
`VOPRF`, suite `P256-SHA256` (RFC suite `0x0003`). The server implementation is
Cloudflare CIRCL, not product-specific cryptography. Compressed P-256 elements
are 33 bytes and the DLEQ proof is 64 bytes. Binary fields are canonical padded
base64.

## Privacy and accounting boundary

Normalization and input eligibility remain deployment-local. A deployment
blinds the normalized input and signs only the blinded evaluation request. It
finalizes the verified VOPRF result locally and derives:

```text
sha256(GlobalIdentityCommitmentMessage(
  key_version,
  "P256-SHA256",
  <canonical padded base64 VOPRF output>
))
```

The registry receives that opaque `sha256:` commitment. During an honest VOPRF
evaluation the blinded request does not reveal the input, and the HTTP schema
has no raw-identifier field. Linking is explicit and requires a separate
opaque consent-evidence commitment.

The public `global_identity_events` chain contains only aggregate counts and a
commitment to the restricted same-transaction direct rows. The alias, link,
consent, and presence tables are access-restricted direct query tables.
Neither public nor direct storage contains the raw identifier.

### Threat-model limit

This v1 design is privacy-enhancing, not anonymous PSI. A single registry
operator controls the VOPRF secret and can read the restricted commitment
tables. A malicious or compromised operator holding both can evaluate a
dictionary of likely low-entropy identifiers (for example known email
addresses) offline and compare the derived commitments. TLS, request blinding,
domain separation, rate limiting, encryption at rest, and the absence of raw
identifiers do not remove that key-holder attack.

Accordingly, access to the VOPRF keyring and restricted tables must be
separated, least-privileged, audited, and backed up as sensitive material.
Deployments must obtain user consent and must not describe this protocol as
full anonymity. A stronger future boundary can use a threshold OPRF or a
separately governed/HSM-backed evaluation service so no single registry
operator holds both capabilities. That more complex machinery is deliberately
not part of v1.

QMAU not covered by a link remains counted as unlinked QMAU. For a period:

```text
deduplicated_network_qmau =
  globally_unique_linked_count + unlinked_qmau_count
```

Aggregate MAU alone cannot prove person-level overlap. Therefore a presence
batch is required for exact cross-deployment deduplication. It must match an
already accepted signed `monthly-qmau` deployment/period/revision and cannot
change that deployment's QMAU count.

The deduplicated snapshot is a network-total measurement only. It does not
redistribute a duplicate person's activity or weight between deployments,
change any deployment's QMAU/leaderboard share, or decide a payout. Identity
uniqueness evidence and deployment activity/weight evidence remain separate
auditable inputs.

## Canonical request rule

All POST operations use the generic canonical signed request from
`protocol-v1.md`, with the assigned `deployment_id` as signer. The payload
hash is SHA-256 over the endpoint-specific canonical payload below. Every
canonical field rejects CR and LF.

## Active VOPRF key

```text
GET /v1/global-identities/voprf-keys/current
```

Response JSON fields, in wire spelling, are:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "key_version": 1,
  "suite": "P256-SHA256",
  "mode": "VOPRF",
  "public_key": "<33-byte compressed SEC1, padded base64>",
  "status": "ACTIVE",
  "activated_at": "2026-07-29T00:00:00Z",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<Ed25519 SPKI DER, padded base64>",
  "signature": "<Ed25519, padded base64>"
}
```

Registry signature input:

```text
myscoutee-registry-global-identity-voprf-key-v1
<protocol_version>
<registry_scope>
<key_version>
<suite>
<mode>
<public_key>
<status>
<activated_at>
<registry_key_id>
```

## Blinded evaluation

```text
POST /v1/global-identities/evaluate
```

Request fields:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "timestamp": "2026-07-29T00:00:00Z",
  "nonce": "nonce_...",
  "idempotency_key": "evaluate_...",
  "key_version": 1,
  "suite": "P256-SHA256",
  "blinded_element": "<33 bytes, padded base64>",
  "payload_hash": "sha256:...",
  "signature": "<deployment Ed25519 signature>"
}
```

Payload input:

```text
myscoutee-registry-global-identity-evaluate-payload-v1
<key_version>
<suite>
<blinded_element>
```

Response:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "key_version": 1,
  "suite": "P256-SHA256",
  "public_key": "<33 bytes, padded base64>",
  "evaluated_element": "<33 bytes, padded base64>",
  "proof": "<64 bytes, padded base64>",
  "request_hash": "sha256:...",
  "response_hash": "sha256:...",
  "evaluated_at": "2026-07-29T00:00:01Z",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64>",
  "receipt_signature": "<base64>",
  "duplicate": false
}
```

`response_hash` commits, in order, to the domain
`myscoutee-registry-global-identity-evaluation-result-v1`, key version, suite,
public key, evaluated element, and proof. The receipt signature commits to the
domain `myscoutee-registry-global-identity-evaluation-receipt-v1`, protocol,
scope, deployment, version, suite, request hash, response hash, evaluation
time, and registry key ID. Evaluations are durably audited, idempotent, and
limited to 60 accepted evaluations per deployment per rolling minute.

## Link, unlink, and correction

Create a link with:

```text
POST /v1/global-identities/links
```

Request fields are:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "timestamp": "2026-07-29T00:00:00Z",
  "nonce": "nonce_...",
  "idempotency_key": "link_...",
  "key_version": 1,
  "suite": "P256-SHA256",
  "network_identity_commitment": "sha256:...",
  "consent_version": "global-dedup-consent-v1",
  "consent_evidence_commitment": "sha256:...",
  "verified_at": "2026-07-28T12:00:00Z",
  "effective_period": "2026-07",
  "payload_hash": "sha256:...",
  "signature": "<base64>"
}
```

The payload domain is
`myscoutee-registry-global-identity-link-payload-v1`, followed by key version,
suite, network commitment, consent version, consent evidence commitment,
verification timestamp, and effective period.

`POST /v1/global-identities/link-actions` accepts the same signed envelope plus:

```json
{
  "action": "UNLINK",
  "link_id": "gil_...",
  "replacement_key_version": 0,
  "replacement_suite": "",
  "replacement_commitment": "",
  "consent_version": "",
  "consent_evidence_commitment": "",
  "verified_at": "",
  "effective_period": "2026-08",
  "reason_commitment": "sha256:..."
}
```

For `CORRECT`, the replacement and consent fields are required and identify
the currently active key. For `UNLINK`, they must be absent/zero. The payload
domain is `myscoutee-registry-global-identity-link-action-payload-v1` followed
by those fields in the order shown. Corrections also provide the explicit
key-rotation path. Old key versions remain evaluable only so a deployment can
derive and submit that correction.

Both endpoints return:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "link": {
    "link_id": "gil_...",
    "deployment_id": "dep_...",
    "status": "ACTIVE",
    "key_version": 1,
    "suite": "P256-SHA256",
    "active_from_period": "2026-07",
    "consent_version": "global-dedup-consent-v1",
    "verified_at": "2026-07-28T12:00:00Z",
    "latest_event_index": 1,
    "latest_event_hash": "sha256:..."
  },
  "event": {
    "event_index": 1,
    "event_id": "gievt_...",
    "action": "LINK",
    "deployment_id": "dep_...",
    "period": "2026-07",
    "aggregate_commitment": "sha256:...",
    "reported_count": 0,
    "deduplicated_count": 0,
    "accepted_at": "2026-07-29T00:00:01Z",
    "previous_event_hash": "sha256:...",
    "event_hash": "sha256:...",
    "registry_scope": "example:region-a",
    "registry_key_id": "rkey_...",
    "signature": "<base64>"
  },
  "registry_public_key": "<base64>",
  "duplicate": false
}
```

The link response deliberately omits the internal global identity ID, network
commitment, and consent-evidence commitment.

## Qualified-presence batch

```text
POST /v1/global-identities/presence-batches
```

Request-only fields beyond the signed envelope are:

```json
{
  "period": "2026-07",
  "revision": 3,
  "supersedes_batch_id": "batch_...",
  "reported_qmau_count": 100,
  "key_version": 1,
  "suite": "P256-SHA256",
  "network_identity_commitments": ["sha256:...", "sha256:..."]
}
```

Commitments are bytewise non-decreasing. Repetition is permitted because two
qualified local accounts may collapse to one person. Every commitment must
already have an active link for the submitting deployment and effective
period. The payload domain is
`myscoutee-registry-global-identity-presence-batch-v1`, followed by period,
revision, superseded batch ID, reported count, key version, suite, commitment
count, then each commitment.

The response contains `protocol_version`, `registry_scope`, `batch_id`,
`deployment_id`, `period`, `revision`, `linked_count`, `unlinked_count`, the
public signed `event`, the `snapshot` below, and `duplicate`.

New link, correction, and presence writes must use the active VOPRF key
version. Retired versions remain evaluable for explicit rotation correction.
An exact idempotent retry of a mutation or presence batch accepted before a
rotation returns its original receipt even though its key version is now
retired; rotation cannot turn a committed success into an ambiguous failure.

## Aggregate query

```text
GET /v1/global-identities/dedup/{YYYY-MM}
```

It returns the latest immutable revision:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "period": "2026-07",
  "revision": 4,
  "reported_qmau_count": 220,
  "linked_observation_count": 170,
  "globally_unique_linked_count": 130,
  "unlinked_qmau_count": 50,
  "deduplicated_network_qmau": 180,
  "duplicate_reduction": 40,
  "covered_deployment_count": 3,
  "aggregate_commitment": "sha256:...",
  "through_event_index": 12,
  "through_event_hash": "sha256:...",
  "generated_at": "2026-07-29T00:00:01Z"
}
```

The through-event is registry-signed and includes the same aggregate
commitment and public counts. Consumers verify that event receipt before using
the snapshot as audited network accounting.

## Storage, rotation, and recovery

Each link action and presence batch appends its public event and writes its
restricted direct rows plus immutable snapshot in one SQLite transaction.
There is no asynchronous projection or repair writer.

The VOPRF seed keyring is a mode-`0600`, non-symlink JSON file in the registry
runtime data volume. It is not SQLite data, an environment secret, a Docker
image layer, or a Debian package asset. Rotate locally with:

```bash
/registry rotate-global-identity-key
```

Restart after rotation. Back up and restore the SQLite database, registry
Ed25519 signing key, and VOPRF keyring together. Losing the VOPRF keyring
prevents future correction/evaluation and must fail closed; generating a
replacement is not recovery.
