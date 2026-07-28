# MyScoutee Operator Network Protocol v1

This document defines signed company-verification claims, virtual operator
grouping, the registry-admin review boundary, and snapshot-bound leaderboard
reads. A claim is a company submission, not proof of an individual user's
identity or a transfer of ledger ownership.

## Trust and identity

- Every operator mutation is signed by the already registered deployment key.
- The registry verifies the signature, timestamp, nonce, idempotency key, and
  payload hash before accepting an action.
- A deployment submits or withdraws its own company claim. A client token never
  changes deployment identity, MAU history, or ledger ownership.
- Approval is an administrative action available only through local access to
  the registry container and its existing database/signing key. `reviewer_id`
  identifies that local audit actor; it is not a separate reviewer signature
  or remote authentication protocol.
- Registry integrity verification fails closed. It verifies append-only
  sources and directly maintained query state, but never rebuilds or repairs
  query state while serving a request.

## Structured company claim

The deployment submits:

```text
POST /v1/operator/actions
```

using action `claim` and these claim fields:

| JSON field | Requirement |
| --- | --- |
| `legal_name` | required, 1–160 UTF-8 bytes |
| `registration_number` | required, 1–80 UTF-8 bytes |
| `jurisdiction` | required, 1–80 UTF-8 bytes |
| `registered_address` | required, 1–500 UTF-8 bytes |
| `website` | optional absolute HTTPS URL, at most 2048 UTF-8 bytes |
| `verification_contact_name` | required, 1–120 UTF-8 bytes |
| `verification_contact_role` | required, 1–120 UTF-8 bytes |
| `verification_contact_email` | required canonical lowercase address, at most 254 UTF-8 bytes |
| `authority_attested` | must be `true` |

Surrounding whitespace and CR/LF are rejected. `operator_name` is not accepted
for a structured claim: `legal_name` is the public operator and leaderboard
label. `operator_avatar_url` remains optional and must be an absolute HTTPS
URL. The request does not accept personal identity numbers, beneficial-owner
data, or uploaded documents.

The deployment signature commits to:

```text
myscoutee-registry-operator-claim-payload-v2
claim
<legal_name>
<registration_number>
<jurisdiction>
<registered_address>
<website>
<verification_contact_name>
<verification_contact_role>
<verification_contact_email>
<authority_attested>
<operator_avatar_url>
```

Acceptance immediately returns `claim_state: "pending-review"`, creates or
retains the operator group, and makes the deployment a provisional claimed
leaderboard member. Its grouping/client-token operations remain available
while review is pending. Resubmitting a claim retains its group but creates a
new claim action; a reviewer must approve that exact current action.

The application may accept an explicit `Idempotency-Key` HTTP header at its
operator API boundary. When absent, it derives a stable `claim_...` key from
the normalized signed claim payload, registry scope, deployment ID, and the
last durable claim-generation boundary. An already active identical local
claim reuses its recorded key.
Therefore an identical retry after a lost registry response resolves to the
same central action; changed content or a new post-withdrawal generation
derives a different key.

## Privacy boundary

Raw registered address and verification-contact fields are never columns in
the public/auditable operator action ledger and never appear in claim status or
leaderboard responses. The public audit event contains the legal label and the
signed payload digest.

The raw submission is stored in the same SQLite database in a separate,
append-only private table linked by claim action ID and private-record hash.
This is an access-control boundary, not field-level encryption. Restrict access
to the registry data volume, container shell, CLI stdout, logs, and backups;
apply the governing retention/deletion policy to protected backups as well.
Do not put contact data or other personal information in `reviewer_id` or
`review_reference`.

The submitting application also retains the signed structured request with its
registry receipt in its existing private local receipt journal so it can
re-verify the payload and recover idempotently. On POSIX package targets the
state/receipt directories are enforced as mode `0700` and files as `0600`;
permission failures stop the operation. Treat that journal and every backup as
verification data subject to the same access and retention controls.

## Signed status

An operator reads its direct, registry-signed status at:

```text
GET /v1/operator/claims/{deployment_id}
```

The receipt binds the deployment, exact claim action/audit index/hash, group,
legal name, `verification_status`, submission time, review boundary, registry
scope, and registry key. Status is one of:

- `PENDING_REVIEW`
- `APPROVED`
- `WITHDRAWN`

Pending response example:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "status": {
    "deployment_id": "dep_0123456789abcdef0123456789abcdef",
    "claim_action_id": "opa_0123456789abcdef0123456789abcdef",
    "claim_audit_index": 42,
    "claim_audit_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "group_id": "opg_0123456789abcdef0123456789abcdef",
    "legal_name": "Example Cooperative",
    "verification_status": "PENDING_REVIEW",
    "submitted_at": "2026-07-28T12:00:00Z",
    "review_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "registry_scope": "example:region-a",
    "registry_key_id": "rkey_0123456789abcdef0123456789abcdef",
    "signature": "BASE64_ED25519_SIGNATURE"
  }
}
```

The mutable current-status row is written in the same transaction as claim,
withdrawal, or approval. Reads query that row directly. Integrity verification
independently reconstructs the expected value from signed append-only sources
and rejects a mismatch; it does not serve or repair reconstructed state.

Approval changes this status receipt only. The provisional group membership
already exists, so approval does not append an operator-network action, change
a leaderboard snapshot boundary, or invalidate a cursor.

## Other signed operator actions

Non-claim actions retain the v1 canonical payload:

```text
myscoutee-registry-operator-action-payload-v1
<action>
<operator_name>
<operator_avatar_url>
<client_token_hash>
<token_ttl_seconds>
<token_id>
<link_id>
```

Supported actions are:

- `withdraw-claim`
- `issue-client-token`
- `revoke-client-token`
- `redeem-client-token`
- `revoke-group-link`
- `deactivate-deployment`
- `reactivate-deployment`

Client tokens are valid for 60–3600 seconds. The plaintext value is returned
once and only its SHA-256 hash is stored. Redeeming a token creates virtual
group membership; each deployment's accounting rows remain separately
auditable.

Each accepted mutation atomically appends the deployment-signed nonce proof,
hash-linked operator audit event, and the versioned network-state row used by
leaderboard reads. Claim acceptance also appends its private submission and
direct status row in that transaction. Replay, idempotency conflict, invalid
state, and invalid signatures append nothing.

## Administrative review CLI

Operational CLI commands require an existing initialized registry database,
registry identity, and signing key at the configured paths. They never create
state for a missing/mistyped volume; use the explicit initialization workflow
before operating a new registry.

List review-safe summaries:

```bash
docker compose exec -T registry \
  /registry list-operator-claims \
  --status PENDING_REVIEW \
  --limit 50
```

```json
{
  "items": [
    {
      "deployment_id": "dep_0123456789abcdef0123456789abcdef",
      "claim_action_id": "opa_0123456789abcdef0123456789abcdef",
      "group_id": "opg_0123456789abcdef0123456789abcdef",
      "legal_name": "Example Cooperative",
      "verification_status": "PENDING_REVIEW",
      "submitted_at": "2026-07-28T12:00:00Z"
    }
  ],
  "next_deployment_id": "dep_fedcba9876543210fedcba9876543210"
}
```

Continue with the returned opaque deployment cursor:

```bash
docker compose exec -T registry \
  /registry list-operator-claims \
  --status PENDING_REVIEW \
  --limit 50 \
  --after-deployment-id dep_fedcba9876543210fedcba9876543210
```

`--status` accepts `PENDING_REVIEW`, `APPROVED`, or `WITHDRAWN`. List output
never includes the private address or contact.

Inspect one private submission only in an access-controlled terminal:

```bash
docker compose exec -T registry \
  /registry show-operator-claim \
  --deployment-id dep_0123456789abcdef0123456789abcdef
```

```json
{
  "deployment_id": "dep_0123456789abcdef0123456789abcdef",
  "claim_action_id": "opa_0123456789abcdef0123456789abcdef",
  "group_id": "opg_0123456789abcdef0123456789abcdef",
  "legal_name": "Example Cooperative",
  "verification_status": "PENDING_REVIEW",
  "submitted_at": "2026-07-28T12:00:00Z",
  "registration_number": "REG-42",
  "jurisdiction": "Slovakia",
  "registered_address": "Main Street 1",
  "website": "https://example.test",
  "verification_contact_name": "Alex Reviewer",
  "verification_contact_role": "Director",
  "verification_contact_email": "alex@example.test",
  "authority_attested": true
}
```

Copy the four optimistic-lock fields exactly from `show`, then approve:

```bash
docker compose exec -T registry \
  /registry approve-operator-claim \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --claim-action-id opa_0123456789abcdef0123456789abcdef \
  --group-id opg_0123456789abcdef0123456789abcdef \
  --legal-name 'Example Cooperative' \
  --reviewer-id network-review-team \
  --review-reference case:2026-0042 \
  --idempotency-key approve-example-2026-0042
```

```json
{
  "duplicate": false,
  "receipt": {
    "review_index": 1,
    "review_id": "opr_0123456789abcdef0123456789abcdef",
    "deployment_id": "dep_0123456789abcdef0123456789abcdef",
    "claim_action_id": "opa_0123456789abcdef0123456789abcdef",
    "group_id": "opg_0123456789abcdef0123456789abcdef",
    "legal_name": "Example Cooperative",
    "decision": "approved",
    "reviewer_id": "network-review-team",
    "review_reference": "case:2026-0042",
    "idempotency_key": "approve-example-2026-0042",
    "reviewed_at": "2026-07-28T13:00:00Z",
    "previous_review_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "review_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "registry_scope": "example:region-a",
    "registry_key_id": "rkey_0123456789abcdef0123456789abcdef",
    "signature": "BASE64_ED25519_SIGNATURE"
  }
}
```

The JSON result contains `duplicate` and a registry-signed, hash-linked review
receipt binding all supplied fields. Repeating the exact command returns
`duplicate: true` and the same review. Reusing the idempotency key with
different data fails. Approval of a claim action that was withdrawn or
superseded by resubmission also fails as stale; refresh `show` and review the
new submission instead.

`reviewer_id` (1–120 bytes) and `review_reference` (1–240 bytes) are required
audit identifiers. Local registry CLI access is the approval authority. The
registry signature proves what that authority recorded; it does not prove a
separate person's identity.

CLI exit behavior:

- exit `0`: successful JSON result, exact idempotent duplicate, or `--help`;
- exit `1`: invalid flags/fields, missing or uninitialized DB/key/identity,
  stale target, idempotency conflict, integrity failure, or storage failure.

## Leaderboard CLI and reads

Top-level HTTP pages:

```text
GET /v1/leaderboard?view=founder|claimed|unclaimed&through_period=YYYY-MM&limit=20&cursor=...
```

Deployments inside a group:

```text
GET /v1/leaderboard/groups/{group_id}/deployments?through_period=YYYY-MM&limit=20&cursor=...
```

The equivalent operational commands are:

```bash
docker compose exec -T registry \
  /registry leaderboard --view claimed --limit 20

docker compose exec -T registry \
  /registry leaderboard \
  --view claimed \
  --limit 20 \
  --cursor 'COPY_THE_COMPLETE_next_cursor_VALUE'

docker compose exec -T registry \
  /registry leaderboard \
  --group-id opg_0123456789abcdef0123456789abcdef \
  --limit 20
```

Never parse, edit, or combine a cursor with another view/group/period. It is a
registry-signed opaque value bound to the first page's immutable snapshot
boundaries. CLI output is the same protocol JSON shape as HTTP.

Leaderboard SQL reads weights from immutable `ledger_weight_rows` and operator
membership/profile state from the versioned direct network-state table, always
at or before the signed audit boundary. No action semantics are projected from
the audit log at query time. Integrity verification rejects missing, extra, or
mismatched direct rows.

The six most recent complete UTC months determine measured weight. Founder
contribution is fixed at 100,000 units and founder share is:

```text
max(10%, 100000 / (100000 + measured_network_weight))
```

The remaining pool is divided among claimed operator groups. Pending-review
claims are intentionally provisional claimed members; approval does not change
their weight or share. Protocol v1 currently accepts only zero-count
installation-test MAU batches, so production weight remains zero until the
qualified-MAU protocol is introduced.
