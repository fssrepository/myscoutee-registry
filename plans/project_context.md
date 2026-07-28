# Project Context for Codex

## 1. Project in one sentence

This is an open-core social application that can be deployed independently by multiple operators under their own brand, marketing, domain, and infrastructure, while a central accounting layer tracks qualified monthly active users (MAU) for a possible future, opt-in acquisition or merger.

## 2. Business model

- The application is distributed as a deployable backend package, currently as a `.deb` package with an installer.
- The frontend is included in each deployment and communicates with the deployed backend and, where required, with a central accounting service.
- Each operator may run the product under a different brand and may build its own local user base.
- The network behaves like a virtual company only for accounting and a possible future exit.
- Participation in an exit is optional. An operator that does not participate keeps operating independently.
- If an exit occurs, participating deployments receive weight according to an agreed MAU-based formula.
- The central service is not intended to control the local product, branding, marketing, or ordinary application data.

## 3. Current deployment model

Each deployment has:

- its own installed backend;
- its own frontend bundle;
- its own operator and brand;
- potentially its own Firebase project;
- potentially, later, a different authentication provider;
- its own application database and user data;
- a deployment identity registered with the central accounting service.

The installer should be able to create a deployment key pair. The private key remains on the deployment server. The public key is registered centrally.

Suggested deployment identifier:

```text
deployment_id = centrally assigned opaque identifier
```

Suggested signing algorithm:

```text
Ed25519
```

Every submitted MAU batch or activity commitment should be signed by the deployment.

## 4. Important trust assumption

A deployed backend is not fully trusted merely because it came from the official `.deb` package. An operator controls its own machine and can modify or replace the software.

Cryptography can prove:

- which registered deployment submitted a record;
- whether a submitted record changed;
- when the central service accepted it;
- whether the central ledger was changed retroactively.

Cryptography alone cannot prove:

- that a user is a real person;
- that one person has only one account;
- that an operator did not automate activity;
- that a locally reported action actually happened.

The MAU rules and audit model therefore matter more than the hash algorithm.

## 5. Authentication and identity model

Do not assume that the whole network uses one Firebase project.

The expected initial model is:

- each operator may use its own Firebase project;
- the operator pays its own authentication-related costs if those arise;
- Firebase email/password login and social login can both exist;
- another authentication provider may be supported later.

The application must not use a Firebase UID by itself as a globally meaningful identity, because a UID is scoped to its Firebase project.

Represent an external login identity as:

```text
provider + issuer + subject
```

Firebase example:

```text
provider = "firebase"
issuer   = firebase_project_id
subject  = firebase_uid
```

The tuple below is unique:

```text
(provider, issuer, subject)
```

A minimal local identity table can be:

```sql
CREATE TABLE auth_identities (
    provider   TEXT NOT NULL,
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    local_user_id TEXT NOT NULL,
    PRIMARY KEY (provider, issuer, subject)
);
```

`local_user_id` is the deployment's stable application-level user identifier. Business tables should reference `local_user_id`, not the raw Firebase UID.

A future network-level or buyer-level canonical user ID may be added during migration. It is not necessary to centralize all user identities in the first version.

## 6. Token validation

For a Firebase-authenticated user, validation means verifying a Firebase ID token, not trusting a UID sent as plain JSON.

The validating component must verify at least:

- token signature;
- token expiration;
- issuer (`iss`);
- audience (`aud`);
- Firebase project identity;
- subject/UID (`sub` or Firebase UID claim);
- optional policy claims such as verified email, where required by the MAU rules.

For multiple Firebase projects, the central service must only accept tokens from registered/approved project IDs belonging to registered deployments.

Possible validation models:

### Model A: central token validation

The client or deployment sends the Firebase ID token to the central service. The central service validates it against the registered Firebase project.

Advantages:

- stronger central verification;
- the deployment cannot simply invent a Firebase UID.

Disadvantages:

- the central service sees authentication tokens;
- higher coupling and traffic;
- support for many auth providers is more complex.

### Model B: deployment validation plus signed evidence

The deployment validates the token and submits signed evidence or a batch commitment.

Advantages:

- simpler central service;
- authentication remains local.

Disadvantages:

- the operator controls the deployment and can modify it;
- this proves only which deployment made the claim, not that the claim is true.

The implementation should keep these models separable because the final choice is not yet fixed.

## 7. MAU accounting

The purpose of the central system is not generic analytics. It is exit-related accounting.

A user should count only after satisfying a versioned definition of a qualified monthly active user.

The initial MAU rule is not finalized. Possible requirements include:

- authenticated user;
- verified email or equivalent verified identity;
- at least one meaningful application action;
- optional minimum session/activity threshold;
- exclusion of blocked, deleted, test, or flagged users.

Do not hard-code the final definition into irreversible ledger logic. Store a ruleset version with every MAU snapshot or event.

Example:

```text
ruleset_version = "mau-v1"
period          = "2026-07"
```

### Local versus global deduplication

With separate Firebase projects, the same person can create accounts on multiple deployments. Cross-project global deduplication is not reliably possible from Firebase UIDs alone.

The first version may therefore count qualified users per deployment rather than claiming to count unique human beings across the whole network.

This distinction must be explicit:

```text
network reported MAU = sum of qualified deployment-level MAU
```

It is not necessarily:

```text
globally unique humans
```

Any later global identity linking must be explicit and auditable, not inferred solely from matching names or unverified email addresses.

## 8. Privacy-preserving MAU identifiers

Do not place raw email addresses, Firebase UIDs, access tokens, or other direct identifiers in the public/auditable ledger.

A deployment can derive a period-specific pseudonymous identifier from its stable local user ID:

```text
period_user_id = HMAC-SHA256(period_key, deployment_id || local_user_id)
```

Important properties:

- the HMAC key must not be stored in the public ledger;
- changing the period key prevents easy linking across months;
- including `deployment_id` prevents accidental collisions across deployments;
- this does not provide global cross-deployment deduplication;
- the mapping needed for audits or migration must remain outside the public ledger.

An alternative is for the central service to issue period-specific identifiers after validating an identity. That is stronger but more centralized. Keep the design open to either approach.

## 9. Central ledger model

The preferred design is not a public blockchain and not peer consensus.

Use a central sequencer/accounting service with an append-only, cryptographically auditable log.

The deployments do not validate each other.

Suggested properties:

- append-only entries;
- monotonically increasing ledger index;
- each entry commits to the previous entry hash;
- signed acceptance receipt returned to the submitting deployment;
- periodic Merkle root or snapshot hash;
- centrally signed daily or monthly checkpoints;
- ruleset version stored with accounting records;
- no silent edits or deletes;
- corrections represented as new compensating entries.

Example logical entry:

```json
{
  "ledger_index": 12345,
  "deployment_id": "dep_...",
  "period": "2026-07",
  "ruleset_version": "mau-v1",
  "entry_type": "MAU_BATCH_ACCEPTED",
  "batch_hash": "sha256:...",
  "qualified_mau_count": 1250,
  "previous_entry_hash": "sha256:...",
  "accepted_at": "2026-07-28T00:00:00Z"
}
```

Example receipt:

```json
{
  "ledger_index": 12345,
  "entry_hash": "sha256:...",
  "checkpoint_id": "2026-07-28",
  "central_signature": "..."
}
```

The ledger may store individual pseudonymous MAU commitments or only batch commitments plus auditable supporting data, depending on privacy, cost, and audit requirements.

## 10. Exit and migration model

Two Firebase projects are not literally merged in place.

During an exit, participating operators can migrate users into:

- a buyer-controlled Firebase project;
- another identity provider;
- or a temporary identity gateway supporting multiple source projects.

The source identity key is always:

```text
(provider, issuer, subject)
```

Migration requires an explicit mapping from each source identity to a target identity.

Do not attempt to reconstruct this mapping from ledger hashes. The ledger is for accounting and audit, not for restoring identities.

A migration database may contain:

```sql
CREATE TABLE identity_migrations (
    source_provider TEXT NOT NULL,
    source_issuer   TEXT NOT NULL,
    source_subject  TEXT NOT NULL,
    target_provider TEXT NOT NULL,
    target_issuer   TEXT NOT NULL,
    target_subject  TEXT NOT NULL,
    status          TEXT NOT NULL,
    PRIMARY KEY (source_provider, source_issuer, source_subject)
);
```

Potential migration flow:

1. Export users from participating source projects.
2. Detect UID, email, phone, and provider collisions.
3. Import or create users in the target identity system.
4. Preserve password hashes where the provider supports compatible imports.
5. Reconfigure OAuth providers in the target project.
6. Require one new login, or use a verified session bridge/custom-token flow.
7. Update application identity mappings.
8. Keep an audit trail of every merge, split, and unresolved collision.

Never automatically merge accounts merely because two records have the same name. Matching verified email can identify a merge candidate but may still require user confirmation or reauthentication.

## 11. Exit participation

Participation in an acquisition is optional.

A participating deployment must be able to provide the data and access required by the final agreement, potentially including:

- Firebase/Auth user export;
- password-hash migration parameters where applicable;
- provider configuration;
- application user-data export;
- identity mappings;
- deployment signing keys or key-transfer procedure;
- ledger receipts and audit evidence;
- appropriate cloud/IAM access or project transfer.

A non-participating deployment remains separate and should not be silently included in the buyer's user base.

## 12. Preferred implementation direction

The central accounting service should be minimal and memory-efficient.

Current preferred candidate:

```text
Go
```

Suggested first-version stack:

- Go standard library HTTP server or a very small router;
- SQLite in WAL mode for an initial single-node deployment;
- Ed25519 signatures;
- SHA-256/HMAC-SHA-256;
- append-only ledger table;
- periodic signed checkpoints;
- one deployable binary;
- low-memory VM as the initial target.

Avoid in the first version unless proven necessary:

- blockchain consensus;
- peer validation;
- Kubernetes;
- Kafka;
- multiple microservices;
- premature global identity consolidation.

The storage layer should be abstract enough to move from SQLite to PostgreSQL later without changing the wire protocol or ledger semantics.

## 13. Suggested minimal API surface

The exact API is not finalized, but a small initial surface could be:

```text
POST /v1/deployments/register
POST /v1/deployments/rotate-key
POST /v1/mau/batches
GET  /v1/mau/batches/{batch_id}/receipt
GET  /v1/ledger/checkpoints/{period}
GET  /v1/deployments/{deployment_id}/summary
```

Every write request should include:

- deployment ID;
- timestamp;
- nonce or idempotency key;
- payload hash;
- deployment signature;
- protocol version.

The server should reject:

- unknown deployments;
- invalid signatures;
- replayed nonces/idempotency keys;
- timestamps outside an accepted window;
- unsupported ruleset/protocol versions;
- malformed or oversized batches.

## 14. Open design questions

These are intentionally unresolved. Codex should not silently choose permanent answers without explaining the trade-offs.

1. Does the central service validate every Firebase/Auth token, or only signed deployment batches?
2. What exact activity qualifies a user as MAU?
3. Is MAU counted per deployment, or is some form of cross-deployment deduplication required later?
4. Are individual period pseudonyms stored centrally, or only aggregate counts with Merkle commitments?
5. Who holds the HMAC period keys?
6. How are independent operators audited without exposing raw personal data?
7. What is the correction/dispute process for an accepted batch?
8. How is the exit weight calculated: latest month, average, median, or another window?
9. How are project ownership and migration obligations represented contractually?
10. When should SQLite be replaced by PostgreSQL?

## 15. Instructions for Codex

When working on this project:

- first inspect the existing repository and current data model;
- do not assume a shared Firebase project;
- do not use raw Firebase UID as a cross-project identity;
- keep authentication-provider logic behind an interface;
- keep ledger/accounting separate from ordinary analytics;
- distinguish deployment-level MAU from globally unique humans;
- never place secrets or raw personal identifiers in the append-only ledger;
- use versioned protocols and versioned MAU rules;
- prefer the smallest implementation that preserves future migration paths;
- do not refactor unrelated code;
- preserve backward compatibility with the `.deb` deployment model;
- include database migrations, tests, and clear failure handling;
- explain any security assumption that cannot be enforced technically;
- treat operator-controlled deployments as potentially modified/untrusted;
- use idempotent batch submission and signed central receipts.

## 16. Recommended first implementation milestone

Build only the deployment registration and signed batch-receipt path:

1. Generate an Ed25519 key pair during installation.
2. Register the public key and receive a `deployment_id`.
3. Submit a signed, idempotent test MAU batch.
4. Validate the signature and replay protection centrally.
5. Append the accepted batch to a hash-linked ledger.
6. Return a centrally signed receipt.
7. Generate a signed daily checkpoint.
8. Add tests for signature failure, replay, duplicate batch, and ledger-chain verification.

Do not implement cross-project account merging or global human deduplication in this milestone.
