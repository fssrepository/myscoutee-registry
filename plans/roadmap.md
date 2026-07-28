# MyScoutee Operator Network Roadmap

This roadmap turns the first signed-registry milestone into the complete
operator product without collapsing local product ownership into the central
service.

## Permanent architecture boundaries

1. The Angular frontend talks only to its local Java backend for application,
   operator, claim, and accounting operations.
2. The Java backend is the only component in a product deployment that may call
   the external registry. It does so only when the configured outbound policy
   permits the requested operation.
3. Deployment and registry private keys never enter the browser, Mongo seed
   data, logs, or the public ledger.
4. The Go registry is a separate accounting/identity service. It does not
   become the database for local profiles, chats, events, payments, or branding.
5. A deployment signature proves which deployment submitted a claim; it does
   not prove that the claimed activity is truthful.
6. Firebase UID is never treated as a global person identifier. External
   identities are always scoped by `(provider, issuer, subject)`.
7. Central accounting stores versioned commitments and aggregates, not raw
   email addresses, access tokens, Firebase UIDs, chats, profiles, or precise
   locations.
8. Every accepted accounting change is append-only. Corrections and disputes
   add compensating entries instead of rewriting history.
9. The registry may publish signed update metadata, but it never performs an
   unattended deployment upgrade. A local operator must inspect and explicitly
   approve every installation.
10. A registry URL is a route, not a deployment identity. Moving one parent
    service to another domain preserves the deployment key, code, idempotency
    state, receipts, and pinned parent signing identity.
11. Each independently governed parent/accounting scope is a separate
    cryptographic and operational domain. A deployment selects one parent
    directly; neither registration, raw accounting traffic, identity data, nor
    receipt delivery is silently relayed across a scope boundary. Geography
    and legal-region names are deployment policy, not hard-coded modes.
12. The deployment/share rail is product-independent infrastructure. Every
    signed record is scoped to a configured virtual-company/program and parent
    accounting domain so the same registry implementation can serve other
    products without mixing ledgers or replay domains.
13. A claim, connection-code grouping, leaderboard name, or calculated weight
    is a provisional accounting/read-model fact, not a legal entitlement or
    payout decision. Final eligibility is established only through a separate,
    authorized and auditable exit-review process.

The intended request path is:

```text
Angular operator UI
        |
        | local authenticated API
        v
Java deployment backend
        |
        | policy check -> durable outbox -> signed protocol
        v
configured parent registry URL + signed program/accounting scope
        |
        | validation -> append-only acceptance
        v
Go registry + SQLite/PostgreSQL
```

## Milestone 1 — signed deployment rail

Goal: establish a real, durable, independently verifiable transport before
defining operator claims or production MAU.

Deliverables:

- a fully uninitialized installed node: no deployment key, pinned registry
  selection, or automatic registry traffic; before confirmation only an
  explicitly operator-requested, read-only registry identity preflight is
  permitted;
- a narrow host-persistence boundary, invoked only after the future
  authenticated operator confirmation, that will generate an Ed25519
  deployment key which survives upgrades while exposing only its public
  fingerprint to the browser;
- configurable parent registry URL, virtual-company/program scope, accounting
  domain, and independent outbound enable/allow flags;
- read-only, self-signed registry identity preflight so a candidate endpoint's
  scope, key ID, and public key can be verified and explicitly pinned before
  confirmation, without central mutation;
- Java registry client with deterministic signing, bounded HTTP calls, durable
  retry state, and central-receipt verification;
- self-signed deployment registration with an opaque deployment ID;
- one zero-count `installation-test-v1` batch that can never affect weight;
- signed `daily-revenue` aggregate snapshots by original-payment UTC day and
  settlement currency, with a pinned minor-unit table, fixed
  `net-captured-revenue-v1` ruleset, 500-basis-point technical network pool,
  explicit zero days, and immutable revision/supersession corrections;
- revenue ledger/source/query rows written directly in one transaction, with
  signed receipts and fail-closed replay verification instead of an
  asynchronously rebuilt projection;
- local registry-administrator revenue queries for global,
  deployment-specific, and current claimed-group totals; currencies are never
  combined, there is no public revenue-query endpoint, and filtered
  breakdowns retain the global day/currency commission pool;
- Go HTTP registry in Docker;
- dedicated production Compose deployment on the separate registry host, with
  operator-supplied TLS certificate/key material and a registry-owned Nginx
  edge; Go has only an internal Docker-network port, while Nginx alone
  publishes HTTP-to-HTTPS redirect and bounded HTTPS proxy traffic;
- the canonical Java development Docker Compose stack includes a
  disposable/persistent local Go registry for operator and failure testing;
  production Java packaging never includes that local registry, and direct
  plain HTTP is permitted only inside this explicit development topology;
- SQLite in WAL mode on a persistent volume;
- atomic nonce/idempotency enforcement;
- append-only, hash-linked ledger;
- centrally signed registration receipts, batch receipts, and completed-day
  checkpoints;
- identity/key/state backup and guarded restore;
- real end-to-end verification across operator-initialized key material (or
  packaged-helper key material used only by the E2E fallback), Java, Go, and
  SQLite.

Exit criteria:

- restarting either deployment or registry preserves identity and signatures;
- repeating a batch returns the original receipt and does not append;
- exact revenue retries return the original receipt, stale or branching
  corrections fail, and the global pool is calculated once from the active
  day/currency basis instead of by summing rounded deployment estimates;
- invalid signature, stale timestamp, nonce replay, and idempotency conflict are
  rejected;
- ledger and checkpoint verification succeed after restart;
- registry outage never prevents the local product from starting;
- the production public endpoint is HTTPS-only after redirect, the Go registry
  port is not published to the host or public network, and direct HTTP remains
  confined to the explicit local-development Compose path;
- no application user identity or activity is uploaded.

## Milestone 2 — local operator workspace and consent

Goal: add an operator authority next to ordinary user and admin while keeping
all secrets and external calls server-side.

Deliverables:

- explicit operator authority and access-policy keys, separate from moderation
  admin authority;
- operator authorization through the deployment's configured identity provider
  (Firebase in the current production path), with an explicit operator
  allowlist/bootstrap policy and no installer-generated shared password;
- prepare/inspect/confirm enrollment flow: preparation records only a
  candidate, inspection verifies the read-only registry identity preflight,
  and confirmation of that exact endpoint/scope/key tuple is the first
  operation allowed to initialize deployment identity, create registration
  state, or enqueue outbound retry work;
- authenticated, auditable node `Initialize` action invoked by confirmation;
  it calls the narrow host-persistence boundary, atomically establishes the
  first deployment key, and returns only public identity metadata;
- local Java operator APIs and Angular operator workspace;
- Angular operator data access implemented through the existing shared-core
  contract/entity, mapper, repository, base-service, local-service, and
  HTTP-service layers, with UI state owned by shared signal stores; local
  adapters use the configured artificial route delay and HTTP adapters use the
  central per-route timeout/error policy, leaving only presentation components
  inside the feature module;
- every browser-local seed transaction hydrates IndexedDB once, passes the same
  in-memory graph through all seed builders, mappers, and repositories, and
  flushes each completed seed step from that graph; no intermediate seed step
  re-queries IndexedDB;
- one operator settings model for routine configuration: operator override,
  then installer-provided default, then built-in default, with an explicit
  reset-to-default action; editing `.env` is a recovery/bootstrap path rather
  than the normal product workflow;
- registry connection states: disabled, registration-only, accounting enabled,
  and claim enabled;
- enrollment states shown independently from installation health: unregistered,
  registration pending, registered, receipt pending, complete, and action
  required;
- editable parent registry URL and program/accounting scope with HTTPS
  enforcement, certificate/key pin diagnostics, connection testing, and a
  deliberate
  insecure-local-development exception;
- route-change diagnostics that distinguish the same pinned parent registry
  behind a new domain from a genuinely different parent/signing identity;
- safe manual retry for transient failures and an explicit, warned
  re-enrollment flow when moving to a genuinely different registry identity;
- deployment-domain changes that preserve the deployment key, code, receipts,
  and registry identity without requiring re-registration;
- connection status, last successful receipt, pending outbox count, key ID,
  deployment code, protocol version, and safe retry controls;
- audit trail for operator setting changes;
- secrets returned to the UI only as presence/masked metadata.

Exit criteria:

- an ordinary user or admin cannot read/change operator-only settings;
- disabling outbound accounting stops Java registry calls without breaking the
  local app;
- the browser cannot obtain a deployment private key, provider secret, or full
  stored token.

## Milestone 3 — reliable, versioned qualified MAU

Goal: replace the current best-effort admin analytics as the accounting source
with a durable local evidence pipeline.

Deliverables:

- a dedicated local accounting event model, separate from Redis admin
  telemetry;
- stable event IDs, local user IDs, action type/version, occurred/recorded time,
  authentication assurance, exclusion state, and source record reference;
- idempotent persistence at the domain-action boundary and a durable outbound
  outbox;
- an authentication-provider interface and local scoped identity records using
  `(provider, issuer, subject)` without central/global linking;
- versioned MAU rulesets with fixtures for qualifying actions, day thresholds,
  verified identity requirements, and blocked/deleted/test exclusions;
- immutable monthly calculation snapshots and reproducible recalculation;
- per-period secret keys and
  `HMAC-SHA256(period_key, deployment_id || local_user_id)` pseudonyms;
- central batches containing only count, ruleset, commitment/root, period, and
  supporting audit metadata;
- retry-safe signed submissions and locally retained central receipts;
- compensating correction batches and a documented dispute window.

Exit criteria:

- a fresh calculation can be reproduced from durable local evidence;
- Redis loss does not change accounting;
- no raw local user ID or direct identifier crosses the deployment boundary;
- every central count names the exact ruleset and evidence commitment;
- the central service labels totals as deployment-level QMAU, not globally
  unique humans.

## Milestone 4 — operator claims, weight, and leaderboard

Goal: bind a deployment's history to an asserted or provisionally
provider-verified operator record without making claiming mandatory for local
operation. This milestone does not establish a legal beneficiary or payout
right.

Deliverables:

- signed claim challenge issued to the deployment backend;
- provisional operator/company identity verification through a maintained
  external identity/OAuth provider rather than a home-grown central password
  database; this verifies provider evidence and key control, not legal
  entitlement;
- server-side claim submission and proof of current deployment-key control;
- claim states: unclaimed, pending, verified, suspended, transferred,
  withdrawn, and disputed;
- explicit rules for retroactive history, transfers, key loss, and record dates;
- immutable claim-history entries;
- a virtual operator-ownership grouping model that associates multiple
  independently claimed deployments without treating the association as
  server routing, clustering, or shared deployment identity;
- a separate Operator Settings connection flow, independent from claiming:
  one claimed deployment exposes or generates a signed client code, and the
  operator enters that code on another claimed deployment to request that both
  deployments belong to the same virtual operator group;
- configurable client-code expiry plus explicit rotation and revocation;
  redemption and link acceptance are authenticated, deployment-signed, and
  audited, but a code is not inherently one-time unless the operator selects
  that policy; a code is never a deployment takeover bearer token;
- explicit consent and current claimed/provisionally verified operator records
  on both deployments before a group link becomes effective, without changing
  either claim;
- an explicit trust label explaining that a valid client code proves only an
  authenticated request to group deployments; it does not prove beneficial
  ownership, operator authority, untampered server/software, truthful MAU, or
  payout eligibility;
- append-only, effective-dated grouping membership history with `pending`,
  `connected`, `revoked`, `expired`, and `disputed` states, plus explicit
  transfer and revocation records;
- same-registry grouping first; any later cross-registry grouping requires an
  explicit bilateral parent policy and compatible domain separation, and can
  never act as a relay around a scope boundary;
- versioned weight formula and six-complete-month calculation if that remains
  the agreed formula;
- cursor-paginated registry summary and claimed/unclaimed leaderboard APIs
  with a deterministic versioned sort (calculated weight, then immutable
  operator/group ID as the tie-breaker); the operator row aggregates only
  already-computed deployment-level MAU and weight, and its contributing
  deployment list is fetched through a separate cursor-paginated endpoint
  carrying each deployment's claim/membership status;
- every leaderboard traversal is pinned to one immutable finalized calculation
  snapshot (formula/ruleset/through-period included); opaque cursors are bound
  to that snapshot, view, and filter set, while exact weights cross APIs as
  canonical integer numerator/denominator strings rather than floating-point
  values;
- cursor-paginated claim, grouping-membership, transfer, dispute, and audit
  histories so no operator screen or Java proxy must load an unbounded central
  result set;
- provisional leaderboard presentation: a claimed operator name may appear
  before human validation, but claim verification, grouping status, audit
  status, and any later exit-eligibility status remain visibly distinct;
- strict separation of deployment identities, claim histories, MAU receipts,
  ledger entries, weight calculations, and revenue allocations inside a
  grouping; raw users and identities are never merged by default, and any
  global-human deduplication remains the separate milestone 7 flow;
- local Angular leaderboard populated only through Java proxy APIs and the
  existing shared smart-list/query, repository/service, mapper, and signal-store
  pagination patterns;
- clear separation between measured network scale and provisional
  claimed/grouped weight; only milestone 8 buyer review can establish
  exit/legal eligibility.

Exit criteria:

- claiming or unclaiming does not alter historical MAU receipts;
- an unclaimed deployment has visible measured weight but no named provisional
  operator attribution;
- no browser-held claim token can take over a deployment without a valid
  deployment signature;
- disputes and transfers create an auditable history;
- leaderboard cursors remain stable for a fixed calculation snapshot, and
  expanding one operator never requires downloading every deployment or every
  history record;
- disconnecting or disputing a grouping never rewrites either deployment's
  claim, MAU, receipt, ledger, or historical weight records;
- neither a displayed name nor a connected group is represented as buyer
  approval, legal ownership, or a right to payment.

## Milestone 5 — operator-owned product configuration

Goal: make each deployment independently marketable and commercially operable.

Deliverables:

- ten token-based theme presets using CSS custom properties;
- all branding, provider, Firebase, forum/community, registry-route, and update
  preferences exposed through the authenticated local operator workspace
  rather than requiring routine server-file edits;
- operator logo/icon upload, safe image validation, home label, product name,
  contact links, and landing copy;
- immutable default assets plus reversible operator overrides;
- provider catalog and server-side encrypted payment credentials;
- provider capability/status checks and explicit test/live modes;
- operator-owned payout configuration, receipts, refunds, tax metadata, and
  merchant-of-record wording;
- server-side Firebase project/service-account configuration with validation,
  safe activation/rollback, and restart/reload behavior;
- masked secret rotation and audit events;
- external forum/community configuration, initially Discord or Discourse links
  and feeds instead of a custom forum;
- operator help links and central documentation cached locally so temporary
  registry unavailability does not remove help.

Exit criteria:

- a deployment can remove MyScoutee-facing brand presentation without changing
  source code;
- payment and Firebase secrets never appear in frontend storage or API
  responses;
- changing a provider has a test/rollback path;
- local commerce remains owned by the operator and is not mixed with network
  accounting.

## Milestone 6 — signed, operator-approved updates

Goal: let operators discover and install supported releases without granting
the registry arbitrary remote-code execution over deployments.

Deliverables:

- a versioned, registry-signed update manifest containing release version,
  channel, publication time, minimum/maximum compatible versions, artifact
  origin, artifact size and SHA-256 digest, package-signing identity, release
  notes URL, and revocation/supersession state;
- artifacts hosted on a dedicated HTTPS release service, GitHub Releases, or a
  signed Debian repository independently from the accounting database;
- Java retrieval and verification of manifests through the configured
  registry/relay, with registry-key pinning and durable caching of the last
  verified result;
- a local operator UI that displays the current and offered versions, exact
  download origin, digest/signature status, compatibility result, release
  notes, backup requirement, and expected downtime before enabling the upgrade
  action;
- an explicit operator confirmation for each version; checking for updates
  never implies consent to download or install one;
- download to a bounded staging area followed by artifact digest verification
  and Debian/package signature verification against a separately pinned
  release-signing key;
- a narrowly scoped privileged host helper that accepts a verified local
  package/version, not an arbitrary command or URL, and records the requesting
  operator and manifest hash;
- preflight backup, disk-space and health checks, upgrade progress, post-upgrade
  health verification, and a documented rollback/recovery path;
- release channels and optional automatic *notification*, while installation
  remains manual unless a later explicit policy is designed and audited;
- append-only local update audit events and central manifest transparency so an
  operator can independently verify what was offered.

Exit criteria:

- neither a registry response nor a browser request can execute a shell command
  or replace a package without a valid manifest, artifact signature, and
  operator approval;
- changing an artifact URL without changing the signed manifest is rejected;
- a compromised artifact host cannot serve a different package under the same
  release;
- loss of registry connectivity does not affect the running local product;
- failed post-upgrade health checks leave a usable recovery procedure and do
  not silently report success.

## Milestone 7 — explicit global identity linking and deduplication

Goal: measure globally linked people only where identity and consent evidence
actually support that claim.

Deliverables:

- separate central identity-linking store, not part of the public ledger;
- network identity IDs mapped to scoped source identities
  `(provider, issuer, subject)`;
- opt-in link flows using reauthentication or provider-issued proof;
- configurable central-token-validation versus deployment-validated evidence;
- registered/approved issuer configuration for each deployment;
- collision queues for shared email/phone, recycled identities, split accounts,
  and provider changes;
- user-confirmed merge/split operations with complete audit history;
- deduplicated accounting snapshots that reference an identity-linking ruleset;
- simultaneous reporting of deployment-level QMAU and globally linked unique
  users so the distinction remains visible;
- exportable source-to-target mappings for a future buyer identity migration.

Exit criteria:

- no accounts merge solely because names match;
- verified email/phone creates a candidate, not an automatic irreversible merge;
- every global deduplication decision is explainable and reversible by an
  append-only correction;
- users/deployments outside the opt-in linking scope remain deployment-level
  counts and are labeled accordingly.

## Milestone 8 — resilience, sovereign parent domains, and exit readiness

Goal: make the system operable across regions and auditable at contractual
scale.

Deliverables:

- deployment and central signing-key rotation with overlap and revocation;
- offline recovery packages and guarded identity restore;
- registry database/key/checkpoint backups tested by restoration drills;
- independently governed parent registries, selected by deployment policy,
  with distinct signing keys, databases, ledgers, claims, legal allocation,
  backups, and operator-selected endpoints;
- cryptographic domain separation by virtual-company/program and parent
  accounting scope on every request, receipt, ledger entry, and checkpoint;
- policy enforcement that one participation record cannot silently submit to
  both parent domains, with any exceptional transfer handled as an explicit
  legal/audited workflow rather than network forwarding;
- signed route metadata and overlap windows for a planned domain move *within
  one parent*, without silently replacing that parent's pinned signing key;
- product-neutral registry configuration and APIs so a separate virtual
  company can reuse the infrastructure with an isolated scope and ledger;
- audited cross-registry operator-grouping policy, where legally permitted,
  based on explicit consent and verifiable bilateral assertions; grouping
  metadata must not forward enrollment/accounting traffic, collapse
  deployment-level evidence, or bypass either parent's scope and data-transfer
  rules;
- public or independently witnessed checkpoint publication;
- operator audit exports and sampled evidence review;
- rate limits, abuse/fraud review, anomaly signals, and dispute SLAs;
- PostgreSQL storage implementation behind the same store interface when
  single-node SQLite limits are reached;
- optional read replicas/reporting stores without changing ledger semantics;
- exit record-date freeze, participation election, legal agreement state, and
  signed final allocation export;
- separate append-only exit-review records, controlled only by authorized
  buyer/auditor roles, with effective-dated `not-reviewed`, `review-pending`,
  `verified-eligible`, `rejected`, `disputed`, and `withdrawn` states;
- documented exit due diligence covering operator identity and authority,
  deployment/server and software-tamper inspection, reconciliation of signed
  receipts against registry ledger/checkpoints, MAU evidence sampling/audit,
  and contractual acceptance before eligibility or allocation is finalized;
- identity/provider and application-data migration tooling for participating
  operators only.

Exit criteria:

- a parent-registry outage cannot lose an accepted local batch;
- independently governed operation does not require prohibited cross-boundary
  enrollment or accounting transport;
- an operator group spanning permitted parent scopes remains expandable to
  separately verifiable deployment metrics and cannot silently merge user,
  claim, receipt, ledger, or allocation records;
- only an authorized exit-review decision can move a provisional claim/group
  into final eligibility, and every decision or later dispute remains
  independently auditable;
- a third party can verify receipts, ledger chaining, and published
  checkpoints;
- storage migration does not change protocol hashes or receipt validity;
- participating and non-participating deployments are unambiguously separated.

## Decisions deliberately deferred until their milestone

- the production QMAU ruleset;
- whether central token validation is required for every counted identity;
- the global-link consent and privacy model;
- the final weight window and founder/operator allocation formula;
- share-weighted revenue allocation and legal settlement, which require an
  immutable production weight snapshot and cannot be inferred from the current
  zero-count installation-test records;
- claim retroactivity and transfer terms;
- the preferred external operator/company identity provider;
- the forum provider;
- the threshold for moving SQLite to PostgreSQL.

These decisions must be versioned and documented before they affect accepted
accounting data. They must not be silently embedded in milestone 1.
