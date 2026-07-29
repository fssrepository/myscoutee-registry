# Registry production qualification

This document separates automated registry evidence from release operations
that cannot be proven by a unit-test result. Passing the repository tests does
not by itself authorize a production rollout.

## Automated registry gates

Run from the registry repository without starting a Compose stack:

```bash
go test ./...
go vet ./...
go build -trimpath -o /tmp/myscoutee-registry ./cmd/registry
docker build -t myscoutee-registry:qualification .
```

With the Java backend repository checked out beside this repository, run the
real cross-language rail gate separately:

```bash
./scripts/qualify-java-rails.sh
```

Set `MYSCOUTEE_BACKEND_ROOT` when the repositories are not siblings. The runner
builds the current Go command, starts it on loopback with disposable SQLite and
signing-key paths, and runs only
`OperatorGoRegistryRailQualificationTest`. The Java test uses disposable
embedded Mongo for the real outbox repositories. It does not start Docker, the
Java application, Redis, the frontend, or a development stack.

This gate proves, with Java-generated Ed25519 requests consumed by the Go HTTP
server:

- accepted QMAU and revenue delivery with Go-signed receipts;
- a Java-submitted structured claim, registry-manager CLI approval, ordinary
  completed-month calculation, and a Java-signed private
  `/v1/settlements/query` whose Go-signed response is fully verified and mapped
  by the production Java settlement service;
- response loss after Go acceptance, durable Java outbox recovery through a
  new service/repository instance, and exact idempotent retry;
- the same recovery after restarting the Go process over its original SQLite
  database and signing key;
- duplicate receipts, QMAU and revenue correction/supersession revisions, Go
  rejection of invalid Java request signatures, and Java rejection of a
  tampered Go receipt signature.

The test suite uses real temporary SQLite databases, real Ed25519 keys, and
in-process HTTP servers. The relevant release gates cover:

- deployment registration, request/receipt signatures, replay protection,
  exact idempotent retry, scope separation, and completed-day checkpoints;
- signed `monthly-qmau` revision/supersession, commitment-bearing receipts,
  latest-revision leaderboard reads, and stale-branch rejection;
- signed daily revenue snapshots/corrections and direct query-table equality;
- the linear authoritative ledger, compact RFC 9162-style Merkle index,
  signed historical inclusion/consistency proofs for every tree size from
  1 through 17, and persisted-node tamper detection;
- structured claims, manager review, temporary client codes, direct
  leaderboard state, announcements, and immutable audit chains;
- restart/key-loss guards and a closed-database backup/restore drill that
  preserves the seeded registry scope, key ID, ledger head, and Merkle proof;
- guarded demo seeding, interrupted-seed resume, exact idempotent restart,
  latest-six-complete-month QMAU refresh, deterministic signed revenue sources
  plus ordinary settlement calculation, and rejection of disabled,
  production-scope, non-demo-path, or populated-unmarked seed targets.

The Docker release image must additionally be inspected as:

- a statically linked, `-trimpath`, stripped Go binary;
- a scratch runtime image with no package manager or shell;
- numeric non-root user `65532:65532`;
- read-only-compatible filesystem with writable data volume and bounded
  `/tmp`;
- only container port 8080 exposed by image metadata.

The production MyScoutee package may include this image only for the
server-backed Explore workspace. That service must use:

- image `myscoutee-registry:<version>-prod`;
- command `start-demo`;
- `REGISTRY_DEMO_SEED=true`;
- a `demo:` registry scope;
- database and key filenames containing `demo`;
- registry and Java-client volumes distinct from all operator/central state;
- an internal Docker network with no host `ports` entry.

This is not a bundled real registry. A real/operator registry is deployed
separately with ordinary startup, an explicit non-demo scope, a separate
database/key/volume, and a TLS edge.

## Merkle cost boundary

The Merkle delta is intentionally bounded:

- leaves reuse ledger entry hashes and are not stored twice;
- `n` leaves store exactly `n - popcount(n)` internal rows;
- one append computes one leaf plus at most `floor(log2(n))` parent hashes,
  with one parent hash amortized per append;
- inclusion and consistency proof generation/verification are `O(log n)`;
- full Merkle validation runs at bootstrap, health checks, checkpoint
  finalization, and explicit verification, not as an additional scan on every
  ordinary request.

The ordinary operational integrity gate is also bounded:

- a successful startup/full audit establishes the immutable trusted prefix;
- an unchanged SQLite `data_version` is an `O(1)` fast-path check proving no
  other connection committed since that audit/boundary;
- Store writes on the server connection remain serialized and transactional;
- a commit from another connection (normally the local CLI) requires identity,
  append-only-trigger, cryptographic head/predecessor, source/query boundary,
  signature, and Merkle-frontier validation before the new revision is trusted;
- the Merkle frontier check is `O(log n)` worst-case and amortized `O(1)`;
- a failed complete audit is latched fail-closed until a later complete audit
  succeeds.

The qualification test records the full-audit counter across real signed
registration, QMAU append/retry/correction, receipt, leaderboard, and Merkle
proof reads. It proves those ordinary paths perform no additional full scan;
an explicit health check performs one.

## Release drills that remain mandatory

The following require the actual candidate Java package, Go image, installer,
host storage, TLS endpoint, and supported upgrade sources. They cannot be
truthfully marked complete by this repository alone:

1. Re-run the Java-to-Go QMAU/revenue/signature rail gate against the exact
   release artifacts, rather than only the source-built Go command and Java
   test runtime used by the automated gate.
2. Install, restart, power-loss, registry-outage, and retry drills on every
   supported deployment topology.
3. Online SQLite backup or storage-snapshot restore with the matching signing
   key, including a restore to a clean host and verification of every signed
   record.
4. Upgrade from the oldest supported package through every required schema and
   image transition, followed by rollback/restore rehearsal.
5. Multi-registry isolation using distinct public TLS endpoints, scopes, keys,
   databases, and volumes; deactivation before moving a deployment between
   registries.
6. Sustained and burst load tests sized to the expected deployment, QMAU,
   leaderboard, proof, and announcement volumes.
7. Independent security review of canonical signing, key custody, TLS,
   package/update signatures, CLI access, SQLite corruption behavior, privacy,
   and abuse/rate-limit controls.

Record the candidate image digest, package checksum, source commit, commands,
timings, host/kernel/filesystem, and pass/fail evidence for every drill. A
release is not fully production-qualified while any mandatory drill above
remains open.
