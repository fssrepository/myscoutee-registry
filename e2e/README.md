# Registry black-box E2E tests

These tests exercise the Go registry as its own deployable service. They build
and start the real `cmd/registry` binary on a loopback TCP port with a temporary
SQLite database and signing key. They do not start or call the Java server.

The suite is behind the `e2e` build tag so the normal unit-test command remains
fast:

```bash
go test ./...
```

Run the standalone registry E2E suite explicitly:

```bash
go test -tags=e2e -count=1 -v ./e2e
```

The tests cover:

- process startup, health checking, graceful shutdown, and restart;
- signed registry identity stability without ledger mutation;
- canonical request-target and strict JSON rejection;
- signed deployment registration and idempotent retry;
- signed installation-test submission, immutable receipt lookup, and restart
  persistence;
- registry receipt and ledger-hash verification from the black-box test client;
- fail-closed scope/key identity binding;
- concurrent local announcement publication through the real CLI and retrieval
  through the real HTTP server.

Every case uses its own temporary directory and loopback port. No shared
registry database, signing key, Docker volume, or Java state is touched.
