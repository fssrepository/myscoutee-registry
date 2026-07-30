# Verify a registry deployment

> **MANUAL OPERATOR COMMAND — not an automated E2E or post-install test.**

This external verifier checks an already running registry at an
Operator-supplied origin. It never starts or changes a deployment and sends
exactly one unauthenticated `GET` to each of:

- `/versionz`
- `/v1/registry/identity`
- `/healthz`

No installer hook, qualification job, E2E suite, or aggregate test runner
invokes it.

## Run

Node.js 20 or newer is recommended:

```bash
node packaging/verify-deployment/run.mjs \
  --url https://registry.example \
  --expected-version 1.0.0
```

`1.0.0` is the default expected version. Release operators should still pass
the package version explicitly. The target can also be positional or supplied
with `VERIFY_DEPLOYMENT_URL`.

Pin the registry's sovereign identity when the expected values are known:

```bash
node packaging/verify-deployment/run.mjs \
  https://registry.example \
  --expected-version 1.0.0 \
  --expected-scope production:primary \
  --expected-key-id rkey_0123456789abcdef0123456789abcdef
```

Use `--list`, `--case FILTER`, or `--help` to inspect and select checks.
Invalid invocation exits 2, a failed deployment verification exits 1, and a
complete pass exits 0.

## Verification boundary

The command requires an origin-only HTTPS URL, follows no redirects, performs
no retries, bounds every response body to 64 KiB, and applies a five-second
per-request timeout by default. Normal Node TLS validation checks certificate
trust, hostname, and validity. Insecure TLS is deliberately unsupported and
`NODE_TLS_REJECT_UNAUTHORIZED=0` is refused.

For a private CA, extend normal trust:

```bash
NODE_EXTRA_CA_CERTS=/path/to/private-ca.pem \
node packaging/verify-deployment/run.mjs --url https://registry.example
```

`--allow-http` is restricted to `localhost` or a literal loopback address. It
exists only for an intentional VM/tunnel smoke test such as
`http://127.0.0.1:18081`; it cannot weaken TLS for a production host.

The verifier checks the exact JSON shapes, content type, `nosniff`,
`Cache-Control: no-store`, and (over HTTPS) HSTS. It requires protocol version
1 and the expected build version. It parses the identity key as canonical
base64 DER SPKI, requires Ed25519, derives and pins its `rkey_` key ID, and
verifies the canonical identity signature. Finally it cross-checks the signed
scope/key/protocol against health and validates ledger index, entry count, and
head-hash invariants.

This is a public black-box check. It does not prove package-manager state,
systemd state, local file permissions, database backups, or private container
health.
