import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  createHash,
  generateKeyPairSync,
  sign
} from 'node:crypto';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const runner = fileURLToPath(new URL('../run.mjs', import.meta.url));
const ZERO_HASH = `sha256:${'0'.repeat(64)}`;

test('valid fixture passes and every read-only endpoint is requested exactly once', async t => {
  const fixture = createFixture();
  const target = await listen(t, fixture.handler);
  const result = await runVerifier([
    '--url', target,
    '--allow-http',
    '--expected-version', '1.0.0',
    '--expected-scope', fixture.scope,
    '--expected-key-id', fixture.keyId
  ]);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(
    Object.fromEntries([...fixture.requests].sort()),
    {
      '/healthz': 1,
      '/v1/registry/identity': 1,
      '/versionz': 1
    }
  );
  assert.deepEqual([...fixture.methods], ['GET']);
});

test('tampered canonical identity signature fails with exit 1', async t => {
  const fixture = createFixture({
    mutateIdentity(identity) {
      identity.signature = Buffer.alloc(64).toString('base64');
    }
  });
  const target = await listen(t, fixture.handler);
  const result = await runVerifier(['--url', target, '--allow-http']);
  assert.equal(result.code, 1);
});

test('derived key ID and expected identity pins fail closed', async t => {
  const fixture = createFixture({
    mutateIdentity(identity) {
      identity.registry_key_id = `rkey_${'f'.repeat(32)}`;
    }
  });
  const target = await listen(t, fixture.handler);
  const result = await runVerifier(['--url', target, '--allow-http']);
  assert.equal(result.code, 1);
});

test('health identity disagreement and ledger inconsistencies fail', async t => {
  const fixture = createFixture({
    mutateHealth(health) {
      health.registry_scope = 'fixture:other';
      health.ledger_index = 2;
      health.entry_count = 1;
    }
  });
  const target = await listen(t, fixture.handler);
  const result = await runVerifier(['--url', target, '--allow-http']);
  assert.equal(result.code, 1);
});

test('redirects are not followed', async t => {
  const fixture = createFixture({ redirectPath: '/versionz' });
  const target = await listen(t, fixture.handler);
  const result = await runVerifier(['--url', target, '--allow-http']);
  assert.equal(result.code, 1);
  assert.equal(fixture.requests.get('/redirect-target') ?? 0, 0);
});

test('security headers, content type, and response body bound are enforced', async t => {
  await t.test('missing no-store', async t => {
    const fixture = createFixture({ omitNoStorePath: '/healthz' });
    const target = await listen(t, fixture.handler);
    const result = await runVerifier(['--url', target, '--allow-http']);
    assert.equal(result.code, 1);
  });

  await t.test('wrong content type', async t => {
    const fixture = createFixture({ wrongContentTypePath: '/versionz' });
    const target = await listen(t, fixture.handler);
    const result = await runVerifier(['--url', target, '--allow-http']);
    assert.equal(result.code, 1);
  });

  await t.test('oversized body', async t => {
    const fixture = createFixture({ oversizedPath: '/healthz' });
    const target = await listen(t, fixture.handler);
    const result = await runVerifier(['--url', target, '--allow-http']);
    assert.equal(result.code, 1);
  });
});

test('usage and HTTPS policy failures exit 2 before network access', async () => {
  const missing = await runVerifier([]);
  assert.equal(missing.code, 2);

  const plainExternal = await runVerifier([
    '--url', 'http://registry.example',
    '--allow-http'
  ]);
  assert.equal(plainExternal.code, 2);

  const originWithPath = await runVerifier([
    '--url', 'https://registry.example/not-an-origin'
  ]);
  assert.equal(originWithPath.code, 2);
});

test('insecure TLS environment is refused and version mismatch exits 1', async t => {
  const insecure = await runVerifier(
    ['--url', 'https://registry.example'],
    { NODE_TLS_REJECT_UNAUTHORIZED: '0' }
  );
  assert.equal(insecure.code, 2);

  const fixture = createFixture();
  const target = await listen(t, fixture.handler);
  const mismatch = await runVerifier([
    '--url', target,
    '--allow-http',
    '--expected-version', '9.9.9'
  ]);
  assert.equal(mismatch.code, 1);
});

function createFixture(options = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const encodedPublicKey = spki.toString('base64');
  const keyId = `rkey_${createHash('sha256').update(spki).digest('hex').slice(0, 32)}`;
  const scope = 'fixture:primary';
  const identity = {
    protocol_version: '1',
    registry_scope: scope,
    registry_key_id: keyId,
    registry_public_key: encodedPublicKey,
    signature: ''
  };
  const message = Buffer.from([
    'myscoutee-registry-identity-v1',
    identity.protocol_version,
    identity.registry_scope,
    identity.registry_key_id,
    identity.registry_public_key,
    ''
  ].join('\n'));
  identity.signature = sign(null, message, privateKey).toString('base64');
  options.mutateIdentity?.(identity);

  const health = {
    status: 'ok',
    protocol_version: '1',
    registry_scope: scope,
    registry_key_id: keyId,
    ledger_index: 0,
    entry_count: 0,
    ledger_head_hash: ZERO_HASH
  };
  options.mutateHealth?.(health);
  const responses = {
    '/versionz': {
      service: 'myscoutee-registry',
      version: '1.0.0',
      protocol_version: '1'
    },
    '/v1/registry/identity': identity,
    '/healthz': health
  };
  const requests = new Map();
  const methods = new Set();
  const handler = (request, response) => {
    methods.add(request.method);
    const path = new URL(request.url, 'http://fixture.invalid').pathname;
    requests.set(path, (requests.get(path) ?? 0) + 1);
    if (path === options.redirectPath) {
      response.writeHead(302, { Location: '/redirect-target' });
      response.end();
      return;
    }
    if (path === '/redirect-target') {
      response.writeHead(500);
      response.end();
      return;
    }
    if (!(path in responses)) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.setHeader(
      'Content-Type',
      path === options.wrongContentTypePath ? 'text/plain' : 'application/json'
    );
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (path !== options.omitNoStorePath) {
      response.setHeader('Cache-Control', 'no-store');
    }
    const body = path === options.oversizedPath
      ? 'x'.repeat(64 * 1024 + 1)
      : JSON.stringify(responses[path]);
    response.end(body);
  };
  return { handler, keyId, methods, requests, scope };
}

async function listen(t, handler) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function runVerifier(args, environment = {}) {
  try {
    const result = await execFileAsync(process.execPath, [runner, ...args], {
      env: { ...process.env, ...environment },
      maxBuffer: 1024 * 1024,
      timeout: 10000
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return {
      code: typeof error.code === 'number' ? error.code : -1,
      stdout: error.stdout ?? '',
      stderr: error.stderr ?? `${error}`
    };
  }
}
