import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from 'node:crypto';

import {
  assert,
  assertExactKeys,
  assertInteger,
  assertString
} from './lib/assertions.mjs';

const PROTOCOL_VERSION = '1';
const SERVICE = 'myscoutee-registry';
const ZERO_HASH = `sha256:${'0'.repeat(64)}`;

export const CHECK_CATALOG = [
  ['registry/version', 'build and protocol version'],
  ['registry/identity', 'canonical Ed25519 registry identity'],
  ['registry/health', 'registry health and ledger head'],
  ['registry/cross-check', 'version, identity, and health agreement']
];

export function buildChecks(ctx) {
  const versionResult = once(() => ctx.get('/versionz'));
  const identityResult = once(() => ctx.get('/v1/registry/identity'));
  const healthResult = once(() => ctx.get('/healthz'));

  const version = once(async () => verifyVersion(
    (await versionResult()).data,
    ctx.expectedVersion
  ));
  const identity = once(async () => verifyIdentity(
    (await identityResult()).data,
    ctx.expectedScope,
    ctx.expectedKeyId
  ));
  const health = once(async () => verifyHealth((await healthResult()).data));

  return [
    check('registry/version', 'build and protocol version', version),
    check('registry/identity', 'canonical Ed25519 registry identity', identity),
    check('registry/health', 'registry health and ledger head', health),
    check('registry/cross-check', 'version, identity, and health agreement', async () => {
      const [versionValue, identityValue, healthValue] = await Promise.all([
        version(),
        identity(),
        health()
      ]);
      assert(
        identityValue.protocol_version === versionValue.protocol_version,
        'signed identity protocol_version does not match /versionz',
        { version: versionValue.protocol_version, identity: identityValue.protocol_version }
      );
      assert(
        healthValue.protocol_version === versionValue.protocol_version,
        'health protocol_version does not match /versionz',
        { version: versionValue.protocol_version, health: healthValue.protocol_version }
      );
      assert(
        healthValue.registry_scope === identityValue.registry_scope,
        'health registry_scope does not match the signed identity',
        { identity: identityValue.registry_scope, health: healthValue.registry_scope }
      );
      assert(
        healthValue.registry_key_id === identityValue.registry_key_id,
        'health registry_key_id does not match the signed identity',
        { identity: identityValue.registry_key_id, health: healthValue.registry_key_id }
      );
    })
  ];
}

function check(id, name, run) {
  return { id, name, run };
}

function once(loader) {
  let promise;
  return () => {
    promise ??= Promise.resolve().then(loader);
    return promise;
  };
}

function verifyVersion(value, expectedVersion) {
  const version = assertExactKeys(
    value,
    ['service', 'version', 'protocol_version'],
    '/versionz'
  );
  assert(version.service === SERVICE, `/versionz service must be ${SERVICE}`, {
    service: version.service
  });
  assertString(version.version, '/versionz version');
  assert(
    version.protocol_version === PROTOCOL_VERSION,
    `/versionz protocol_version must be ${PROTOCOL_VERSION}`,
    { protocolVersion: version.protocol_version }
  );
  if (expectedVersion) {
    assert(
      version.version === expectedVersion,
      `/versionz version ${version.version} does not match expected ${expectedVersion}`,
      { actual: version.version, expected: expectedVersion }
    );
  }
  return version;
}

function verifyIdentity(value, expectedScope, expectedKeyId) {
  const identity = assertExactKeys(
    value,
    [
      'protocol_version',
      'registry_scope',
      'registry_key_id',
      'registry_public_key',
      'signature'
    ],
    '/v1/registry/identity'
  );
  assert(
    identity.protocol_version === PROTOCOL_VERSION,
    `identity protocol_version must be ${PROTOCOL_VERSION}`,
    { protocolVersion: identity.protocol_version }
  );
  assert(
    isRegistryScope(identity.registry_scope),
    'identity registry_scope is malformed',
    { registryScope: identity.registry_scope }
  );
  if (expectedScope) {
    assert(
      identity.registry_scope === expectedScope,
      `identity registry_scope ${identity.registry_scope} does not match expected ${expectedScope}`
    );
  }

  const spki = decodeCanonicalBase64(
    identity.registry_public_key,
    'identity registry_public_key'
  );
  let publicKey;
  try {
    publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch (error) {
    throw new Error(`identity registry_public_key is not valid SPKI: ${error.message}`);
  }
  assert(
    publicKey.asymmetricKeyType === 'ed25519',
    'identity registry_public_key must be Ed25519',
    { asymmetricKeyType: publicKey.asymmetricKeyType }
  );
  const canonicalSpki = publicKey.export({ format: 'der', type: 'spki' });
  assert(
    canonicalSpki.equals(spki),
    'identity registry_public_key SPKI encoding is not canonical'
  );
  const derivedKeyId = `rkey_${createHash('sha256').update(spki).digest('hex').slice(0, 32)}`;
  assert(
    identity.registry_key_id === derivedKeyId,
    'identity registry_key_id does not match the canonical SPKI key',
    { actual: identity.registry_key_id, derived: derivedKeyId }
  );
  if (expectedKeyId) {
    assert(
      identity.registry_key_id === expectedKeyId,
      `identity registry_key_id ${identity.registry_key_id} does not match expected ${expectedKeyId}`
    );
  }
  const signature = decodeCanonicalBase64(identity.signature, 'identity signature');
  assert(signature.length === 64, 'identity signature must be a 64-byte Ed25519 signature');
  const message = Buffer.from([
    'myscoutee-registry-identity-v1',
    identity.protocol_version,
    identity.registry_scope,
    identity.registry_key_id,
    identity.registry_public_key,
    ''
  ].join('\n'), 'utf8');
  assert(
    verifySignature(null, message, publicKey, signature),
    'registry identity canonical signature verification failed'
  );
  return identity;
}

function verifyHealth(value) {
  const health = assertExactKeys(
    value,
    [
      'status',
      'protocol_version',
      'registry_scope',
      'registry_key_id',
      'ledger_index',
      'entry_count',
      'ledger_head_hash'
    ],
    '/healthz'
  );
  assert(health.status === 'ok', '/healthz status must be ok', { status: health.status });
  assert(
    health.protocol_version === PROTOCOL_VERSION,
    `/healthz protocol_version must be ${PROTOCOL_VERSION}`
  );
  assert(isRegistryScope(health.registry_scope), '/healthz registry_scope is malformed');
  assert(
    /^rkey_[0-9a-f]{32}$/.test(health.registry_key_id),
    '/healthz registry_key_id is malformed'
  );
  assertInteger(health.ledger_index, '/healthz ledger_index');
  assertInteger(health.entry_count, '/healthz entry_count');
  assert(
    health.ledger_index === health.entry_count,
    '/healthz ledger_index and entry_count are inconsistent',
    { ledgerIndex: health.ledger_index, entryCount: health.entry_count }
  );
  assert(
    /^sha256:[0-9a-f]{64}$/.test(health.ledger_head_hash),
    '/healthz ledger_head_hash is not a canonical SHA-256 digest'
  );
  assert(
    (health.ledger_index === 0) === (health.ledger_head_hash === ZERO_HASH),
    '/healthz ledger extent and ledger_head_hash zero state are inconsistent'
  );
  return health;
}

function decodeCanonicalBase64(value, label) {
  assertString(value, label);
  assert(
    value.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(value),
    `${label} is not padded RFC 4648 base64`
  );
  const decoded = Buffer.from(value, 'base64');
  assert(decoded.toString('base64') === value, `${label} base64 encoding is not canonical`);
  return decoded;
}

function isRegistryScope(value) {
  return typeof value === 'string'
    && value.length >= 3
    && value.length <= 128
    && /^[a-z0-9][a-z0-9._:-]*$/.test(value);
}
