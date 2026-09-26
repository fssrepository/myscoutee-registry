#!/usr/bin/env node
// MANUAL ONLY: this verifier is intentionally not registered in post-install,
// E2E, CI, or aggregate test commands.

import { buildChecks, CHECK_CATALOG } from './checks.mjs';
import { compactSnippet } from './lib/assertions.mjs';
import {
  createReadOnlyClient,
  parseDeploymentOrigin
} from './lib/http.mjs';

const EXIT_FAILURE = 1;
const EXIT_USAGE = 2;

await main();

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    usageError(error);
    return;
  }
  if (options.help) {
    printHelp();
    return;
  }
  if (options.list) {
    for (const [id, name] of CHECK_CATALOG) {
      console.log(`${id.padEnd(26)} ${name}`);
    }
    return;
  }
  if (typeof fetch !== 'function') {
    usageError(new Error('Node.js with built-in fetch support is required (Node 20+ recommended)'));
    return;
  }
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    usageError(new Error(
      'refusing NODE_TLS_REJECT_UNAUTHORIZED=0; use NODE_EXTRA_CA_CERTS for a private CA'
    ));
    return;
  }

  let context;
  try {
    context = createContext(options);
  } catch (error) {
    usageError(error);
    return;
  }
  const checks = buildChecks(context);
  const selected = checks.filter(check => matchesFilter(check, options.caseFilter));
  if (selected.length === 0) {
    usageError(new Error(`no deployment check matched --case ${options.caseFilter}`));
    return;
  }

  console.log('Verify registry deployment');
  console.log(`target: ${context.baseUrl.origin}`);
  console.log(`expected version: ${context.expectedVersion}`);
  if (context.expectedScope) {
    console.log(`expected scope: ${context.expectedScope}`);
  }
  if (context.expectedKeyId) {
    console.log(`expected key id: ${context.expectedKeyId}`);
  }
  console.log(`checks: ${selected.length}, request timeout: ${context.timeoutMs}ms, retries: 0`);

  const startedAt = performance.now();
  const outcomes = await Promise.all(selected.map(runCheck));
  let passed = 0;
  let failed = 0;
  for (const outcome of outcomes) {
    if (outcome.error) {
      failed += 1;
      console.error(`- FAIL ${outcome.id}`);
      console.error(`  ${outcome.error.message ?? outcome.error}`);
      if (outcome.error.details !== undefined) {
        console.error(`  details: ${compactSnippet(safeJson(outcome.error.details))}`);
      }
    } else {
      passed += 1;
      console.log(`- PASS ${outcome.id} ${Math.round(outcome.durationMs)}ms`);
    }
  }
  const summary = `registry deployment verification: ${passed} passed, ${failed} failed `
    + `in ${Math.round(performance.now() - startedAt)}ms`;
  if (failed > 0) {
    console.error(`\n${summary}`);
    process.exitCode = EXIT_FAILURE;
  } else {
    console.log(`\n${summary}`);
  }
}

function createContext(options) {
  const baseUrl = parseDeploymentOrigin(options.url, options.allowHttp);
  const timeoutMs = numericTimeout(options.timeoutMs);
  const expectedVersion = canonicalOption(options.expectedVersion, 'expected version', true);
  const expectedScope = canonicalOption(options.expectedScope, 'expected scope', false);
  const expectedKeyId = canonicalOption(options.expectedKeyId, 'expected key ID', false);
  if (expectedScope && !/^[a-z0-9][a-z0-9._:-]{2,127}$/.test(expectedScope)) {
    throw new Error('expected scope is malformed');
  }
  if (expectedKeyId && !/^rkey_[0-9a-f]{32}$/.test(expectedKeyId)) {
    throw new Error('expected key ID must use canonical rkey_<32 lowercase hex> form');
  }
  const client = createReadOnlyClient({ baseUrl, timeoutMs });
  const requests = new Map();
  const get = path => {
    if (!requests.has(path)) {
      requests.set(path, client.getJson(path));
    }
    return requests.get(path);
  };
  return {
    baseUrl,
    expectedKeyId,
    expectedScope,
    expectedVersion,
    get,
    timeoutMs
  };
}

async function runCheck(check) {
  const startedAt = performance.now();
  try {
    await check.run();
    return { id: check.id, durationMs: performance.now() - startedAt };
  } catch (error) {
    return { id: check.id, error, durationMs: performance.now() - startedAt };
  }
}

function parseArgs(argv) {
  const options = {
    allowHttp: process.env.VERIFY_DEPLOYMENT_ALLOW_HTTP === 'true',
    caseFilter: '',
    expectedKeyId: process.env.VERIFY_DEPLOYMENT_EXPECTED_KEY_ID ?? '',
    expectedScope: process.env.VERIFY_DEPLOYMENT_EXPECTED_SCOPE ?? '',
    expectedVersion: process.env.VERIFY_DEPLOYMENT_EXPECTED_VERSION ?? '1.3.0',
    help: false,
    list: false,
    timeoutMs: process.env.VERIFY_DEPLOYMENT_TIMEOUT_MS ?? '5000',
    url: process.env.VERIFY_DEPLOYMENT_URL ?? ''
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else if (argument === '--list') {
      options.list = true;
    } else if (argument === '--allow-http') {
      options.allowHttp = true;
    } else if (argument === '--url') {
      options.url = requiredValue(argv, ++index, '--url');
    } else if (argument.startsWith('--url=')) {
      options.url = argument.slice('--url='.length);
    } else if (argument === '--expected-version') {
      options.expectedVersion = requiredValue(argv, ++index, '--expected-version');
    } else if (argument.startsWith('--expected-version=')) {
      options.expectedVersion = argument.slice('--expected-version='.length);
    } else if (argument === '--expected-scope') {
      options.expectedScope = requiredValue(argv, ++index, '--expected-scope');
    } else if (argument.startsWith('--expected-scope=')) {
      options.expectedScope = argument.slice('--expected-scope='.length);
    } else if (argument === '--expected-key-id') {
      options.expectedKeyId = requiredValue(argv, ++index, '--expected-key-id');
    } else if (argument.startsWith('--expected-key-id=')) {
      options.expectedKeyId = argument.slice('--expected-key-id='.length);
    } else if (argument === '--timeout-ms') {
      options.timeoutMs = requiredValue(argv, ++index, '--timeout-ms');
    } else if (argument.startsWith('--timeout-ms=')) {
      options.timeoutMs = argument.slice('--timeout-ms='.length);
    } else if (argument === '--case') {
      options.caseFilter = requiredValue(argv, ++index, '--case');
    } else if (argument.startsWith('--case=')) {
      options.caseFilter = argument.slice('--case='.length);
    } else if (argument.startsWith('-')) {
      throw new Error(`unknown option: ${argument}`);
    } else if (!options.url) {
      options.url = argument;
    } else {
      throw new Error(`unexpected positional argument: ${argument}`);
    }
  }
  return options;
}

function requiredValue(argv, index, option) {
  const value = argv[index];
  if (!value || value.startsWith('-')) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function numericTimeout(value) {
  const timeoutMs = Number(value);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 250 || timeoutMs > 30000) {
    throw new Error('timeout must be an integer between 250 and 30000 ms');
  }
  return timeoutMs;
}

function canonicalOption(value, label, required) {
  const raw = `${value ?? ''}`;
  const canonical = raw.trim();
  if ((required && !canonical) || raw !== canonical) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return canonical;
}

function matchesFilter(check, filter) {
  if (!filter) {
    return true;
  }
  const normalized = filter.toLowerCase();
  return check.id.toLowerCase().includes(normalized)
    || check.name.toLowerCase().includes(normalized);
}

function usageError(error) {
  console.error(`registry deployment verification error: ${error.message}`);
  console.error(`Run ${runnerCommand()} --help for usage.`);
  process.exitCode = EXIT_USAGE;
}

function printHelp() {
  console.log(`Verify a running registry deployment (manual, external, read-only)

Usage:
  ${runnerCommand()} --url https://registry.example [options]
  ${runnerCommand()} https://registry.example [options]

Options:
  --url URL                 Registry origin (or VERIFY_DEPLOYMENT_URL)
  --expected-version X.Y.Z  Exact /versionz version (default: 1.3.0)
  --expected-scope SCOPE    Pin the signed registry scope
  --expected-key-id KEY_ID  Pin the derived Ed25519 registry key ID
  --timeout-ms MS           Per-request timeout, 250-30000 (default: 5000)
  --case FILTER             Run checks whose id or name contains FILTER
  --allow-http              Loopback-only VM tunnel smoke test
  --list                    List checks without requiring a URL
  --help                    Show this help

The verifier sends one GET each to /versionz, /v1/registry/identity, and
/healthz. Redirects, retries, mutation requests, and insecure TLS are forbidden.
For a private CA, use NODE_EXTRA_CA_CERTS=/path/to/ca.pem.`);
}

function runnerCommand() {
  return `node ${JSON.stringify(process.argv[1] || 'verify-deployment/run.mjs')}`;
}

function safeJson(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return `${value}`;
  }
}
