import net from 'node:net';

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

export class VerificationRequestError extends Error {
  constructor(message, details = undefined) {
    super(message);
    this.name = 'VerificationRequestError';
    this.details = details;
  }
}

export function parseDeploymentOrigin(value, allowHttp = false) {
  const raw = `${value ?? ''}`.trim();
  if (!raw) {
    throw new VerificationRequestError('a registry deployment URL is required');
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new VerificationRequestError('deployment URL must be an absolute HTTPS origin');
  }
  if (url.username || url.password) {
    throw new VerificationRequestError('deployment URL must not contain credentials');
  }
  if ((url.pathname !== '' && url.pathname !== '/') || url.search || url.hash) {
    throw new VerificationRequestError(
      'deployment URL must contain only the scheme and authority (no path, query, or fragment)'
    );
  }
  if (url.protocol === 'http:') {
    if (!allowHttp) {
      throw new VerificationRequestError(
        'HTTPS is required; --allow-http is only for a loopback VM tunnel smoke test'
      );
    }
    if (!isLoopbackHostname(url.hostname)) {
      throw new VerificationRequestError(
        '--allow-http is restricted to localhost or a literal loopback IP address'
      );
    }
  } else if (url.protocol !== 'https:') {
    throw new VerificationRequestError('deployment URL must use https://');
  }
  url.pathname = '/';
  return url;
}

export function createReadOnlyClient({ baseUrl, timeoutMs, maxBodyBytes }) {
  const origin = baseUrl instanceof URL
    ? new URL(baseUrl)
    : parseDeploymentOrigin(baseUrl);
  const requestTimeoutMs = Number(timeoutMs ?? 5000);
  const responseLimit = Number(maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
  if (!Number.isInteger(requestTimeoutMs)
      || requestTimeoutMs < 250
      || requestTimeoutMs > 30000) {
    throw new VerificationRequestError(
      'request timeout must be an integer between 250 and 30000 ms'
    );
  }
  if (!Number.isInteger(responseLimit)
      || responseLimit < 1024
      || responseLimit > 1024 * 1024) {
    throw new VerificationRequestError('maximum response body size is invalid');
  }

  async function getJson(path) {
    const target = new URL(path, origin);
    if (target.origin !== origin.origin || target.search || target.hash) {
      throw new VerificationRequestError('verifier request escaped the deployment origin', {
        target: target.toString()
      });
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
    let response;
    try {
      response = await fetch(target, {
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store',
        headers: {
          Accept: 'application/json',
          'Accept-Encoding': 'identity',
          'Cache-Control': 'no-cache',
          'User-Agent': 'myscoutee-registry-deployment-verifier/1'
        },
        signal: controller.signal
      });
      if (response.status >= 300 && response.status < 400) {
        await cancelBody(response);
        throw new VerificationRequestError(`GET ${path} returned a forbidden redirect`, {
          status: response.status,
          location: response.headers.get('location') ?? ''
        });
      }
      const bytes = await readBoundedBody(response, responseLimit, path);
      const result = {
        requestUrl: target.toString(),
        responseUrl: response.url,
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        bytes
      };
      if (response.url !== target.toString()) {
        throw new VerificationRequestError(`GET ${path} finished at an unexpected URL`, {
          expected: target.toString(),
          actual: response.url
        });
      }
      if (response.status !== 200) {
        throw new VerificationRequestError(`GET ${path} expected HTTP 200, got ${response.status}`, {
          status: response.status,
          body: new TextDecoder().decode(bytes).slice(0, 400)
        });
      }
      validateJsonSecurityHeaders(result, path, origin.protocol === 'https:');
      let text;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        throw new VerificationRequestError(`GET ${path} returned non-UTF-8 JSON`);
      }
      try {
        result.data = JSON.parse(text);
      } catch (error) {
        throw new VerificationRequestError(`GET ${path} returned invalid JSON: ${error.message}`);
      }
      return result;
    } catch (error) {
      if (error instanceof VerificationRequestError) {
        throw error;
      }
      const reason = error?.name === 'AbortError'
        ? `timed out after ${requestTimeoutMs} ms`
        : `${error?.message ?? error}${error?.cause?.code ? ` (${error.cause.code})` : ''}`;
      throw new VerificationRequestError(`GET ${target} failed: ${reason}`);
    } finally {
      clearTimeout(timer);
    }
  }

  return { getJson };
}

function validateJsonSecurityHeaders(result, path, requireHsts) {
  const contentType = `${result.headers['content-type'] ?? ''}`.trim().toLowerCase();
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(contentType)) {
    throw new VerificationRequestError(
      `GET ${path} must return Content-Type: application/json`,
      { contentType }
    );
  }
  if (`${result.headers['x-content-type-options'] ?? ''}`.trim().toLowerCase() !== 'nosniff') {
    throw new VerificationRequestError(
      `GET ${path} must return X-Content-Type-Options: nosniff`
    );
  }
  const cacheDirectives = `${result.headers['cache-control'] ?? ''}`
    .split(',')
    .map(value => value.trim().toLowerCase());
  if (!cacheDirectives.includes('no-store')) {
    throw new VerificationRequestError(`GET ${path} must return Cache-Control: no-store`);
  }
  if (requireHsts) {
    const hsts = `${result.headers['strict-transport-security'] ?? ''}`;
    const maxAge = hsts.match(/(?:^|[;\s])max-age\s*=\s*(\d+)/i);
    if (!maxAge || Number(maxAge[1]) < 31536000) {
      throw new VerificationRequestError(
        `GET ${path} must return Strict-Transport-Security with max-age >= 31536000`,
        { strictTransportSecurity: hsts }
      );
    }
  }
}

async function readBoundedBody(response, maxBytes, path) {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    await cancelBody(response);
    throw new VerificationRequestError(
      `GET ${path} exceeded the ${maxBytes}-byte response limit`
    );
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new VerificationRequestError(
          `GET ${path} exceeded the ${maxBytes}-byte response limit`
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function cancelBody(response) {
  if (response.body) {
    await response.body.cancel();
  }
}

function isLoopbackHostname(hostname) {
  const normalized = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
  if (normalized.toLowerCase() === 'localhost') {
    return true;
  }
  const kind = net.isIP(normalized);
  if (kind === 4) {
    return normalized.split('.')[0] === '127';
  }
  return kind === 6 && normalized === '::1';
}
