export class VerificationAssertionError extends Error {
  constructor(message, details = undefined) {
    super(message);
    this.name = 'VerificationAssertionError';
    this.details = details;
  }
}

export function assert(condition, message, details = undefined) {
  if (!condition) {
    throw new VerificationAssertionError(message, details);
  }
}

export function assertExactKeys(value, expectedKeys, label) {
  assert(isObject(value), `${label} must be a JSON object`, { value });
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${label} has an unexpected JSON shape`,
    { actualKeys: actual, expectedKeys: expected }
  );
  return value;
}

export function assertString(value, label) {
  assert(
    typeof value === 'string' && value.length > 0 && value === value.trim(),
    `${label} must be a non-empty canonical string`,
    { value }
  );
  return value;
}

export function assertInteger(value, label, minimum = 0) {
  assert(
    Number.isSafeInteger(value) && value >= minimum,
    `${label} must be a safe integer >= ${minimum}`,
    { value }
  );
  return value;
}

export function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function compactSnippet(value, maxLength = 600) {
  const compact = `${value ?? ''}`.replace(/\s+/g, ' ').trim();
  return compact.length <= maxLength ? compact : `${compact.slice(0, maxLength)}…`;
}
