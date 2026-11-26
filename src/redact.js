/**
 * Redact a sensitive value so packsafe never leaks the secret it detected.
 * Shows at most the first 4 characters followed by length metadata.
 *
 * @param {string} value
 * @returns {string}
 */
export function redactSecret(value) {
  if (!value || value.length === 0) {
    return '[redacted len=0]';
  }
  const len = value.length;
  if (len <= 4) {
    return `***[len=${len}]`;
  }
  return `${value.slice(0, 4)}...[redacted len=${len}]`;
}

/**
 * Redact a matched substring inside a line and trim to a safe preview window.
 *
 * @param {string} line
 * @param {number} startIndex
 * @param {number} endIndex
 * @param {string} [replacement]
 * @returns {string}
 */
export function redactLineSnippet(line, startIndex, endIndex, replacement) {
  const rawMatch = line.slice(startIndex, endIndex);
  const masked = replacement ?? redactSecret(rawMatch);
  const before = line.slice(Math.max(0, startIndex - 24), startIndex);
  const after = line.slice(endIndex, Math.min(line.length, endIndex + 24));
  const prefix = startIndex > 24 ? '...' : '';
  const suffix = endIndex + 24 < line.length ? '...' : '';
  return `${prefix}${before}${masked}${after}${suffix}`.trim();
}
