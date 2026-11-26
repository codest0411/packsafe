/**
 * Format scan results as pretty-printed JSON.
 *
 * @param {import('../rules/types.js').ScanResult} result
 * @returns {string}
 */
export function formatJson(result) {
  return JSON.stringify(result, null, 2) + '\n';
}
