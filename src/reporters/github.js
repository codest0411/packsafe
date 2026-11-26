/**
 * Escape special characters for GitHub Actions workflow commands.
 * @param {string} str
 * @returns {string}
 */
function escapeGhProperty(str) {
  return str.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A').replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/**
 * Escape message body for GitHub Actions workflow commands.
 * @param {string} str
 * @returns {string}
 */
function escapeGhData(str) {
  return str.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/**
 * Format scan results as GitHub Actions annotations (`::error`, `::warning`, `::notice`).
 *
 * @param {import('../rules/types.js').ScanResult} result
 * @returns {string}
 */
export function formatGithub(result) {
  /** @type {string[]} */
  const lines = [];
  for (const f of result.findings) {
    const level = f.severity === 'error' ? 'error' : f.severity === 'warn' ? 'warning' : 'notice';
    const props = [`file=${escapeGhProperty(f.file)}`];
    if (f.line) props.push(`line=${f.line}`);
    if (f.column) props.push(`col=${f.column}`);
    props.push(`title=${escapeGhProperty(`[${f.ruleId}]`)}`);
    lines.push(`::${level} ${props.join(',')}::${escapeGhData(f.message)}`);
  }
  return lines.length > 0 ? lines.join('\n') + '\n' : '';
}
