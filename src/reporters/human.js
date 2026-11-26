import { formatBytes } from '../rules/ps007-size-sanity.js';

/**
 * Format scan results for human-readable terminal output.
 * Colors are enabled ONLY when `useColor` is true (TTY and NO_COLOR unset).
 *
 * @param {import('../rules/types.js').ScanResult} result
 * @param {{ useColor?: boolean }} [options]
 * @returns {string}
 */
export function formatHuman(result, options = {}) {
  const useColor = options.useColor === true;
  const c = {
    reset: useColor ? '\x1b[0m' : '',
    bold: useColor ? '\x1b[1m' : '',
    dim: useColor ? '\x1b[2m' : '',
    red: useColor ? '\x1b[31m' : '',
    yellow: useColor ? '\x1b[33m' : '',
    cyan: useColor ? '\x1b[36m' : '',
    green: useColor ? '\x1b[32m' : ''
  };

  /** @type {string[]} */
  const lines = [];
  lines.push(
    `${c.bold}packsafe${c.reset} ${c.dim}${result.packageName}@${result.packageVersion} (${result.fileCount} files, ${formatBytes(result.totalSize)})${c.reset}`
  );
  lines.push('');

  for (const f of result.findings) {
    const sevColor = f.severity === 'error' ? c.red : f.severity === 'warn' ? c.yellow : c.cyan;
    const sevLabel = f.severity.toUpperCase().padEnd(5);
    const loc = f.line ? `${f.file}:${f.line}${f.column ? `:${f.column}` : ''}` : f.file;
    lines.push(`${sevColor}${sevLabel}${c.reset} ${c.bold}[${f.ruleId}]${c.reset} ${loc}`);
    lines.push(`      ${f.message}`);
    if (f.snippet) {
      lines.push(`      ${c.dim}${f.snippet}${c.reset}`);
    }
  }

  lines.push('');
  const statusColor = result.failed ? c.red : c.green;
  const statusWord = result.failed ? 'FAILED' : 'PASSED';
  lines.push(
    `${statusColor}${c.bold}${statusWord}${c.reset} — ${result.counts.error} error(s), ${result.counts.warn} warning(s), ${result.counts.info} info (fail-on: ${result.failOn})`
  );

  return lines.join('\n') + '\n';
}
