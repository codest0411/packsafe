/** @type {import('./types.js').RuleMeta} */
export const RULE_PS007 = {
  id: 'PS007',
  name: 'size-sanity',
  defaultSeverity: 'info',
  description: 'Reports total unpacked size, file count, and top 5 largest files; warns when configurable thresholds are exceeded.'
};

export const DEFAULT_SIZE_THRESHOLDS = {
  maxTotalBytes: 10 * 1024 * 1024, // 10 MB
  maxFileCount: 500,
  maxFileBytes: 2 * 1024 * 1024 // 2 MB
};

/**
 * Format byte count into a human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Evaluate package size sanity across the publish set.
 *
 * @param {Array<{ relPosix: string, size: number }>} files
 * @param {number} totalSize
 * @param {{ maxTotalBytes?: number, maxFileCount?: number, maxFileBytes?: number }} [thresholds]
 * @returns {{
 *   findings: import('./types.js').Finding[],
 *   topLargest: Array<{ file: string, size: number }>
 * }}
 */
export function evaluateSizePS007(files, totalSize, thresholds = {}) {
  const maxTotalBytes = thresholds.maxTotalBytes ?? DEFAULT_SIZE_THRESHOLDS.maxTotalBytes;
  const maxFileCount = thresholds.maxFileCount ?? DEFAULT_SIZE_THRESHOLDS.maxFileCount;
  const maxFileBytes = thresholds.maxFileBytes ?? DEFAULT_SIZE_THRESHOLDS.maxFileBytes;

  const sorted = [...files].sort((a, b) => b.size - a.size);
  const topLargest = sorted.slice(0, 5).map((f) => ({ file: f.relPosix, size: f.size }));

  /** @type {import('./types.js').Finding[]} */
  const findings = [];

  if (totalSize > maxTotalBytes) {
    findings.push({
      ruleId: RULE_PS007.id,
      severity: 'warn',
      file: 'package.json',
      message: `Total unpacked size ${formatBytes(totalSize)} exceeds threshold ${formatBytes(maxTotalBytes)}`
    });
  }

  if (files.length > maxFileCount) {
    findings.push({
      ruleId: RULE_PS007.id,
      severity: 'warn',
      file: 'package.json',
      message: `Publish file count (${files.length}) exceeds threshold (${maxFileCount})`
    });
  }

  for (const f of sorted) {
    if (f.size > maxFileBytes) {
      findings.push({
        ruleId: RULE_PS007.id,
        severity: 'warn',
        file: f.relPosix,
        message: `File size ${formatBytes(f.size)} exceeds single-file threshold ${formatBytes(maxFileBytes)}`
      });
    }
  }

  const topSummary = topLargest.map((t) => `${t.file} (${formatBytes(t.size)})`).join(', ');
  findings.push({
    ruleId: RULE_PS007.id,
    severity: 'info',
    file: 'package.json',
    message: `Package summary: ${files.length} files, ${formatBytes(totalSize)} total. Top files: ${topSummary || 'none'}`
  });

  return { findings, topLargest };
}
