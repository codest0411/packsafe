import { redactLineSnippet } from '../redact.js';

/** @type {import('./types.js').RuleMeta} */
export const RULE_PS002 = {
  id: 'PS002',
  name: 'machine-identity',
  defaultSeverity: 'error',
  description: 'Detects current machine identity (OS username, hostname, git user.name/email) or configured denyWords.'
};

/**
 * @param {string} ch
 * @returns {boolean}
 */
function isWordChar(ch) {
  return ch.length === 1 && /[A-Za-z0-9_]/.test(ch);
}

/**
 * Scan a line for exact, case-insensitive, boundary-aware matches of machine identity
 * values and configured denyWords using linear-time indexOf scanning.
 *
 * @param {string} line
 * @param {string} relPosix
 * @param {number} lineNum
 * @param {{
 *   identities: Array<{ value: string, kind: string }>,
 *   denyWords?: string[]
 * }} context
 * @returns {import('./types.js').Finding[]}
 */
export function scanLinePS002(line, relPosix, lineNum, context) {
  /** @type {import('./types.js').Finding[]} */
  const findings = [];
  const lineLower = line.toLowerCase();

  /** @type {Array<{ needle: string, lower: string, label: string }>} */
  const targets = [];
  for (const id of context.identities) {
    targets.push({
      needle: id.value,
      lower: id.value.toLowerCase(),
      label: `machine ${id.kind}`
    });
  }
  if (context.denyWords) {
    for (const word of context.denyWords) {
      if (word.length > 0) {
        targets.push({
          needle: word,
          lower: word.toLowerCase(),
          label: 'configured denyWord'
        });
      }
    }
  }

  for (const target of targets) {
    if (!target.lower) continue;
    let fromIndex = 0;
    while (fromIndex <= lineLower.length - target.lower.length) {
      const idx = lineLower.indexOf(target.lower, fromIndex);
      if (idx === -1) break;

      const before = idx > 0 ? line.charAt(idx - 1) : '';
      const afterIdx = idx + target.lower.length;
      const after = afterIdx < line.length ? line.charAt(afterIdx) : '';

      if (!isWordChar(before) && !isWordChar(after)) {
        findings.push({
          ruleId: RULE_PS002.id,
          severity: RULE_PS002.defaultSeverity,
          file: relPosix,
          line: lineNum,
          column: idx + 1,
          message: `Matched ${target.label} ("${target.needle}")`,
          snippet: redactLineSnippet(line, idx, afterIdx, line.slice(idx, afterIdx))
        });
      }
      fromIndex = idx + Math.max(1, target.lower.length);
    }
  }

  return findings;
}
