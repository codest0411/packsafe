import { redactLineSnippet, redactSecret } from '../redact.js';
import { isPlaceholderSecret, SECRET_PATTERNS } from './secret-patterns.js';

/** @type {import('./types.js').RuleMeta} */
export const RULE_PS003 = {
  id: 'PS003',
  name: 'secrets-and-tokens',
  defaultSeverity: 'error',
  description: 'Detects private keys, npm/GitHub/AWS/Slack tokens, _authToken lines, and hardcoded secret assignments.'
};

/**
 * Scan a line for secrets and redact any matched secret value in the finding.
 *
 * @param {string} line
 * @param {string} relPosix
 * @param {number} lineNum
 * @returns {import('./types.js').Finding[]}
 */
export function scanLinePS003(line, relPosix, lineNum) {
  /** @type {import('./types.js').Finding[]} */
  const findings = [];

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(line)) !== null) {
      const secretVal =
        pattern.secretGroup !== undefined ? (match[pattern.secretGroup] ?? match[0]) : match[0];

      if (pattern.ignorePlaceholders && isPlaceholderSecret(secretVal)) {
        continue;
      }

      const start = match.index;
      const end = start + match[0].length;
      const redacted = redactSecret(secretVal);

      findings.push({
        ruleId: RULE_PS003.id,
        severity: RULE_PS003.defaultSeverity,
        file: relPosix,
        line: lineNum,
        column: start + 1,
        message: `${pattern.label} detected (${redacted})`,
        snippet: redactLineSnippet(line, start, end, redacted)
      });
    }
  }

  return findings;
}
