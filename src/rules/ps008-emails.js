import { redactLineSnippet } from '../redact.js';

/** @type {import('./types.js').RuleMeta} */
export const RULE_PS008 = {
  id: 'PS008',
  name: 'email-address',
  defaultSeverity: 'info',
  description: 'Detects email addresses in shipped files unless allowlisted via package.json or configuration.'
};

const EMAIL_RE = /\b([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,24})\b/g;

const ALLOWLISTED_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'users.noreply.github.com',
  'localhost',
  'test.com'
]);

/**
 * Scan a line for email addresses not in the public/example allowlist.
 *
 * @param {string} line
 * @param {string} relPosix
 * @param {number} lineNum
 * @param {Set<string>} publicValues
 * @returns {import('./types.js').Finding[]}
 */
export function scanLinePS008(line, relPosix, lineNum, publicValues) {
  /** @type {import('./types.js').Finding[]} */
  const findings = [];
  EMAIL_RE.lastIndex = 0;

  let match;
  while ((match = EMAIL_RE.exec(line)) !== null) {
    const email = match[1] ?? match[0];
    const lower = email.toLowerCase();
    const atIdx = lower.indexOf('@');
    const domain = atIdx >= 0 ? lower.slice(atIdx + 1) : '';

    if (ALLOWLISTED_DOMAINS.has(domain) || publicValues.has(lower)) {
      continue;
    }

    // Skip npm scoped package names or CSS @ rules if they somehow match, though TLD check filters most.
    const start = match.index;
    const end = start + match[0].length;
    findings.push({
      ruleId: RULE_PS008.id,
      severity: RULE_PS008.defaultSeverity,
      file: relPosix,
      line: lineNum,
      column: start + 1,
      message: `Email address found in shipped file (${email})`,
      snippet: redactLineSnippet(line, start, end, email)
    });
  }

  return findings;
}
