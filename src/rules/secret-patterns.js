/**
 * Documented, linear-time secret detection patterns for PS003.
 * All regexes use bounded quantifiers and avoid nested repetition to prevent ReDoS.
 *
 * @typedef {{
 *   id: string,
 *   label: string,
 *   regex: RegExp,
 *   secretGroup?: number,
 *   ignorePlaceholders?: boolean
 * }} SecretPattern
 */

const PLACEHOLDER_TERMS = [
  'changeme',
  'your-api-key',
  'your_api_key',
  'your-secret',
  'your_secret',
  'your-token',
  'your_token',
  'example',
  'placeholder',
  'dummy',
  'replace_me',
  'replace-me',
  'insert_here',
  'insert-here',
  'redacted'
];

/**
 * Check whether a matched generic secret value is an obvious documentation placeholder.
 * @param {string} val
 * @returns {boolean}
 */
export function isPlaceholderSecret(val) {
  const lower = val.toLowerCase().trim();
  if (lower.startsWith('${') || (lower.startsWith('<') && lower.endsWith('>'))) {
    return true;
  }
  if (/^([x*.\-_])\1{5,}$/.test(lower)) {
    return true;
  }
  return PLACEHOLDER_TERMS.some((term) => lower.includes(term));
}

/** @type {SecretPattern[]} */
export const SECRET_PATTERNS = [
  {
    id: 'private-key-block',
    label: 'Private key block header',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
  },
  {
    id: 'npm-token',
    label: 'npm access token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g
  },
  {
    id: 'github-token',
    label: 'GitHub token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b/g
  },
  {
    id: 'github-fine-grained-pat',
    label: 'GitHub fine-grained personal access token',
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g
  },
  {
    id: 'aws-access-key-id',
    label: 'AWS Access Key ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,120}\b/g
  },
  {
    id: 'npmrc-auth-token',
    label: '.npmrc _authToken assignment',
    regex: /_authToken\s*=\s*([^\s"'#;]{8,256})/g,
    secretGroup: 1
  },
  {
    id: 'generic-secret-assignment',
    label: 'Hardcoded secret or password assignment',
    regex: /\b(?:password|passwd|secret|api_?key|access_?token|auth_?token|private_?key)\s*[:=]\s*["']([^"'\r\n]{12,128})["']/gi,
    secretGroup: 1,
    ignorePlaceholders: true
  }
];
