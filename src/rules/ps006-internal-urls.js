import { redactLineSnippet } from '../redact.js';

/** @type {import('./types.js').RuleMeta} */
export const RULE_PS006 = {
  id: 'PS006',
  name: 'internal-urls',
  defaultSeverity: 'warn',
  description: 'Detects private IPv4 ranges, internal hostnames, localhost URLs, non-default publishConfig.registry, and non-npmjs lockfile resolved hosts.'
};

const PRIVATE_IP_RE =
  /(?:^|[^0-9.])((?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})(?=$|[^0-9.])/g;

const INTERNAL_HOST_URL_RE =
  /https?:\/\/[A-Za-z0-9.-]+\.(?:internal|corp|local|lan|intranet)(?:[:/][^\s"'`<>)]*)?/gi;

const LOCALHOST_URL_RE =
  /https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d{1,5})?(?:\/[^\s"'`<>)]*)?/gi;

const RESOLVED_URL_RE = /resolved\s*[:=]\s*["']?(https?:\/\/[^"'\s]+)["']?/gi;

const TEST_PATH_RE = /(?:^|\/)(?:test|tests|__tests__|spec|__mocks__|fixtures?)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/i;

const DEFAULT_NPM_REGISTRY = 'https://registry.npmjs.org';

/**
 * Scan a line of text for internal URLs, private IPs, and localhost references.
 *
 * @param {string} line
 * @param {string} relPosix
 * @param {number} lineNum
 * @returns {import('./types.js').Finding[]}
 */
export function scanLinePS006(line, relPosix, lineNum) {
  /** @type {import('./types.js').Finding[]} */
  const findings = [];

  PRIVATE_IP_RE.lastIndex = 0;
  let match;
  while ((match = PRIVATE_IP_RE.exec(line)) !== null) {
    const ip = match[1] ?? match[0];
    const start = match.index + match[0].indexOf(ip);
    const end = start + ip.length;
    findings.push({
      ruleId: RULE_PS006.id,
      severity: 'warn',
      file: relPosix,
      line: lineNum,
      column: start + 1,
      message: `Private IPv4 address detected (${ip})`,
      snippet: redactLineSnippet(line, start, end, ip)
    });
  }

  INTERNAL_HOST_URL_RE.lastIndex = 0;
  while ((match = INTERNAL_HOST_URL_RE.exec(line)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    findings.push({
      ruleId: RULE_PS006.id,
      severity: 'warn',
      file: relPosix,
      line: lineNum,
      column: start + 1,
      message: `Internal hostname URL detected (${match[0]})`,
      snippet: redactLineSnippet(line, start, end, match[0])
    });
  }

  if (!TEST_PATH_RE.test(relPosix)) {
    LOCALHOST_URL_RE.lastIndex = 0;
    while ((match = LOCALHOST_URL_RE.exec(line)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      findings.push({
        ruleId: RULE_PS006.id,
        severity: 'info',
        file: relPosix,
        line: lineNum,
        column: start + 1,
        message: `Localhost URL in shipped non-test file (${match[0]})`,
        snippet: redactLineSnippet(line, start, end, match[0])
      });
    }
  }

  const baseName = relPosix.split('/').pop() ?? '';
  if (
    baseName === 'package-lock.json' ||
    baseName === 'npm-shrinkwrap.json' ||
    baseName === 'yarn.lock' ||
    baseName === 'pnpm-lock.yaml'
  ) {
    RESOLVED_URL_RE.lastIndex = 0;
    while ((match = RESOLVED_URL_RE.exec(line)) !== null) {
      const urlStr = match[1] ?? '';
      try {
        const parsed = new URL(urlStr);
        if (parsed.hostname !== 'registry.npmjs.org' && parsed.hostname !== 'registry.yarnpkg.com') {
          findings.push({
            ruleId: RULE_PS006.id,
            severity: 'warn',
            file: relPosix,
            line: lineNum,
            message: `Lockfile resolved URL points to non-public registry host (${parsed.hostname})`
          });
        }
      } catch {
        // Ignore malformed URL in lockfile line
      }
    }
  }

  return findings;
}

/**
 * Inspect package.json `publishConfig.registry` for non-default registries.
 *
 * @param {Record<string, unknown> | null | undefined} pkgJson
 * @returns {import('./types.js').Finding[]}
 */
export function scanPackageJsonPS006(pkgJson) {
  if (!pkgJson || typeof pkgJson !== 'object') return [];
  const publishConfig = pkgJson.publishConfig;
  if (!publishConfig || typeof publishConfig !== 'object' || Array.isArray(publishConfig)) {
    return [];
  }
  const registry = /** @type {Record<string, unknown>} */ (publishConfig).registry;
  if (typeof registry !== 'string' || registry.trim().length === 0) {
    return [];
  }

  const normalized = registry.trim().replace(/\/+$/, '');
  if (normalized !== DEFAULT_NPM_REGISTRY) {
    return [
      {
        ruleId: RULE_PS006.id,
        severity: 'warn',
        file: 'package.json',
        message: `Non-default publishConfig.registry configured (${normalized})`
      }
    ];
  }
  return [];
}
