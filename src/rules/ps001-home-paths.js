import { redactLineSnippet } from '../redact.js';

/** @type {import('./types.js').RuleMeta} */
export const RULE_PS001 = {
  id: 'PS001',
  name: 'absolute-home-path',
  defaultSeverity: 'error',
  description: 'Detects absolute local home directory paths (/home/<user>, /Users/<user>, C:\\Users\\<user>).'
};

/**
 * Generic placeholder usernames commonly used in docs/examples.
 */
export const GENERIC_HOME_PLACEHOLDERS = new Set([
  'yourname',
  'your-name',
  'your_name',
  'username',
  'user-name',
  'user_name',
  'user',
  'runner',
  'example',
  'someone',
  'alice',
  'bob',
  'john',
  'doe',
  'jane',
  'name',
  'myuser',
  'test',
  'admin',
  'root',
  'vscode',
  'codespace',
  'build',
  'ci',
  'developer',
  'dev',
  'owner',
  'default',
  'guest',
  'nobody',
  'ubuntu',
  'docker'
]);

/**
 * Linear-time regex matching POSIX, Windows, JSON-escaped Windows, and file:// home paths.
 * Capture group 1: POSIX /home/<name> or /Users/<name>
 * Capture group 2: Windows <drive>:\Users\<name> (single or double backslash, or forward slash)
 */
const HOME_PATH_RE =
  /(?:file:\/\/)?(?:\/(?:home|Users)\/([A-Za-z0-9._-]{1,64})|[A-Za-z]:(?:\\\\|\\|\/)Users(?:\\\\|\\|\/)([A-Za-z0-9._-]{1,64}))/g;

/**
 * Scan a single line for absolute home paths.
 *
 * @param {string} line
 * @param {string} relPosix
 * @param {number} lineNum
 * @returns {import('./types.js').Finding[]}
 */
export function scanLinePS001(line, relPosix, lineNum) {
  /** @type {import('./types.js').Finding[]} */
  const findings = [];
  HOME_PATH_RE.lastIndex = 0;

  let match;
  while ((match = HOME_PATH_RE.exec(line)) !== null) {
    const start = match.index;
    const prevChar = start > 0 ? line.charAt(start - 1) : '';
    // Avoid matching mid-identifier like "foo/home/bar" unless preceded by file:// or delimiter.
    if (/[A-Za-z0-9_]/.test(prevChar) && !match[0].startsWith('file://')) {
      continue;
    }

    const rawUser = (match[1] ?? match[2] ?? '').trim();
    const lowerUser = rawUser.toLowerCase();
    if (!rawUser || GENERIC_HOME_PLACEHOLDERS.has(lowerUser)) {
      continue;
    }

    const end = start + match[0].length;
    findings.push({
      ruleId: RULE_PS001.id,
      severity: RULE_PS001.defaultSeverity,
      file: relPosix,
      line: lineNum,
      column: start + 1,
      message: `Absolute home path detected (${match[0]})`,
      snippet: redactLineSnippet(line, start, end, match[0])
    });
  }

  return findings;
}
