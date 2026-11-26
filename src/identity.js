import { execFile } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Common generic usernames/hostnames that must NOT be flagged by PS002
 * because they cause noisy false positives in documentation and CI.
 */
export const COMMON_IDENTITY_DENYLIST = new Set([
  'root',
  'admin',
  'administrator',
  'user',
  'users',
  'test',
  'guest',
  'node',
  'ubuntu',
  'runner',
  'vscode',
  'codespace',
  'docker',
  'builder',
  'default',
  'owner',
  'developer',
  'local',
  'localhost',
  'unknown',
  'system',
  'nobody',
  'service',
  'linux',
  'macos',
  'windows',
  'win32',
  'darwin'
]);

/**
 * @typedef {'username' | 'homedir' | 'hostname' | 'gitName' | 'gitEmail'} IdentityKind
 */

/**
 * @typedef {{ value: string, kind: IdentityKind }} IdentityEntry
 */

/**
 * @typedef {{
 *   username?: string,
 *   homedir?: string,
 *   hostname?: string,
 *   gitName?: string,
 *   gitEmail?: string
 * }} RawIdentity
 */

/**
 * Extract intentionally public identity strings from package.json
 * (`author`, `contributors`, `maintainers`, `repository`, `bugs`, `homepage`).
 *
 * @param {Record<string, unknown> | null | undefined} pkgJson
 * @returns {Set<string>} Lowercase set of public strings and tokens
 */
export function extractPublicPackageIdentity(pkgJson) {
  /** @type {Set<string>} */
  const publicSet = new Set();
  if (!pkgJson || typeof pkgJson !== 'object') {
    return publicSet;
  }

  /** @param {unknown} val */
  const addString = (val) => {
    if (typeof val !== 'string') return;
    const trimmed = val.trim();
    if (trimmed.length >= 4) {
      publicSet.add(trimmed.toLowerCase());
    }
    // Extract email inside "Name <email@example.com>"
    const angleMatch = /<([^>\s]+@[^>\s]+)>/.exec(trimmed);
    if (angleMatch && angleMatch[1]) {
      publicSet.add(angleMatch[1].toLowerCase());
    }
    // Extract name before "<email>"
    const nameBeforeAngle = /^([^<(]+)[<(]/.exec(trimmed);
    if (nameBeforeAngle && nameBeforeAngle[1]) {
      const namePart = nameBeforeAngle[1].trim();
      if (namePart.length >= 4) {
        publicSet.add(namePart.toLowerCase());
      }
    }
  };

  /** @param {unknown} person */
  const addPerson = (person) => {
    if (typeof person === 'string') {
      addString(person);
    } else if (person && typeof person === 'object') {
      const obj = /** @type {Record<string, unknown>} */ (person);
      addString(obj.name);
      addString(obj.email);
      addString(obj.url);
    }
  };

  addPerson(pkgJson.author);
  if (Array.isArray(pkgJson.contributors)) {
    for (const c of pkgJson.contributors) addPerson(c);
  }
  if (Array.isArray(pkgJson.maintainers)) {
    for (const m of pkgJson.maintainers) addPerson(m);
  }
  addPerson(pkgJson.repository);
  addPerson(pkgJson.bugs);
  addString(pkgJson.homepage);

  return publicSet;
}

/**
 * Default machine identity provider using Node's `os` module and `git config`.
 * Failures in `os.userInfo()` or `git` are tolerated gracefully.
 *
 * @param {string} packageRoot
 * @returns {Promise<RawIdentity>}
 */
export async function defaultIdentityProvider(packageRoot) {
  /** @type {RawIdentity} */
  const raw = {};

  try {
    raw.username = os.userInfo().username;
  } catch {
    raw.username = process.env.USER || process.env.USERNAME || '';
  }

  try {
    raw.homedir = os.homedir();
  } catch {
    raw.homedir = '';
  }

  try {
    raw.hostname = os.hostname();
  } catch {
    raw.hostname = '';
  }

  /** @param {string} key */
  const readGitConfig = async (key) => {
    try {
      const { stdout } = await execFileAsync('git', ['config', '--get', key], {
        cwd: packageRoot,
        shell: false,
        timeout: 3000,
        maxBuffer: 64 * 1024,
        windowsHide: true
      });
      return stdout.trim();
    } catch {
      return '';
    }
  };

  const [gitName, gitEmail] = await Promise.all([
    readGitConfig('user.name'),
    readGitConfig('user.email')
  ]);
  raw.gitName = gitName;
  raw.gitEmail = gitEmail;

  return raw;
}

/**
 * Build the filtered machine identity list for PS002.
 *
 * @param {string} packageRoot
 * @param {{
 *   provider?: (root: string) => Promise<RawIdentity> | RawIdentity,
 *   pkgJson?: Record<string, unknown> | null,
 *   allowPackageJsonIdentity?: boolean
 * }} [options]
 * @returns {Promise<{ entries: IdentityEntry[], publicValues: Set<string> }>}
 */
export async function detectMachineIdentity(packageRoot, options = {}) {
  const provider = options.provider ?? defaultIdentityProvider;
  const raw = await provider(packageRoot);
  const allowPublic = options.allowPackageJsonIdentity !== false;
  const publicValues = extractPublicPackageIdentity(options.pkgJson);

  /** @type {Map<string, IdentityEntry>} */
  const deduped = new Map();

  /**
   * @param {string | undefined} value
   * @param {IdentityKind} kind
   */
  const addCandidate = (value, kind) => {
    if (typeof value !== 'string') return;
    const trimmed = value.trim();
    if (trimmed.length < 4) return;
    const lower = trimmed.toLowerCase();
    if (COMMON_IDENTITY_DENYLIST.has(lower)) return;
    if (allowPublic && publicValues.has(lower)) return;
    if (!deduped.has(lower)) {
      deduped.set(lower, { value: trimmed, kind });
    }
  };

  addCandidate(raw.username, 'username');

  if (raw.homedir) {
    const trimmedHome = raw.homedir.trim();
    if (trimmedHome.length >= 4 && trimmedHome !== '/' && !/^[A-Za-z]:\\?$/.test(trimmedHome)) {
      addCandidate(trimmedHome, 'homedir');
      const homeBase = path.basename(trimmedHome);
      addCandidate(homeBase, 'username');
    }
  }

  if (raw.hostname) {
    addCandidate(raw.hostname, 'hostname');
    const shortHost = raw.hostname.split('.')[0];
    if (shortHost && shortHost !== raw.hostname) {
      addCandidate(shortHost, 'hostname');
    }
  }

  addCandidate(raw.gitName, 'gitName');
  addCandidate(raw.gitEmail, 'gitEmail');

  return {
    entries: Array.from(deduped.values()),
    publicValues
  };
}
