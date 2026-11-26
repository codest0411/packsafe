import fs from 'node:fs';
import path from 'node:path';

/**
 * Error thrown when `.packsaferc.json` fails JSON parsing or schema validation.
 */
export class ConfigError extends Error {
  /**
   * @param {string} message
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, options) {
    super(message, options);
    this.name = 'ConfigError';
  }
}

const VALID_TOP_KEYS = new Set([
  'allow',
  'denyWords',
  'thresholds',
  'failOn',
  'allowPackageJsonIdentity'
]);

const VALID_FAIL_ON = new Set(['error', 'warn', 'info', 'none']);
const VALID_ALLOW_KEYS = new Set(['pattern', 'reason', 'rule']);
const VALID_THRESHOLD_KEYS = new Set(['maxTotalBytes', 'maxFileCount', 'maxFileBytes']);

/**
 * @typedef {{
 *   pattern: string,
 *   reason: string,
 *   rule?: string
 * }} AllowEntry
 *
 * @typedef {{
 *   allow: AllowEntry[],
 *   denyWords: string[],
 *   thresholds: {
 *     maxTotalBytes?: number,
 *     maxFileCount?: number,
 *     maxFileBytes?: number
 *   },
 *   failOn?: import('./rules/types.js').FailOnLevel,
 *   allowPackageJsonIdentity: boolean
 * }} PackSafeConfig
 */

/**
 * Safely check own property without prototype chain lookup.
 * @param {object} obj
 * @param {string} key
 * @returns {boolean}
 */
function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/**
 * Validate a parsed configuration object against the strict `.packsaferc.json` schema.
 *
 * @param {unknown} raw
 * @returns {PackSafeConfig}
 */
export function validateConfig(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError('Configuration must be a JSON object.');
  }

  const obj = /** @type {Record<string, unknown>} */ (raw);
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new ConfigError(`Forbidden key "${key}" in configuration.`);
    }
    if (!VALID_TOP_KEYS.has(key)) {
      throw new ConfigError(`Unknown configuration key "${key}".`);
    }
  }

  /** @type {AllowEntry[]} */
  const allow = [];
  if (hasOwn(obj, 'allow')) {
    if (!Array.isArray(obj.allow)) {
      throw new ConfigError('"allow" must be an array.');
    }
    for (let i = 0; i < obj.allow.length; i += 1) {
      const item = obj.allow[i];
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new ConfigError(`"allow[${i}]" must be an object.`);
      }
      const entry = /** @type {Record<string, unknown>} */ (item);
      for (const k of Object.keys(entry)) {
        if (!VALID_ALLOW_KEYS.has(k)) {
          throw new ConfigError(`Unknown key "${k}" in allow[${i}].`);
        }
      }
      if (typeof entry.pattern !== 'string' || entry.pattern.trim().length === 0) {
        throw new ConfigError(`"allow[${i}].pattern" must be a non-empty string.`);
      }
      if (typeof entry.reason !== 'string' || entry.reason.trim().length === 0) {
        throw new ConfigError(`"allow[${i}].reason" is required and must be a non-empty string.`);
      }
      if (hasOwn(entry, 'rule') && (typeof entry.rule !== 'string' || !/^PS\d{3}$/.test(entry.rule))) {
        throw new ConfigError(`"allow[${i}].rule" must be a valid rule ID like "PS001".`);
      }
      allow.push({
        pattern: entry.pattern,
        reason: entry.reason.trim(),
        rule: typeof entry.rule === 'string' ? entry.rule : undefined
      });
    }
  }

  /** @type {string[]} */
  const denyWords = [];
  if (hasOwn(obj, 'denyWords')) {
    if (!Array.isArray(obj.denyWords)) {
      throw new ConfigError('"denyWords" must be an array of strings.');
    }
    for (let i = 0; i < obj.denyWords.length; i += 1) {
      const w = obj.denyWords[i];
      if (typeof w !== 'string' || w.trim().length === 0) {
        throw new ConfigError(`"denyWords[${i}]" must be a non-empty string.`);
      }
      denyWords.push(w.trim());
    }
  }

  /** @type {PackSafeConfig['thresholds']} */
  const thresholds = {};
  if (hasOwn(obj, 'thresholds')) {
    if (!obj.thresholds || typeof obj.thresholds !== 'object' || Array.isArray(obj.thresholds)) {
      throw new ConfigError('"thresholds" must be an object.');
    }
    const tObj = /** @type {Record<string, unknown>} */ (obj.thresholds);
    for (const k of Object.keys(tObj)) {
      if (!VALID_THRESHOLD_KEYS.has(k)) {
        throw new ConfigError(`Unknown key "${k}" in thresholds.`);
      }
      const val = tObj[k];
      if (typeof val !== 'number' || !Number.isFinite(val) || val < 0) {
        throw new ConfigError(`"thresholds.${k}" must be a non-negative finite number.`);
      }
    }
    if (typeof tObj.maxTotalBytes === 'number') thresholds.maxTotalBytes = tObj.maxTotalBytes;
    if (typeof tObj.maxFileCount === 'number') thresholds.maxFileCount = tObj.maxFileCount;
    if (typeof tObj.maxFileBytes === 'number') thresholds.maxFileBytes = tObj.maxFileBytes;
  }

  /** @type {import('./rules/types.js').FailOnLevel | undefined} */
  let failOn;
  if (hasOwn(obj, 'failOn')) {
    if (typeof obj.failOn !== 'string' || !VALID_FAIL_ON.has(obj.failOn)) {
      throw new ConfigError('"failOn" must be one of: error, warn, info, none.');
    }
    failOn = /** @type {import('./rules/types.js').FailOnLevel} */ (obj.failOn);
  }

  let allowPackageJsonIdentity = true;
  if (hasOwn(obj, 'allowPackageJsonIdentity')) {
    if (typeof obj.allowPackageJsonIdentity !== 'boolean') {
      throw new ConfigError('"allowPackageJsonIdentity" must be a boolean.');
    }
    allowPackageJsonIdentity = obj.allowPackageJsonIdentity;
  }

  return {
    allow,
    denyWords,
    thresholds,
    failOn,
    allowPackageJsonIdentity
  };
}

/**
 * Load and validate `.packsaferc.json` from `packageRoot` or an explicit `configPath`.
 *
 * @param {string} packageRoot
 * @param {string} [explicitConfigPath]
 * @returns {PackSafeConfig}
 */
export function loadConfig(packageRoot, explicitConfigPath) {
  const targetPath = explicitConfigPath
    ? path.resolve(explicitConfigPath)
    : path.join(packageRoot, '.packsaferc.json');

  if (!fs.existsSync(targetPath)) {
    if (explicitConfigPath) {
      throw new ConfigError(`Config file not found: ${explicitConfigPath}`);
    }
    return {
      allow: [],
      denyWords: [],
      thresholds: {},
      failOn: undefined,
      allowPackageJsonIdentity: true
    };
  }

  let rawText;
  try {
    rawText = fs.readFileSync(targetPath, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new ConfigError(`Unable to read config file: ${msg}`, { cause: err });
  }

  let parsed;
  try {
    // Strip BOM if present
    const clean = rawText.charCodeAt(0) === 0xfeff ? rawText.slice(1) : rawText;
    parsed = JSON.parse(clean);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new ConfigError(`Invalid JSON in config file: ${msg}`, { cause: err });
  }

  return validateConfig(parsed);
}

/**
 * Parse an inline `packsafe-ignore-next-line` directive from a line of text.
 * Returns `null` if not present, `'ALL'` if no specific rule IDs are listed,
 * or a `Set<string>` of rule IDs (e.g. `PS001`).
 *
 * @param {string} line
 * @returns {'ALL' | Set<string> | null}
 */
export function parseIgnoreNextLine(line) {
  const idx = line.indexOf('packsafe-ignore-next-line');
  if (idx === -1) return null;
  const rest = line.slice(idx + 'packsafe-ignore-next-line'.length).trim();
  const ids = rest.match(/PS\d{3}/g);
  if (!ids || ids.length === 0) {
    return 'ALL';
  }
  return new Set(ids);
}

/**
 * Check whether a finding is suppressed by any `allow` entry in config.
 * Matches against `finding.file`, `finding.message`, or `finding.snippet`.
 *
 * @param {import('./rules/types.js').Finding} finding
 * @param {AllowEntry[]} allowEntries
 * @returns {boolean}
 */
export function isAllowedByConfig(finding, allowEntries) {
  for (const entry of allowEntries) {
    if (entry.rule && entry.rule !== finding.ruleId) {
      continue;
    }
    const needle = entry.pattern.toLowerCase();
    if (
      finding.file.toLowerCase().includes(needle) ||
      finding.message.toLowerCase().includes(needle) ||
      (finding.snippet && finding.snippet.toLowerCase().includes(needle))
    ) {
      return true;
    }
  }
  return false;
}
