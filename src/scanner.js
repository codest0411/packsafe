import fs from 'node:fs';
import path from 'node:path';
import { isAllowedByConfig, loadConfig, parseIgnoreNextLine } from './config.js';
import { detectMachineIdentity } from './identity.js';
import { isBinaryBuffer, normalizeText } from './paths.js';
import { getPublishSet } from './publish-set.js';
import { scanLinePS001 } from './rules/ps001-home-paths.js';
import { scanLinePS002 } from './rules/ps002-identity.js';
import { scanLinePS003 } from './rules/ps003-secrets.js';
import { scanSourceMapPS004 } from './rules/ps004-sourcemaps.js';
import { scanFilePathPS005 } from './rules/ps005-risky-files.js';
import { scanLinePS006, scanPackageJsonPS006 } from './rules/ps006-internal-urls.js';
import { evaluateSizePS007 } from './rules/ps007-size-sanity.js';
import { scanLinePS008 } from './rules/ps008-emails.js';

export const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * Severity rank used for `--fail-on` threshold comparisons.
 * @type {Record<import('./rules/types.js').FailOnLevel, number>}
 */
export const SEVERITY_RANK = {
  none: 99,
  info: 1,
  warn: 2,
  error: 3
};

/**
 * Determine if any finding meets or exceeds the failOn threshold.
 *
 * @param {import('./rules/types.js').Finding[]} findings
 * @param {import('./rules/types.js').FailOnLevel} failOn
 * @returns {boolean}
 */
export function shouldFail(findings, failOn) {
  if (failOn === 'none') return false;
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
}

/**
 * Safely read and parse `package.json` from `packageRoot`.
 * @param {string} packageRoot
 * @returns {Record<string, unknown> | null}
 */
function readPackageJson(packageRoot) {
  const pkgPath = path.join(packageRoot, 'package.json');
  try {
    const raw = fs.readFileSync(pkgPath, 'utf8');
    const clean = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
    const parsed = JSON.parse(clean);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? /** @type {Record<string, unknown>} */ (parsed)
      : null;
  } catch {
    return null;
  }
}

/**
 * Scan an npm package's exact publish set and return structured findings + summary.
 *
 * @param {string} targetPath
 * @param {{
 *   configPath?: string,
 *   failOn?: import('./rules/types.js').FailOnLevel,
 *   runScripts?: boolean,
 *   identityProvider?: Parameters<typeof detectMachineIdentity>[1] extends infer T ? T extends { provider?: infer P } ? P : never : never,
 *   publishSetFn?: typeof getPublishSet,
 *   maxFileBytes?: number
 * }} [options]
 * @returns {Promise<{
 *   packageName: string,
 *   packageVersion: string,
 *   fileCount: number,
 *   totalSize: number,
 *   topLargest: Array<{ file: string, size: number }>,
 *   findings: import('./rules/types.js').Finding[],
 *   counts: { error: number, warn: number, info: number },
 *   failOn: import('./rules/types.js').FailOnLevel,
 *   failed: boolean
 * }>}
 */
export async function scanPackage(targetPath, options = {}) {
  const packageRoot = fs.realpathSync(path.resolve(targetPath || '.'));
  const config = loadConfig(packageRoot, options.configPath);
  const failOn = options.failOn ?? config.failOn ?? 'error';
  const maxScanBytes = options.maxFileBytes ?? MAX_SCAN_FILE_BYTES;

  const pkgJson = readPackageJson(packageRoot);
  const packageName = typeof pkgJson?.name === 'string' ? pkgJson.name : path.basename(packageRoot);
  const packageVersion = typeof pkgJson?.version === 'string' ? pkgJson.version : '0.0.0';

  const publishSetFn = options.publishSetFn ?? getPublishSet;
  const { files, rejectedPaths, totalSize } = await publishSetFn(packageRoot, {
    runScripts: options.runScripts
  });

  const { entries: identities, publicValues } = await detectMachineIdentity(packageRoot, {
    provider: options.identityProvider,
    pkgJson,
    allowPackageJsonIdentity: config.allowPackageJsonIdentity
  });

  /** @type {import('./rules/types.js').Finding[]} */
  const rawFindings = [];

  for (const rejected of rejectedPaths) {
    rawFindings.push({
      ruleId: 'PS005',
      severity: 'error',
      file: rejected.path || '.',
      message: `Unsafe path in publish list rejected: ${rejected.reason}`
    });
  }

  // Check package.json publishConfig.registry (PS006)
  for (const f of scanPackageJsonPS006(pkgJson)) {
    rawFindings.push(f);
  }

  /**
   * Scan a single text line with all line-based rules (PS001, PS002, PS003, PS006, PS008).
   * @param {string} line
   * @param {string} relFile
   * @param {number} lineNum
   * @returns {import('./rules/types.js').Finding[]}
   */
  const scanTextLine = (line, relFile, lineNum) => [
    ...scanLinePS001(line, relFile, lineNum),
    ...scanLinePS002(line, relFile, lineNum, {
      identities,
      denyWords: config.denyWords
    }),
    ...scanLinePS003(line, relFile, lineNum),
    ...scanLinePS006(line, relFile, lineNum),
    ...scanLinePS008(line, relFile, lineNum, publicValues)
  ];

  for (const fileEntry of files) {
    // PS005 runs on every file path (including binary files)
    for (const f of scanFilePathPS005(fileEntry.relPosix)) {
      rawFindings.push(f);
    }

    let stat;
    try {
      stat = fs.statSync(fileEntry.absPath);
    } catch {
      continue;
    }

    if (stat.size > maxScanBytes) {
      rawFindings.push({
        ruleId: 'PS007',
        severity: 'warn',
        file: fileEntry.relPosix,
        message: `File exceeds ${(maxScanBytes / (1024 * 1024)).toFixed(1)} MB scan limit and content scanning was skipped`
      });
      continue;
    }

    let buf;
    try {
      buf = fs.readFileSync(fileEntry.absPath);
    } catch {
      continue;
    }

    if (isBinaryBuffer(buf)) {
      continue;
    }

    const text = normalizeText(buf.toString('utf8'));

    if (fileEntry.relPosix.endsWith('.map')) {
      for (const f of scanSourceMapPS004(fileEntry.relPosix, text, scanTextLine)) {
        rawFindings.push(f);
      }
      continue;
    }

    const lines = text.split('\n');
    /** @type {'ALL' | Set<string> | null} */
    let ignoreNext = null;

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? '';
      const lineFindings = scanTextLine(line, fileEntry.relPosix, i + 1);

      if (ignoreNext) {
        for (const f of lineFindings) {
          if (ignoreNext === 'ALL' || ignoreNext.has(f.ruleId)) {
            continue;
          }
          rawFindings.push(f);
        }
      } else {
        for (const f of lineFindings) {
          rawFindings.push(f);
        }
      }

      ignoreNext = parseIgnoreNextLine(line);
    }
  }

  const sizeEval = evaluateSizePS007(files, totalSize, config.thresholds);
  for (const f of sizeEval.findings) {
    rawFindings.push(f);
  }

  const findings = rawFindings.filter((f) => !isAllowedByConfig(f, config.allow));

  const counts = { error: 0, warn: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity] += 1;
  }

  return {
    packageName,
    packageVersion,
    fileCount: files.length,
    totalSize,
    topLargest: sizeEval.topLargest,
    findings,
    counts,
    failOn,
    failed: shouldFail(findings, failOn)
  };
}
