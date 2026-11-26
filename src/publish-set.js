import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { resolveSafePackagePath } from './paths.js';

const execFileAsync = promisify(execFile);

/**
 * Error thrown when npm cannot be invoked or returns an invalid publish list.
 */
export class PublishSetError extends Error {
  /**
   * @param {string} message
   * @param {{ cause?: unknown }} [options]
   */
  constructor(message, options) {
    super(message, options);
    this.name = 'PublishSetError';
  }
}

/**
 * Resolve how to invoke npm safely WITHOUT `shell: true`.
 * On Windows, spawning `npm.cmd` without a shell fails due to Node's 2024
 * security hardening, so we prefer `npm_execpath` or `npm-cli.js` executed
 * directly with `process.execPath` (`node`).
 *
 * @param {{
 *   env?: NodeJS.ProcessEnv,
 *   execPath?: string,
 *   platform?: NodeJS.Platform,
 *   existsSync?: (p: string) => boolean
 * }} [deps]
 * @returns {{ command: string, baseArgs: string[] }}
 */
export function resolveNpmCommand(deps = {}) {
  const env = deps.env ?? process.env;
  const execPath = deps.execPath ?? process.execPath;
  const platform = deps.platform ?? process.platform;
  const existsSync = deps.existsSync ?? fs.existsSync;

  const npmExecPath = env.npm_execpath;
  if (npmExecPath && /\.(?:m|c)?js$/i.test(npmExecPath) && existsSync(npmExecPath)) {
    return { command: execPath, baseArgs: [npmExecPath] };
  }

  const nodeDir = path.dirname(execPath);
  const candidates = [
    path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js')
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return { command: execPath, baseArgs: [candidate] };
    }
  }

  if (platform === 'win32') {
    throw new PublishSetError(
      'Unable to locate npm-cli.js next to Node.js and npm_execpath is not set. Ensure npm is installed with Node.js.'
    );
  }

  return { command: 'npm', baseArgs: [] };
}

/**
 * Determine the exact set of files `npm publish` would ship by running
 * `npm pack --dry-run --json --ignore-scripts`.
 *
 * @param {string} packageRoot - Resolved realpath of the package directory.
 * @param {{
 *   runScripts?: boolean,
 *   execFileFn?: typeof execFileAsync,
 *   npmDeps?: Parameters<typeof resolveNpmCommand>[0],
 *   timeoutMs?: number
 * }} [options]
 * @returns {Promise<{
 *   files: Array<{ relPosix: string, absPath: string, size: number }>,
 *   rejectedPaths: Array<{ path: string, reason: string }>,
 *   totalSize: number
 * }>}
 */
export async function getPublishSet(packageRoot, options = {}) {
  const runScripts = options.runScripts === true;
  const execFn = options.execFileFn ?? execFileAsync;
  const timeoutMs = options.timeoutMs ?? 30000;

  const { command, baseArgs } = resolveNpmCommand(options.npmDeps);
  const npmArgs = [...baseArgs, 'pack', '--dry-run', '--json'];
  if (!runScripts) {
    npmArgs.push('--ignore-scripts');
  }

  let stdout;
  try {
    const res = await execFn(command, npmArgs, {
      cwd: packageRoot,
      shell: false,
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true
    });
    stdout = typeof res.stdout === 'string' ? res.stdout : String(res.stdout ?? '');
  } catch (err) {
    const errObj = /** @type {{ code?: string, stderr?: string, message?: string }} */ (err);
    if (errObj && errObj.code === 'ENOENT') {
      throw new PublishSetError(
        'npm executable not found on PATH. packsafe requires npm to determine the exact publish set.',
        { cause: err }
      );
    }
    const detail = errObj?.stderr?.trim() || errObj?.message || String(err);
    throw new PublishSetError(`npm pack --dry-run failed: ${detail}`, { cause: err });
  }

  let parsed;
  try {
    // npm may print warnings before JSON if scripts ran; find the JSON array/object start.
    const trimmed = stdout.trim();
    const jsonStart = trimmed.search(/[[{]/);
    const jsonText = jsonStart >= 0 ? trimmed.slice(jsonStart) : trimmed;
    parsed = JSON.parse(jsonText);
  } catch (err) {
    throw new PublishSetError('Failed to parse JSON output from npm pack --dry-run --json.', {
      cause: err
    });
  }

  const packEntry = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!packEntry || !Array.isArray(packEntry.files)) {
    throw new PublishSetError('Unexpected npm pack --dry-run --json output: missing files array.');
  }

  /** @type {Array<{ relPosix: string, absPath: string, size: number }>} */
  const files = [];
  /** @type {Array<{ path: string, reason: string }>} */
  const rejectedPaths = [];
  let totalSize = 0;

  for (const entry of packEntry.files) {
    const rawPath = typeof entry?.path === 'string' ? entry.path : '';
    const size = typeof entry?.size === 'number' && Number.isFinite(entry.size) ? entry.size : 0;
    const resolved = resolveSafePackagePath(packageRoot, rawPath);
    if (!resolved.ok) {
      rejectedPaths.push({ path: rawPath, reason: resolved.reason });
      continue;
    }
    files.push({
      relPosix: resolved.relPosix,
      absPath: resolved.absPath,
      size
    });
    totalSize += size;
  }

  return { files, rejectedPaths, totalSize };
}
