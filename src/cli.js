import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { ConfigError } from './config.js';
import { PublishSetError } from './publish-set.js';
import { formatGithub } from './reporters/github.js';
import { formatHuman } from './reporters/human.js';
import { formatJson } from './reporters/json.js';
import { formatSarif } from './reporters/sarif.js';
import { scanPackage } from './scanner.js';

const require = createRequire(import.meta.url);
const pkgMeta = /** @type {{ version: string }} */ (require('../package.json'));

const VALID_FORMATS = new Set(['human', 'json', 'github', 'sarif']);
const VALID_FAIL_ON = new Set(['error', 'warn', 'info', 'none']);

const HELP_TEXT = `packsafe v${pkgMeta.version} — Pre-publish security & privacy gate for npm packages

Usage:
  packsafe [path] [options]

Options:
  --format <fmt>      Output format: human (default), json, github, sarif
  --fail-on <level>   Minimum severity to exit 1: error (default), warn, info, none
  --config <file>     Path to .packsaferc.json config file
  --run-scripts       Allow npm pack lifecycle scripts (OFF by default; unsafe on untrusted packages)
  --no-color          Disable ANSI colors in human output
  -h, --help          Show this help message
  -v, --version       Show version number

Exit codes:
  0  Clean (no findings at or above --fail-on)
  1  Findings at or above --fail-on
  2  Usage, configuration, or runtime error
`;

/**
 * Execute the packsafe CLI with injectable I/O streams for testability.
 *
 * @param {string[]} argv
 * @param {{
 *   stdout?: { write: (s: string) => unknown, isTTY?: boolean },
 *   stderr?: { write: (s: string) => unknown },
 *   env?: NodeJS.ProcessEnv,
 *   scanFn?: typeof scanPackage
 * }} [io]
 * @returns {Promise<number>} Exit code (0, 1, or 2)
 */
export async function runCli(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const env = io.env ?? process.env;
  const scanFn = io.scanFn ?? scanPackage;

  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        format: { type: 'string', default: 'human' },
        'fail-on': { type: 'string' },
        config: { type: 'string' },
        'run-scripts': { type: 'boolean', default: false },
        'no-color': { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false }
      }
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    stderr.write(`packsafe: ${msg}\nRun "packsafe --help" for usage.\n`);
    return 2;
  }

  const { values, positionals } = parsed;

  if (values.help) {
    stdout.write(HELP_TEXT);
    return 0;
  }

  if (values.version) {
    stdout.write(`${pkgMeta.version}\n`);
    return 0;
  }

  if (positionals.length > 1) {
    stderr.write('packsafe: Too many positional arguments. Expected at most one [path].\n');
    return 2;
  }

  const format = values.format ?? 'human';
  if (!VALID_FORMATS.has(format)) {
    stderr.write(`packsafe: Invalid --format "${format}". Expected: human, json, github, sarif.\n`);
    return 2;
  }

  const failOnArg = values['fail-on'];
  if (failOnArg !== undefined && !VALID_FAIL_ON.has(failOnArg)) {
    stderr.write(`packsafe: Invalid --fail-on "${failOnArg}". Expected: error, warn, info, none.\n`);
    return 2;
  }

  const targetPath = positionals[0] ?? '.';
  const resolvedTarget = path.resolve(targetPath);
  if (!fs.existsSync(resolvedTarget)) {
    stderr.write(`packsafe: Target path does not exist: ${targetPath}\n`);
    return 2;
  }

  const runScripts = values['run-scripts'] === true;
  if (runScripts) {
    stderr.write(
      'WARNING: --run-scripts is enabled. npm lifecycle scripts will execute during `npm pack --dry-run`.\n'
    );
  }

  let result;
  try {
    result = await scanFn(resolvedTarget, {
      configPath: values.config,
      failOn: /** @type {import('./rules/types.js').FailOnLevel | undefined} */ (failOnArg),
      runScripts
    });
  } catch (err) {
    if (err instanceof ConfigError || err instanceof PublishSetError) {
      stderr.write(`packsafe: ${err.message}\n`);
      return 2;
    }
    const msg = err instanceof Error ? err.message : String(err);
    stderr.write(`packsafe: Unexpected error: ${msg}\n`);
    return 2;
  }

  const useColor = Boolean(stdout.isTTY) && !env.NO_COLOR && !values['no-color'];

  if (format === 'json') {
    stdout.write(formatJson(result));
  } else if (format === 'github') {
    stdout.write(formatGithub(result));
  } else if (format === 'sarif') {
    stdout.write(formatSarif(result, pkgMeta.version));
  } else {
    stdout.write(formatHuman(result, { useColor }));
  }

  return result.failed ? 1 : 0;
}
