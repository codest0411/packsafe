import assert from 'node:assert/strict';
import fs from 'node:fs';
import { describe, it } from 'node:test';
import { runCli } from '../../src/cli.js';
import { ConfigError, loadConfig, parseIgnoreNextLine, validateConfig } from '../../src/config.js';
import { formatGithub } from '../../src/reporters/github.js';
import { formatHuman } from '../../src/reporters/human.js';
import { formatJson } from '../../src/reporters/json.js';
import { formatSarif } from '../../src/reporters/sarif.js';
import { scanPackage } from '../../src/scanner.js';
import { createTempPackage } from '../helpers/fixture.js';

function makeStream(isTTY = false) {
  let buf = '';
  return {
    isTTY,
    write: (/** @type {string} */ chunk) => {
      buf += chunk;
      return true;
    },
    read: () => buf
  };
}

describe('config, reporters, scanner, and CLI', () => {
  it('validates .packsaferc.json strictly and rejects invalid schemas', () => {
    assert.throws(() => validateConfig([]), ConfigError);
    assert.throws(() => validateConfig({ unknownKey: 1 }), ConfigError);
    assert.throws(() => validateConfig(JSON.parse('{"__proto__": {}}')), ConfigError);
    assert.throws(() => validateConfig({ allow: [{ pattern: 'x' }] }), /reason.*required/);
    assert.throws(() => validateConfig({ allow: [{ pattern: 'x', reason: 'ok', rule: 'BAD' }] }), ConfigError);
    assert.throws(() => validateConfig({ denyWords: [''] }), ConfigError);
    assert.throws(() => validateConfig({ failOn: 'critical' }), ConfigError);
    assert.throws(() => validateConfig({ thresholds: { maxTotalBytes: -5 } }), ConfigError);
    assert.throws(() => validateConfig({ allowPackageJsonIdentity: 'yes' }), ConfigError);

    const valid = validateConfig({
      allow: [{ pattern: 'example', reason: 'Intentional fixture', rule: 'PS001' }],
      denyWords: ['SecretCodename'],
      thresholds: { maxTotalBytes: 1024 },
      failOn: 'warn',
      allowPackageJsonIdentity: false
    });
    assert.equal(valid.failOn, 'warn');
    assert.equal(valid.allow.length, 1);
  });

  it('parses packsafe-ignore-next-line directives', () => {
    assert.equal(parseIgnoreNextLine('const x = 1;'), null);
    assert.equal(parseIgnoreNextLine('// packsafe-ignore-next-line'), 'ALL');
    const specific = parseIgnoreNextLine('// packsafe-ignore-next-line PS001, PS006');
    if (!(specific instanceof Set)) {
      throw new Error('Expected Set');
    }
    assert.ok(specific.has('PS001'));
    assert.ok(specific.has('PS006'));
  });

  it('scans package with CRLF, BOM, binary skipping, size skipping, and inline ignore', async () => {
    const pkg = createTempPackage({
      'index.js': Buffer.from(
        '\uFEFF// packsafe-ignore-next-line PS001\r\nconst ignored = "/home/alexsmith/ok";\r\nconst leaked = "/home/alexsmith/bad";\r\n',
        'utf8'
      ),
      'logo.bin': Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x2f, 0x68, 0x6f, 0x6d, 0x65]),
      'big.txt': 'x'.repeat(2048)
    });

    try {
      const result = await scanPackage(fs.realpathSync(pkg.dir), {
        maxFileBytes: 1024,
        identityProvider: async () => ({ username: 'alexsmith' })
      });
      assert.equal(result.failed, true);
      // Ignored line not reported, leaked line reported
      assert.equal(result.findings.filter((f) => f.ruleId === 'PS001').length, 1);
      // Oversized file warned
      assert.ok(result.findings.some((f) => f.file === 'big.txt' && f.severity === 'warn'));
      // Binary file was NOT scanned for text rules
      assert.equal(result.findings.some((f) => f.file === 'logo.bin'), false);
    } finally {
      pkg.cleanup();
    }
  });

  it('formats human (color & no-color), json, github, and sarif outputs', async () => {
    const pkg = createTempPackage({
      'index.js': 'const p = "/home/alexsmith/app";\n'
    });
    try {
      const result = await scanPackage(fs.realpathSync(pkg.dir), {
        identityProvider: async () => ({ username: 'nobody_special' })
      });

      const humanPlain = formatHuman(result, { useColor: false });
      assert.equal(humanPlain.includes('\x1b['), false);
      assert.ok(humanPlain.includes('PS001'));

      const humanColor = formatHuman(result, { useColor: true });
      assert.equal(humanColor.includes('\x1b['), true);

      const jsonOut = JSON.parse(formatJson(result));
      assert.equal(jsonOut.failed, true);

      const ghOut = formatGithub(result);
      assert.ok(ghOut.startsWith('::error file=index.js'));

      const sarifOut = JSON.parse(formatSarif(result));
      assert.equal(sarifOut.version, '2.1.0');
      assert.ok(sarifOut.runs[0].results.length >= 1);
    } finally {
      pkg.cleanup();
    }
  });

  it('CLI handles --help, --version, invalid flags, missing path, --run-scripts warning, and exit codes 0/1/2', async () => {
    const out = makeStream();
    const err = makeStream();
    assert.equal(await runCli(['--help'], { stdout: out, stderr: err }), 0);
    assert.ok(out.read().includes('Usage:'));

    const outV = makeStream();
    assert.equal(await runCli(['--version'], { stdout: outV, stderr: err }), 0);
    assert.match(outV.read().trim(), /^\d+\.\d+\.\d+/);

    assert.equal(await runCli(['--unknown-flag'], { stdout: out, stderr: err }), 2);
    assert.equal(await runCli(['--format', 'xml'], { stdout: out, stderr: err }), 2);
    assert.equal(await runCli(['--fail-on', 'bogus'], { stdout: out, stderr: err }), 2);
    assert.equal(await runCli(['a', 'b'], { stdout: out, stderr: err }), 2);
    assert.equal(await runCli(['./does-not-exist-xyz'], { stdout: out, stderr: err }), 2);

    const pkg = createTempPackage({ 'index.js': 'export const clean = true;\n' });
    try {
      const errWarn = makeStream();
      const outClean = makeStream();
      const code = await runCli([pkg.dir, '--run-scripts', '--fail-on', 'none'], {
        stdout: outClean,
        stderr: errWarn,
        scanFn: async () => ({
          packageName: 'x',
          packageVersion: '1.0.0',
          fileCount: 1,
          totalSize: 10,
          topLargest: [],
          findings: [],
          counts: { error: 0, warn: 0, info: 0 },
          failOn: 'none',
          failed: false
        })
      });
      assert.equal(code, 0);
      assert.ok(errWarn.read().includes('WARNING: --run-scripts is enabled'));
    } finally {
      pkg.cleanup();
    }
  });

  it('throws ConfigError when explicit --config path is missing', () => {
    assert.throws(() => loadConfig(process.cwd(), './nonexistent-packsaferc.json'), ConfigError);
  });
});
