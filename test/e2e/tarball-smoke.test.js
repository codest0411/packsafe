import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';
import { resolveNpmCommand } from '../../src/publish-set.js';
import { createTempPackage } from '../helpers/fixture.js';

const execFileAsync = promisify(execFile);

describe('e2e packed tarball smoke test', () => {
  it('packs packsafe, installs into a clean folder, and detects PS001-PS008 with relative paths and redacted secrets', async () => {
    const repoRoot = path.resolve(import.meta.dirname, '..', '..');
    const packDir = fs.mkdtempSync(path.join(os.tmpdir(), 'packsafe-pack-'));
    const installDir = fs.mkdtempSync(path.join(os.tmpdir(), 'packsafe-install-'));

    const fakeNpmToken = 'npm_' + 'Z'.repeat(36);
    const targetPkg = createTempPackage(
      {
        'index.js': [
          'export const home = "/Users/leakeddevname/project";',
          `export const tok = "${fakeNpmToken}";`,
          'export const api = "https://vault.corp.internal/secret";',
          'export const mail = "leaked.person@privatecorp.org";'
        ].join('\n'),
        'dist/app.js.map': JSON.stringify({
          version: 3,
          sources: ['C:\\Users\\leakeddevname\\project\\index.ts'],
          sourcesContent: ['export const x = 1;']
        }),
        '.env': 'SECRET=123456789012\n'
      },
      {
        files: ['index.js', 'dist/app.js.map', '.env']
      }
    );

    try {
      const { command, baseArgs } = resolveNpmCommand();
      const packRes = await execFileAsync(
        command,
        [...baseArgs, 'pack', '--ignore-scripts', '--pack-destination', packDir],
        { cwd: repoRoot, shell: false, windowsHide: true, timeout: 30000 }
      );
      const tgzName = packRes.stdout.trim().split(/\r?\n/).pop()?.trim();
      assert.ok(tgzName && tgzName.endsWith('.tgz'), `Expected .tgz filename, got: ${tgzName}`);
      const tgzPath = path.join(packDir, tgzName);

      fs.writeFileSync(
        path.join(installDir, 'package.json'),
        JSON.stringify({ name: 'smoke-consumer', version: '1.0.0', private: true })
      );

      await execFileAsync(
        command,
        [...baseArgs, 'install', '--ignore-scripts', '--no-audit', '--no-fund', tgzPath],
        { cwd: installDir, shell: false, windowsHide: true, timeout: 60000 }
      );

      const installedBin = path.join(installDir, 'node_modules', 'packsafe', 'bin', 'packsafe.js');
      assert.equal(fs.existsSync(installedBin), true);

      let cliStdout = '';
      let exitCode = 0;
      try {
        const res = await execFileAsync(process.execPath, [installedBin, targetPkg.dir, '--format', 'json'], {
          cwd: installDir,
          shell: false,
          windowsHide: true,
          timeout: 30000
        });
        cliStdout = res.stdout;
      } catch (err) {
        const errObj = /** @type {{ code?: number, stdout?: string }} */ (err);
        exitCode = errObj.code ?? 2;
        cliStdout = errObj.stdout ?? '';
      }

      assert.equal(exitCode, 1);
      assert.equal(cliStdout.includes(fakeNpmToken), false, 'Output must never contain unredacted secret');
      assert.equal(cliStdout.includes(targetPkg.dir), false, 'Output must never contain absolute temp dir path');

      const report = JSON.parse(cliStdout);
      const ruleIds = new Set(report.findings.map((/** @type {{ ruleId: string }} */ f) => f.ruleId));
      for (const expected of ['PS001', 'PS003', 'PS004', 'PS005', 'PS006', 'PS007', 'PS008']) {
        assert.ok(ruleIds.has(expected), `Expected finding for ${expected}`);
      }
    } finally {
      fs.rmSync(packDir, { recursive: true, force: true });
      fs.rmSync(installDir, { recursive: true, force: true });
      targetPkg.cleanup();
    }
  });
});
