import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { PublishSetError, getPublishSet, resolveNpmCommand } from '../../src/publish-set.js';
import { createTempPackage } from '../helpers/fixture.js';

describe('publish-set and Windows npm resolution', () => {
  it('resolves npm_execpath when it is a JS file', () => {
    const res = resolveNpmCommand({
      env: { npm_execpath: '/usr/local/lib/node_modules/npm/bin/npm-cli.js' },
      execPath: '/usr/local/bin/node',
      platform: 'linux',
      existsSync: (p) => p === '/usr/local/lib/node_modules/npm/bin/npm-cli.js'
    });
    assert.equal(res.command, '/usr/local/bin/node');
    assert.deepEqual(res.baseArgs, ['/usr/local/lib/node_modules/npm/bin/npm-cli.js']);
  });

  it('resolves npm-cli.js next to Node on Windows without shell: true', () => {
    const nodeDir = path.join('/mock', 'nodejs');
    const winExe = path.join(nodeDir, 'node.exe');
    const winCli = path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js');
    const res = resolveNpmCommand({
      env: {},
      execPath: winExe,
      platform: 'win32',
      existsSync: (p) => p === winCli
    });
    assert.equal(res.command, winExe);
    assert.deepEqual(res.baseArgs, [winCli]);
  });

  it('throws PublishSetError on Windows when npm-cli.js cannot be located', () => {
    assert.throws(
      () =>
        resolveNpmCommand({
          env: {},
          execPath: 'C:\\node\\node.exe',
          platform: 'win32',
          existsSync: () => false
        }),
      PublishSetError
    );
  });

  it('falls back to bare npm on POSIX when npm-cli.js is not adjacent', () => {
    const res = resolveNpmCommand({
      env: {},
      execPath: '/usr/bin/node',
      platform: 'linux',
      existsSync: () => false
    });
    assert.equal(res.command, 'npm');
    assert.deepEqual(res.baseArgs, []);
  });

  it('throws helpful PublishSetError when npm is missing (ENOENT)', async () => {
    await assert.rejects(
      () =>
        getPublishSet(process.cwd(), {
          npmDeps: { env: {}, execPath: '/usr/bin/node', platform: 'linux', existsSync: () => false },
          execFileFn: async () => {
            const err = new Error('spawn npm ENOENT');
            /** @type {{ code?: string }} */ (err).code = 'ENOENT';
            throw err;
          }
        }),
      /npm executable not found/
    );
  });

  it('throws PublishSetError on malformed npm JSON output', async () => {
    await assert.rejects(
      () =>
        getPublishSet(process.cwd(), {
          execFileFn: async () => ({ stdout: 'not-json', stderr: '' })
        }),
      /Failed to parse JSON/
    );
  });

  it('does NOT run malicious prepack scripts by default', async () => {
    const marker = 'pwned-by-prepack.txt';
    const pkg = createTempPackage(
      { 'index.js': 'export const ok = 1;\n' },
      {
        scripts: {
          prepack: `node -e "require('node:fs').writeFileSync('${marker}', 'ran')"`
        }
      }
    );
    try {
      const res = await getPublishSet(fs.realpathSync(pkg.dir));
      assert.equal(fs.existsSync(path.join(pkg.dir, marker)), false);
      assert.ok(res.files.some((f) => f.relPosix === 'index.js'));
    } finally {
      pkg.cleanup();
    }
  });

  it('handles tricky filenames (spaces, quotes, semicolons, $(), leading dashes, unicode)', async () => {
    const trickyNames = [
      'file with spaces.js',
      'file;semi.js',
      'file$(cmd).js',
      '-leading-dash.js',
      'café-über.js'
    ];
    /** @type {Record<string, string>} */
    const files = {};
    for (const name of trickyNames) {
      files[name] = 'export const x = 1;\n';
    }
    const pkg = createTempPackage(files);
    try {
      const res = await getPublishSet(fs.realpathSync(pkg.dir));
      const got = new Set(res.files.map((f) => f.relPosix));
      for (const name of trickyNames) {
        assert.ok(got.has(name), `Expected ${name} in publish set`);
      }
    } finally {
      pkg.cleanup();
    }
  });
});
