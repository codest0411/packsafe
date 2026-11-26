import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Ensure npm cache stays inside os.tmpdir() during sandboxed test runs
const testCache = path.join(os.tmpdir(), 'packsafe-test-npm-cache');
fs.mkdirSync(testCache, { recursive: true });
process.env.npm_config_cache = testCache;
process.env.NPM_CONFIG_CACHE = testCache;

/**
 * Create a temporary npm package directory in `os.tmpdir()`.
 *
 * @param {Record<string, string | Buffer>} files - Map of relative paths to contents.
 * @param {Record<string, unknown>} [pkgOverrides]
 * @returns {{ dir: string, cleanup: () => void }}
 */
export function createTempPackage(files, pkgOverrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'packsafe-test-'));
  const defaultPkg = {
    name: 'packsafe-fixture',
    version: '1.0.0',
    license: 'MIT',
    ...pkgOverrides
  };

  if (!Object.prototype.hasOwnProperty.call(files, 'package.json')) {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(defaultPkg, null, 2), 'utf8');
  }

  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }

  return {
    dir,
    cleanup: () => {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}
