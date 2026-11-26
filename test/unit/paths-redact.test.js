import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { isBinaryBuffer, normalizeText, resolveSafePackagePath, toPosixPath } from '../../src/paths.js';
import { redactLineSnippet, redactSecret } from '../../src/redact.js';

describe('paths and redaction', () => {
  it('normalizes Windows backslashes, UTF-8 BOM, and CRLF', () => {
    assert.equal(toPosixPath('dist\\sub\\index.js'), 'dist/sub/index.js');
    assert.equal(normalizeText('\uFEFFline1\r\nline2\rline3'), 'line1\nline2\nline3');
  });

  it('detects binary buffers via NUL byte', () => {
    assert.equal(isBinaryBuffer(Buffer.from('hello world', 'utf8')), false);
    assert.equal(isBinaryBuffer(Buffer.from([0x41, 0x00, 0x42])), true);
  });

  it('rejects traversal, absolute paths, NUL bytes, and escaping symlinks', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'packsafe-path-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'packsafe-out-'));
    try {
      const rootReal = fs.realpathSync(root);
      const insideFile = path.join(rootReal, 'index.js');
      fs.writeFileSync(insideFile, 'export {};\n');

      const outsideFile = path.join(outside, 'secret.txt');
      fs.writeFileSync(outsideFile, 'top-secret');

      assert.equal(resolveSafePackagePath(rootReal, '').ok, false);
      assert.equal(resolveSafePackagePath(rootReal, 'a\0b').ok, false);
      assert.equal(resolveSafePackagePath(rootReal, '/etc/passwd').ok, false);
      assert.equal(resolveSafePackagePath(rootReal, 'C:/Windows/win.ini').ok, false);
      assert.equal(resolveSafePackagePath(rootReal, '../outside.txt').ok, false);
      assert.equal(resolveSafePackagePath(rootReal, 'missing.js').ok, false);

      const okRes = resolveSafePackagePath(rootReal, 'index.js');
      assert.equal(okRes.ok, true);
      if (okRes.ok) {
        assert.equal(okRes.relPosix, 'index.js');
      }

      // Symlink escape test (skip gracefully if OS denies symlink creation without admin)
      const linkPath = path.join(rootReal, 'escape-link.txt');
      let symlinkCreated = false;
      try {
        fs.symlinkSync(outsideFile, linkPath);
        symlinkCreated = true;
      } catch {
        symlinkCreated = false;
      }
      if (symlinkCreated) {
        const esc = resolveSafePackagePath(rootReal, 'escape-link.txt');
        assert.equal(esc.ok, false);
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('redacts secrets without leaking full values', () => {
    assert.equal(redactSecret(''), '[redacted len=0]');
    assert.equal(redactSecret('abc'), '***[len=3]');
    const full = 'npm_1234567890abcdefghijklmnopqrstuvwxyz';
    const redacted = redactSecret(full);
    assert.equal(redacted, 'npm_...[redacted len=40]');
    assert.equal(redacted.includes('1234567890'), false);

    const snippet = redactLineSnippet(`const token = "${full}";`, 15, 15 + full.length, redacted);
    assert.equal(snippet.includes('1234567890'), false);
    assert.equal(snippet.includes('npm_...[redacted len=40]'), true);
  });
});
