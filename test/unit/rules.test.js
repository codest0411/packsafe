import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { scanLinePS001 } from '../../src/rules/ps001-home-paths.js';
import { scanLinePS002 } from '../../src/rules/ps002-identity.js';
import { scanLinePS003 } from '../../src/rules/ps003-secrets.js';
import { scanSourceMapPS004 } from '../../src/rules/ps004-sourcemaps.js';
import { scanFilePathPS005 } from '../../src/rules/ps005-risky-files.js';
import { scanLinePS006, scanPackageJsonPS006 } from '../../src/rules/ps006-internal-urls.js';
import { evaluateSizePS007 } from '../../src/rules/ps007-size-sanity.js';
import { scanLinePS008 } from '../../src/rules/ps008-emails.js';

describe('rules PS001-PS008', () => {
  it('PS001: detects POSIX, Windows, JSON-escaped, and file:// home paths while ignoring placeholders', () => {
    assert.equal(scanLinePS001('const p = "/home/alexsmith/proj";', 'a.js', 1).length, 1);
    assert.equal(scanLinePS001('const p = "/Users/alexsmith/proj";', 'a.js', 1).length, 1);
    assert.equal(scanLinePS001('const p = "C:\\Users\\alexsmith\\proj";', 'a.js', 1).length, 1);
    assert.equal(scanLinePS001('{"p":"C:\\\\Users\\\\alexsmith\\\\proj"}', 'a.json', 1).length, 1);
    assert.equal(scanLinePS001('const p = "C:/Users/alexsmith/proj";', 'a.js', 1).length, 1);
    assert.equal(scanLinePS001('const u = "file:///Users/alexsmith/proj";', 'a.js', 1).length, 1);

    // Placeholders ignored
    assert.equal(scanLinePS001('const p = "/home/yourname/proj";', 'README.md', 1).length, 0);
    assert.equal(scanLinePS001('const p = "C:\\Users\\username\\proj";', 'README.md', 1).length, 0);
    assert.equal(scanLinePS001('const p = "/Users/runner/work";', 'README.md', 1).length, 0);
  });

  it('PS002: detects case-insensitive boundary-aware identity and denyWords', () => {
    const ctx = {
      identities: [{ value: 'alexsmith', kind: 'username' }],
      denyWords: ['ProjectApollo']
    };
    assert.equal(scanLinePS002('Built by AlexSmith on CI', 'a.js', 1, ctx).length, 1);
    assert.equal(scanLinePS002('Internal codename: projectapollo!', 'a.js', 1, ctx).length, 1);
    // Not a boundary match
    assert.equal(scanLinePS002('const x = "prealexsmithpost";', 'a.js', 1, ctx).length, 0);
  });

  it('PS003: detects secrets and redacts values', () => {
    const fakeNpm = 'npm_' + 'A'.repeat(36);
    const f1 = scanLinePS003(`token = "${fakeNpm}"`, 'a.js', 1);
    assert.equal(f1.length, 1);
    assert.equal(f1[0]?.message.includes('AAAA'), false);
    assert.equal(f1[0]?.message.includes('npm_...[redacted len=40]'), true);

    assert.equal(scanLinePS003('-----BEGIN RSA PRIVATE KEY-----', 'k.txt', 1).length, 1);
    assert.equal(scanLinePS003(`const gh = "ghp_${'B'.repeat(36)}";`, 'a.js', 1).length, 1);
    assert.equal(scanLinePS003(`const pat = "github_pat_${'C'.repeat(30)}";`, 'a.js', 1).length, 1);
    assert.equal(scanLinePS003('const aws = "AKIAIOSFODNN7EXAMPLE";', 'a.js', 1).length, 1);
    assert.equal(scanLinePS003('const slack = "xoxb-1234567890-abcdefghij";', 'a.js', 1).length, 1);
    assert.equal(scanLinePS003('//registry.npmjs.org/:_authToken=supersecrettoken123', '.npmrc', 1).length, 1);
    assert.equal(scanLinePS003('const apiKey = "super_real_secret_key_987654";', 'a.js', 1).length, 1);
    // Placeholder ignored
    assert.equal(scanLinePS003('const apiKey = "your-api-key-here";', 'README.md', 1).length, 0);
  });

  it('PS004: parses sourcemaps, flags absolute paths, scans sourcesContent, handles malformed JSON', () => {
    const malformed = scanSourceMapPS004('dist/a.js.map', '{bad json', () => []);
    assert.equal(malformed.length, 1);
    assert.equal(malformed[0]?.severity, 'warn');

    const mapJson = JSON.stringify({
      version: 3,
      sourceRoot: '/Users/alexsmith/dev',
      sources: ['C:\\Users\\alexsmith\\dev\\index.ts'],
      sourcesContent: ['const p = "/home/alexsmith/secret";\n']
    });
    const findings = scanSourceMapPS004('dist/a.js.map', mapJson, (line, file, ln) =>
      scanLinePS001(line, file, ln)
    );
    assert.ok(findings.some((f) => f.severity === 'error' && f.message.includes('sourceRoot')));
    assert.ok(findings.some((f) => f.severity === 'error' && f.message.includes('sources[0]')));
    assert.ok(findings.some((f) => f.severity === 'error' && f.ruleId === 'PS001'));
    assert.ok(findings.some((f) => f.severity === 'info' && f.message.includes('sourcesContent')));
  });

  it('PS005: flags risky files', () => {
    for (const p of ['.env', '.env.local', '.npmrc', 'cert.pem', 'id_rsa', '.git/config', 'data.sqlite', 'npm-debug.log', 'coverage/lcov.info', '.DS_Store', '.vscode/settings.json']) {
      assert.equal(scanFilePathPS005(p).length, 1, `Expected PS005 for ${p}`);
    }
    assert.equal(scanFilePathPS005('src/index.js').length, 0);
  });

  it('PS006: flags private IPs, internal hostnames, localhost in non-test files, publishConfig.registry, and lockfile hosts', () => {
    assert.equal(scanLinePS006('const url = "http://10.0.1.25:8080";', 'src/api.js', 1)[0]?.severity, 'warn');
    assert.equal(scanLinePS006('const url = "http://192.168.1.10";', 'src/api.js', 1)[0]?.severity, 'warn');
    assert.equal(scanLinePS006('const url = "http://172.16.5.4";', 'src/api.js', 1)[0]?.severity, 'warn');
    assert.equal(scanLinePS006('const url = "https://auth.corp.internal/v1";', 'src/api.js', 1)[0]?.severity, 'warn');
    assert.equal(scanLinePS006('const url = "http://localhost:3000/api";', 'src/api.js', 1)[0]?.severity, 'info');
    // localhost in test file is ignored
    assert.equal(scanLinePS006('const url = "http://localhost:3000/api";', 'test/api.test.js', 1).length, 0);
    // lockfile resolved host
    assert.equal(
      scanLinePS006('"resolved": "https://npm.internal.corp/pkg/-/pkg-1.0.0.tgz"', 'package-lock.json', 5)[0]?.severity,
      'warn'
    );
    assert.equal(
      scanPackageJsonPS006({ publishConfig: { registry: 'https://npm.internal.corp' } }).length,
      1
    );
    assert.equal(
      scanPackageJsonPS006({ publishConfig: { registry: 'https://registry.npmjs.org/' } }).length,
      0
    );
  });

  it('PS007: computes top 5 largest files and warns over thresholds', () => {
    const files = Array.from({ length: 6 }, (_, i) => ({
      relPosix: `file-${i}.js`,
      size: (i + 1) * 1000
    }));
    const res = evaluateSizePS007(files, 21000, { maxTotalBytes: 20000, maxFileCount: 5, maxFileBytes: 5500 });
    assert.equal(res.topLargest.length, 5);
    assert.equal(res.topLargest[0]?.file, 'file-5.js');
    assert.equal(res.findings.filter((f) => f.severity === 'warn').length, 3);
    assert.equal(res.findings.filter((f) => f.severity === 'info').length, 1);
  });

  it('PS008: flags non-allowlisted emails and skips allowlisted ones', () => {
    const pub = new Set(['public@author.dev']);
    assert.equal(scanLinePS008('contact: private@company.io', 'src/a.js', 1, pub).length, 1);
    assert.equal(scanLinePS008('contact: public@author.dev', 'src/a.js', 1, pub).length, 0);
    assert.equal(scanLinePS008('contact: demo@example.com', 'README.md', 1, pub).length, 0);
  });
});
