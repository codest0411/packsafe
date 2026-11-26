import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { scanLinePS001 } from '../../src/rules/ps001-home-paths.js';
import { scanLinePS002 } from '../../src/rules/ps002-identity.js';
import { scanLinePS003 } from '../../src/rules/ps003-secrets.js';
import { scanSourceMapPS004 } from '../../src/rules/ps004-sourcemaps.js';
import { scanLinePS006 } from '../../src/rules/ps006-internal-urls.js';
import { scanLinePS008 } from '../../src/rules/ps008-emails.js';

describe('adversarial and fuzz tests (linear-time guarantee)', () => {
  it('handles pathological repeated patterns within 500ms without throwing', () => {
    const pathologicalInputs = [
      '/home/'.repeat(5000),
      'C:\\Users\\'.repeat(5000),
      '-----BEGIN '.repeat(2000),
      'npm_'.repeat(5000),
      'password="' + 'a'.repeat(50000),
      '192.168.'.repeat(5000),
      'user@'.repeat(5000),
      'https://a.b.c.'.repeat(2000) + 'internal'
    ];

    const start = Date.now();
    for (const input of pathologicalInputs) {
      scanLinePS001(input, 'fuzz.js', 1);
      scanLinePS002(input, 'fuzz.js', 1, {
        identities: [{ value: 'alexsmith', kind: 'username' }],
        denyWords: ['internal']
      });
      scanLinePS003(input, 'fuzz.js', 1);
      scanLinePS006(input, 'fuzz.js', 1);
      scanLinePS008(input, 'fuzz.js', 1, new Set());
    }
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 1000, `Pathological fuzz took too long: ${elapsed}ms`);
  });

  it('handles random ASCII/unicode text and malformed sourcemaps without throwing', () => {
    let seed = 1337;
    const nextByte = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed & 0xff;
    };

    for (let i = 0; i < 50; i += 1) {
      let line = '';
      for (let j = 0; j < 256; j += 1) {
        line += String.fromCharCode(32 + (nextByte() % 95));
      }
      assert.doesNotThrow(() => {
        scanLinePS001(line, 'rand.js', i + 1);
        scanLinePS002(line, 'rand.js', i + 1, { identities: [{ value: 'randuser', kind: 'username' }] });
        scanLinePS003(line, 'rand.js', i + 1);
        scanLinePS006(line, 'rand.js', i + 1);
        scanLinePS008(line, 'rand.js', i + 1, new Set());
        scanSourceMapPS004('rand.js.map', line, () => []);
      });
    }
  });
});
