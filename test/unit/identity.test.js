import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { detectMachineIdentity, extractPublicPackageIdentity } from '../../src/identity.js';

describe('machine identity detection', () => {
  it('extracts public author, contributors, repository, and bugs from package.json', () => {
    const pub = extractPublicPackageIdentity({
      author: 'Jane Developer <jane@open-source.org>',
      contributors: [{ name: 'Bob Helper', email: 'bob@helper.dev' }],
      repository: { url: 'https://github.com/acme/pkg' },
      bugs: { email: 'bugs@open-source.org' }
    });
    assert.ok(pub.has('jane developer'));
    assert.ok(pub.has('jane@open-source.org'));
    assert.ok(pub.has('bob helper'));
    assert.ok(pub.has('bob@helper.dev'));
    assert.ok(pub.has('bugs@open-source.org'));
  });

  it('filters short strings (<4), denylist words, and public package.json identity', async () => {
    const { entries } = await detectMachineIdentity(process.cwd(), {
      pkgJson: {
        author: 'Public Author <public@author.dev>'
      },
      provider: async () => ({
        username: 'ab', // too short (<4)
        homedir: '/home/ubuntu', // denylisted
        hostname: 'workstation-42.corp.internal',
        gitName: 'Public Author', // matches package.json author
        gitEmail: 'private.me@internal.corp'
      })
    });

    const values = entries.map((e) => e.value);
    assert.equal(values.includes('ab'), false);
    assert.equal(values.includes('ubuntu'), false);
    assert.equal(values.includes('Public Author'), false);
    assert.ok(values.includes('workstation-42.corp.internal'));
    assert.ok(values.includes('workstation-42'));
    assert.ok(values.includes('private.me@internal.corp'));
  });

  it('flags package.json author when allowPackageJsonIdentity is false', async () => {
    const { entries } = await detectMachineIdentity(process.cwd(), {
      pkgJson: { author: 'Jane Developer <jane@dev.org>' },
      allowPackageJsonIdentity: false,
      provider: async () => ({
        username: 'janedev',
        gitName: 'Jane Developer'
      })
    });
    const values = entries.map((e) => e.value);
    assert.ok(values.includes('janedev'));
    assert.ok(values.includes('Jane Developer'));
  });
});
