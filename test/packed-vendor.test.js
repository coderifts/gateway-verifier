'use strict';

/**
 * The npm tarball, not the working tree, is what a consumer installs.
 * 0.1.2 must ship verify-grant.js that admits applied_policy_hash.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

describe('packed tarball carries the v1.0.3 grant verifier', () => {
  it('npm pack includes src/verify-grant.js with applied_policy_hash on V2_RESERVED_INERT', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-pack-'));
    try {
      const packed = spawnSync('npm', ['pack', '--silent', '--pack-destination', tmp], {
        cwd: ROOT, encoding: 'utf8',
      });
      assert.equal(packed.status, 0, packed.stderr);
      const name = packed.stdout.trim().split('\n').pop().trim();
      const tgz = path.join(tmp, path.basename(name));
      assert.ok(fs.existsSync(tgz), tgz);
      const list = spawnSync('tar', ['-tzf', tgz], { encoding: 'utf8' });
      assert.equal(list.status, 0, list.stderr);
      assert.match(list.stdout, /package\/src\/verify-grant\.js/);
      const cat = spawnSync('tar', ['-xOf', tgz, 'package/src/verify-grant.js'], { encoding: 'utf8' });
      assert.equal(cat.status, 0, cat.stderr);
      assert.match(cat.stdout, /applied_policy_hash/);
      assert.match(cat.stdout, /V2_RESERVED_INERT/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
