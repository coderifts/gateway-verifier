'use strict';

/**
 * Only a v4 receipt bound to the envelope is authorization (P66; receipt-verifier 1.1.4 moves the rule
 * into the core verifyReceipt, this repo's call site has carried it since 2026-10-17).
 *
 * MEASURED 2026-10-17 (org audit, CC 17b block C): with the v1.0.3 core vendored and no call-site check,
 * a real production-signed v2 receipt (no `bh`, `caller: anon`) beside a FORGED ALLOW/CONTINUE envelope
 * was admitted: `allow: true`. These cases keep that from coming back after any re-vendor.
 *
 * Fixtures are PUBLIC test fixtures copied from receipt-verifier: test/fixtures-receipt.txt (a v2 receipt
 * signed by the production key 2026-07-k1), test/fixtures-keys.json (that key's PUBLIC half), and the
 * `valid_v4` vector of test/vectors.json (a test key). No private key is involved.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { checkRequest } = require('../src/index.js');
const core = require('../src/verify.js');
const { newSigner, mintV4, envelope } = require('./mint.js');

const FIX = path.join(__dirname, 'fixtures');
const V2 = fs.readFileSync(path.join(FIX, 'rv-v2-production-receipt.txt'), 'utf8').trim();
const PROD_KEYS = JSON.parse(fs.readFileSync(path.join(FIX, 'rv-v2-production-keys.json'), 'utf8'));
const V4 = JSON.parse(fs.readFileSync(path.join(FIX, 'rv-valid-v4-vector.json'), 'utf8'));

const ringOf = (keys) => new Map(keys.map((k) => [k.kid, {
  publicKey: crypto.createPublicKey(k.public_key_pem), status: k.status || 'active', retired_at: k.retired_at || null,
}]));
const PROD_RING = ringOf(PROD_KEYS.keys);
const V4_RING = ringOf([{ kid: V4.kid, public_key_pem: V4.public_key_pem }]);

const INTENT = { operation: 'deploy', target_uri: 'api://orders' };
/** An envelope anyone can write: it says ALLOW / CONTINUE for exactly the intended target. */
const FORGED = envelope({ execution_action: 'CONTINUE', decision: 'ALLOW', extra: { ...INTENT } });
const headers = (token, env) => ({
  'x-coderifts-receipt': token,
  'x-coderifts-decision': Buffer.from(JSON.stringify(env), 'utf8').toString('base64'),
});

describe('v4-only — a v<4 receipt beside an envelope is never authorization', () => {
  it('control: the production v2 receipt itself verifies (signature) with the pinned public key', () => {
    const r = core.verifyReceipt(V2, { ctx: { keyring: PROD_RING, expectedKid: null } });
    assert.equal(r.valid, true, JSON.stringify(r));
    assert.equal(r.payload.v, 2);
  });

  it('⚠⚠ production v2 receipt + forged ALLOW envelope → denied, RECEIPT_VERSION_UNSUPPORTED', () => {
    const v = checkRequest({ headers: headers(V2, FORGED), intended: INTENT, keyring: PROD_RING });
    assert.equal(v.allow, false, JSON.stringify(v));
    // Before the 1.1.4 re-vendor the call site names it; after it the core does (result.status). Either way.
    assert.match(JSON.stringify(v), /RECEIPT_VERSION_UNSUPPORTED/);
  });

  it('the valid_v4 vector beside an envelope it does not bind → the verdict it had (INVALID_SIGNATURE)', () => {
    const v = checkRequest({ headers: headers(V4.token, FORGED), intended: INTENT, keyring: V4_RING });
    assert.equal(v.allow, false, JSON.stringify(v));
    assert.equal(v.detail, 'INVALID_SIGNATURE');
  });

  it('control: a v4 receipt bound to its envelope is still admitted', () => {
    const signer = newSigner('gw-v4only');
    const ring = new Map([[signer.kid, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);
    const env = envelope({ execution_action: 'CONTINUE', decision: 'ALLOW', extra: { ...INTENT } });
    const v = checkRequest({ headers: headers(mintV4(signer, env), env), intended: INTENT, keyring: ring });
    assert.equal(v.allow, true, JSON.stringify(v));
  });
});
