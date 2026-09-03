'use strict';

/**
 * 1307 — the ext-authz base path verifies an execution grant, not only a receipt.
 *
 * MEASURED before this: this verifier read `x-coderifts-receipt` and `x-coderifts-decision` and
 * nothing else. A receipt records that a decision was issued; a grant is the permission to act on
 * it — bound to one executor, one target, one use.
 *
 * THE OPEN QUESTION WAS THE REQUEST SHAPE, and it is answered by measurement rather than argument:
 * a compact grant is a base64url token of the same order as the receipt this verifier already
 * carries in a header (~700 bytes against the ~8 KB per-header limit proxies typically enforce).
 * Nothing about ext-authz prevented it; it simply was not read.
 *
 * THE WORST CASE these tests are written against: a proxy pairs ANY verified receipt with ANY
 * verified grant and the pair looks complete. The binding test is the load-bearing one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { checkRequest, REASON } = require('../src/index.js');
const { receiptDigest, reconstructSignedInput } = require('../src/verify-grant.js');
const { newSigner, mintV4, envelope } = require('./mint.js');

const KID = 'gw-grant-k1';
const INTENT = { operation: 'deploy', target_uri: 'api://orders' };
const signer = newSigner(KID);
const keyring = new Map([[KID, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);

const env = envelope({ execution_action: 'CONTINUE', decision: 'ALLOW', extra: INTENT });
const token = mintV4(signer, env);

function headers(over = {}) {
  return {
    'x-coderifts-receipt': token,
    'x-coderifts-decision': Buffer.from(JSON.stringify(env), 'utf8').toString('base64'),
    ...over,
  };
}

function mintGrant(receiptToken, over = {}) {
  const now = Date.now();
  const body = {
    v: 'cr.exec.v1',
    kid: KID,
    receipt_digest: receiptDigest(receiptToken),
    scope_hash: `sha256:${crypto.createHash('sha256').update('scope').digest('hex')}`,
    audience: 'api://orders',
    operation: 'deploy',
    target_id: 'api://orders',
    jti: 'jti-gw-1',
    iat: new Date(now - 1000).toISOString(),
    exp: new Date(now + 300000).toISOString(),
    ...over,
  };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(body), 'utf8'), signer.privateKey);
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
}

describe('1307 — additive: nothing changes without the header', () => {
  it('a request with no grant header is allowed exactly as before', () => {
    const v = checkRequest({ headers: headers(), intended: INTENT, keyring });
    assert.equal(v.allow, true);
    assert.equal(v.grant_status, null, 'absent must read as absent, not as failed');
  });

  it('every existing deny reason is untouched', () => {
    const v = checkRequest({ headers: {}, intended: INTENT, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_MISSING);
  });
});

describe('1307 — a grant header is verified offline', () => {
  it('a real grant bound to the receipt is allowed, and its status reported', () => {
    const v = checkRequest({
      headers: headers({ 'x-coderifts-grant': mintGrant(token) }), intended: INTENT, keyring,
    });
    assert.equal(v.allow, true, v.reason);
    assert.ok(v.grant_status, 'the grant status was not reported');
  });

  it('a FORGED grant is refused', () => {
    const [body, sig] = mintGrant(token).split('.');
    const raw = Buffer.from(sig, 'base64url');
    raw[0] ^= 0xff;
    const v = checkRequest({
      headers: headers({ 'x-coderifts-grant': `${body}.${raw.toString('base64url')}` }),
      intended: INTENT,
      keyring,
    });
    assert.equal(v.allow, false, 'a forged grant was forwarded');
    assert.equal(v.reason, REASON.GRANT_INVALID);
  });

  it('WORST CASE: a VALID grant for a DIFFERENT receipt is refused', () => {
    // Both documents verify. They are about different things, and a proxy that accepted the pair
    // would be admitting a request nobody authorised.
    const otherEnv = envelope({
      execution_action: 'CONTINUE', decision: 'ALLOW',
      extra: { operation: 'deploy', target_uri: 'api://somewhere-else' },
    });
    const other = mintV4(signer, otherEnv);
    assert.notEqual(other, token, 'the two receipts are not different');

    const v = checkRequest({
      headers: headers({ 'x-coderifts-grant': mintGrant(other) }), intended: INTENT, keyring,
    });
    assert.equal(v.allow, false, 'a grant bound to another receipt was accepted');
    assert.equal(v.reason, REASON.GRANT_NOT_BOUND);
  });

  it('an EXPIRED grant is refused', () => {
    const past = Date.now() - 600000;
    const v = checkRequest({
      headers: headers({
        'x-coderifts-grant': mintGrant(token, {
          iat: new Date(past - 1000).toISOString(), exp: new Date(past).toISOString(),
        }),
      }),
      intended: INTENT,
      keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.GRANT_INVALID);
  });

  it('a grant signed by a kid the pinned ring does not carry is refused', () => {
    // Rotation is additive; an unknown kid is fail-closed, never "probably fine".
    const stranger = newSigner('not-in-the-ring');
    const body = {
      v: 'cr.exec.v1', kid: 'not-in-the-ring', receipt_digest: receiptDigest(token),
      scope_hash: `sha256:${'0'.repeat(64)}`, audience: 'api://orders', operation: 'deploy',
      target_id: 'api://orders', jti: 'j', iat: new Date(Date.now() - 1000).toISOString(),
      exp: new Date(Date.now() + 300000).toISOString(),
    };
    const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(body), 'utf8'), stranger.privateKey);
    const tok = `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${Buffer.from(sig).toString('base64url')}`;
    const v = checkRequest({ headers: headers({ 'x-coderifts-grant': tok }), intended: INTENT, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.GRANT_INVALID);
  });
});

describe('1307 — requireGrant makes absence a refusal', () => {
  it('no grant + requireGrant → refused', () => {
    const v = checkRequest({ headers: headers(), intended: INTENT, keyring, requireGrant: true });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.GRANT_MISSING);
  });

  it('a grant + requireGrant → allowed', () => {
    const v = checkRequest({
      headers: headers({ 'x-coderifts-grant': mintGrant(token) }),
      intended: INTENT, keyring, requireGrant: true,
    });
    assert.equal(v.allow, true, v.reason);
  });
});

describe('1307 — the grant never becomes a second door', () => {
  it('a perfect grant does not rescue a receipt that fails', () => {
    const bad = `${token.split('.')[0]}.${Buffer.from('not-a-signature').toString('base64url')}`;
    const v = checkRequest({
      headers: headers({ 'x-coderifts-receipt': bad, 'x-coderifts-grant': mintGrant(token) }),
      intended: INTENT,
      keyring,
    });
    assert.equal(v.allow, false);
    assert.notEqual(v.reason, REASON.GRANT_INVALID, 'refused for the grant, not for the receipt');
  });

  it('the whole path stays OFFLINE — no fetch was added', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
    assert.doesNotMatch(src, /fetch\(|https?\.request\(|axios/,
      'the ext-authz path acquired a network call');
  });

  it('the vendored grant verifier is pinned like the rest of the core', () => {
    const pin = fs.readFileSync(path.join(__dirname, '..', 'src', 'VENDOR.sha256'), 'utf8');
    assert.match(pin, /verify-grant\.js\s+[0-9a-f]{64}/, 'verify-grant.js is not pinned');
    const digest = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(__dirname, '..', 'src', 'verify-grant.js')))
      .digest('hex');
    assert.ok(pin.includes(digest), 'the vendored grant verifier drifted from its pin');
  });
});
