'use strict';

/**
 * The deny carries a next step.
 *
 * Two properties, and the second matters more than the first: every refusal
 * that has a remedy emits a schema-valid one, AND the refusal itself is
 * unchanged. A remedy that altered a verdict would be a governance change
 * dressed as an ergonomics change, so the deny fields are compared against the
 * values this surface returned before the remedy existed.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { checkRequest, REASON } = require('../src/index.js');
const { buildDenyRemedy, denyErrorForReason, DENY_ERROR } = require('../src/deny-remedy.js');
const { assertValidRemedy } = require('./remedy-shape.js');
const { newSigner, mintV4, envelope } = require('./mint.js');

const KID = 'gw-remedy-k1';
const INTENT = { operation: 'deploy', target_uri: 'api://orders' };
const signer = newSigner(KID);
const keyring = new Map([[KID, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);

const env = envelope({ execution_action: 'CONTINUE', decision: 'ALLOW', extra: INTENT });
const token = mintV4(signer, env);
const headers = (over = {}) => ({
  'x-coderifts-receipt': token,
  'x-coderifts-decision': Buffer.from(JSON.stringify(env), 'utf8').toString('base64'),
  ...over,
});
const badSig = `${token.split('.')[0]}.${Buffer.from('not-a-signature').toString('base64url')}`;

describe('deny-remedy — every mapped refusal carries a valid next step', () => {
  it('GRANT_REQUIRED: no receipt presented', () => {
    const v = checkRequest({ headers: {}, intended: INTENT, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_MISSING);
    assertValidRemedy(v.remedy, 'receipt_missing');
    assert.equal(v.remedy.error, DENY_ERROR.GRANT_REQUIRED);
    assert.equal(v.remedy.target, 'api://orders');
    // Nothing was presented, so there is nothing to fingerprint.
    assert.equal(v.remedy.fingerprint, null);
  });

  it('GRANT_INVALID: a receipt that does not verify', () => {
    const v = checkRequest({
      headers: headers({ 'x-coderifts-receipt': badSig }), intended: INTENT, keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_INVALID);
    assertValidRemedy(v.remedy, 'receipt_invalid');
    assert.equal(v.remedy.error, DENY_ERROR.GRANT_INVALID);
    assert.equal(v.remedy.observed.receipt_status, 'INVALID_SIGNATURE');
  });

  it('GRANT_MISMATCH: a valid receipt for another operation', () => {
    const v = checkRequest({
      headers: headers(), intended: { ...INTENT, operation: 'delete' }, keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.SCOPE_MISMATCH);
    assertValidRemedy(v.remedy, 'scope_mismatch');
    assert.equal(v.remedy.error, DENY_ERROR.GRANT_MISMATCH);
    assert.deepEqual(v.remedy.observed.mismatches, v.mismatches);
  });
});

describe('deny-remedy — the verdict is unchanged', () => {
  const stripRemedy = (v) => {
    const out = { ...v };
    delete out.remedy;
    return out;
  };

  it('an ALLOW carries NO remedy key at all', () => {
    const v = checkRequest({ headers: headers(), intended: INTENT, keyring });
    assert.equal(v.allow, true);
    assert.ok(!('remedy' in v), 'a permitted request must not carry a refusal remedy');
  });

  it('the deny fields are byte-identical to the pre-remedy shape', () => {
    // These are the exact objects this surface returned before the remedy was
    // added, measured from its own test suite.
    assert.deepEqual(stripRemedy(checkRequest({ headers: {}, intended: INTENT, keyring })),
      { allow: false, reason: 'receipt_missing' });
    assert.deepEqual(stripRemedy(checkRequest({
      headers: headers({ 'x-coderifts-receipt': badSig }), intended: INTENT, keyring,
    })), { allow: false, reason: 'receipt_invalid', detail: 'INVALID_SIGNATURE' });
    const scope = checkRequest({ headers: headers(), intended: { ...INTENT, operation: 'delete' }, keyring });
    assert.deepEqual(stripRemedy(scope), {
      allow: false,
      reason: 'scope_mismatch',
      mismatches: [{ field: 'operation', receipt: 'deploy', request: 'delete' }],
    });
  });

  it('a refusal outside the three classes carries NO remedy', () => {
    // intent_unresolved is a real refusal with no next step this surface can
    // name: re-authorizing does not fix a route the deployment could not map.
    const v = checkRequest({ headers: headers(), intended: null, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.INTENT_UNRESOLVED);
    assert.ok(!('remedy' in v), 'an unmapped reason must not receive a guessed remedy');
    assert.equal(denyErrorForReason(REASON.INTENT_UNRESOLVED), null);
    assert.equal(denyErrorForReason(REASON.VERIFIER_THREW), null);
  });
});

describe('deny-remedy — the builder refuses what it cannot describe', () => {
  it('an unknown error class returns null, not a fourth class', () => {
    for (const bad of ['CODERIFTS_SOMETHING_ELSE', '', null, undefined, 42]) {
      assert.equal(buildDenyRemedy({ error: bad }), null);
    }
  });

  it('a malformed fingerprint is dropped rather than passed through', () => {
    // A caller comparing a truncated digest would see a false mismatch.
    const r = buildDenyRemedy({ error: DENY_ERROR.GRANT_INVALID, fingerprint: 'sha256:abc' });
    assert.equal(r.fingerprint, null);
    const ok = `sha256:${'a'.repeat(64)}`;
    assert.equal(buildDenyRemedy({ error: DENY_ERROR.GRANT_INVALID, fingerprint: ok }).fingerprint, ok);
  });

  it('an empty target becomes null, never a wildcard', () => {
    assert.equal(buildDenyRemedy({ error: DENY_ERROR.GRANT_REQUIRED, target: '' }).target, null);
  });
});
