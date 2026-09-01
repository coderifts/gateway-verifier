'use strict';

/**
 * I-1288f — the DECISION's own next step in the 403 body, from the SIGNED envelope.
 *
 * The step lives inside decision_result, so decision_body_hash covers it and the
 * receipt signs it. A gateway can therefore forward it without ever calling the
 * issuer — which is the point, since ext-authz sits on the request path.
 *
 * The threat this surface has and the webhook does not: the decision envelope
 * arrives in a REQUEST HEADER. Anyone who can reach the gateway can write a
 * perfectly well-formed step into it. So the rule is not a nicety — a step is
 * rendered only from an envelope whose body hash the signature already bound.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { checkRequest, readNextAgentStep, REASON } = require('../src/index.js');
const { newSigner, mintV4, envelope, NEXT_STEP } = require('./mint.js');

const KID = 'gw-nextstep-k1';
const INTENT = { operation: 'deploy', target_uri: 'api://orders' };
const signer = newSigner(KID);
const keyring = new Map([[KID, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);

/** A non-allow decision that still VERIFIES — the reachable case for this surface. */
const blockEnv = (extra = {}) => envelope({
  execution_action: 'STOP',
  decision: 'BLOCK',
  extra: { ...INTENT, ...extra },
});

const headersFor = (env, tok) => ({
  'x-coderifts-receipt': tok || mintV4(signer, env),
  'x-coderifts-decision': Buffer.from(JSON.stringify(env), 'utf8').toString('base64'),
});

describe('next_agent_step — reachability', () => {
  it('a non-allow decision DOES reach this surface: it verifies, then is refused', () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const v = checkRequest({ headers: headersFor(env), intended: INTENT, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.DECISION_NOT_ALLOW);
    assert.equal(v.detail, 'STOP');
  });
});

describe('next_agent_step — rendered verbatim beside remedy', () => {
  it('the 403 body carries next_step, byte-for-byte from the envelope', () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const v = checkRequest({ headers: headersFor(env), intended: INTENT, keyring });
    assert.deepEqual(v.next_step, NEXT_STEP);
    // Verbatim: not re-derived, not re-ordered, not summarised.
    assert.equal(JSON.stringify(v.next_step), JSON.stringify(NEXT_STEP));
  });

  it('THE VERDICT NEVER MOVES: every branchable field is deep-equal to the no-step run', () => {
    const withStep = checkRequest({
      headers: headersFor(blockEnv({ next_agent_step: NEXT_STEP })), intended: INTENT, keyring,
    });
    const without = checkRequest({
      headers: headersFor(blockEnv()), intended: INTENT, keyring,
    });
    for (const k of ['allow', 'reason', 'detail']) {
      assert.deepEqual(withStep[k], without[k], `${k} moved`);
    }
    assert.deepEqual(withStep.remedy, without.remedy);
    const strip = (o) => { const c = { ...o }; delete c.next_step; return c; };
    assert.deepEqual(strip(withStep), strip(without));
  });

  it('a scope mismatch on a VERIFIED envelope carries BOTH: remedy and next_step', () => {
    // MEASURED CO-OCCURRENCE. They answer different questions: `remedy` is "your grant is
    // not usable for THIS request", `next_step` is "this is what the decision says to do
    // about the change". A scope-mismatched envelope reaches here already verified.
    const env = envelope({
      execution_action: 'CONTINUE',
      decision: 'ALLOW',
      extra: { operation: 'deploy', target_uri: 'api://other', next_agent_step: NEXT_STEP },
    });
    const v = checkRequest({ headers: headersFor(env), intended: INTENT, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.SCOPE_MISMATCH);
    assert.ok(v.remedy, 'the gateway\'s own remedy');
    assert.deepEqual(v.next_step, NEXT_STEP);
  });
});

describe('next_agent_step — an unsigned step is never shown as guidance', () => {
  it('a TAMPERED signature renders no next_step, though the header carries one', () => {
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const good = mintV4(signer, env);
    const badSig = `${good.split('.')[0]}.${Buffer.from('not-a-signature').toString('base64url')}`;
    const v = checkRequest({ headers: headersFor(env, badSig), intended: INTENT, keyring });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_INVALID);
    assert.ok(!('next_step' in v), 'an unverified header envelope must never yield a step');
  });

  it('an envelope SWAPPED after signing renders no next_step (body hash no longer binds)', () => {
    // The attacker keeps a genuine receipt and rewrites only the decision header,
    // inserting a step that tells the caller to proceed. verifyReceipt refuses.
    const honest = blockEnv();
    const token = mintV4(signer, honest);
    const forged = blockEnv({ next_agent_step: { ...NEXT_STEP, action: 're_preflight' } });
    const v = checkRequest({
      headers: {
        'x-coderifts-receipt': token,
        'x-coderifts-decision': Buffer.from(JSON.stringify(forged), 'utf8').toString('base64'),
      },
      intended: INTENT,
      keyring,
    });
    assert.equal(v.allow, false);
    assert.ok(!('next_step' in v));
  });

  it('an envelope signed by an UNKNOWN key renders no next_step', () => {
    const stranger = newSigner('not-in-the-keyring');
    const env = blockEnv({ next_agent_step: NEXT_STEP });
    const v = checkRequest({
      headers: headersFor(env, mintV4(stranger, env)), intended: INTENT, keyring,
    });
    assert.equal(v.allow, false);
    assert.ok(!('next_step' in v));
  });

  it('no receipt at all: the gateway\'s remedy, and no step (there is no envelope)', () => {
    const v = checkRequest({ headers: {}, intended: INTENT, keyring });
    assert.equal(v.reason, REASON.RECEIPT_MISSING);
    assert.ok(v.remedy);
    assert.ok(!('next_step' in v));
  });
});

describe('next_agent_step — absent, allow, and malformed', () => {
  it('a 200 forward carries no next_step', () => {
    const env = envelope({
      execution_action: 'CONTINUE', decision: 'ALLOW', extra: { ...INTENT, next_agent_step: null },
    });
    const v = checkRequest({ headers: headersFor(env), intended: INTENT, keyring });
    assert.equal(v.allow, true);
    assert.ok(!('next_step' in v));
  });

  it('an absent step is not invented', () => {
    for (const extra of [{ next_agent_step: null }, {}]) {
      const v = checkRequest({
        headers: headersFor(blockEnv(extra)), intended: INTENT, keyring,
      });
      assert.equal(v.reason, REASON.DECISION_NOT_ALLOW);
      assert.ok(!('next_step' in v), `unexpected step for ${JSON.stringify(extra)}`);
    }
  });

  it('a step without an action is not a step', () => {
    assert.equal(readNextAgentStep({ next_agent_step: { reason: 'x' } }), null);
    assert.equal(readNextAgentStep({ next_agent_step: 'revert' }), null);
    assert.equal(readNextAgentStep({ next_agent_step: ['revert'] }), null);
    assert.equal(readNextAgentStep({ next_agent_step: { action: '' } }), null);
    assert.equal(readNextAgentStep(undefined), null);
  });
});
