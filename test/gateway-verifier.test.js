'use strict';

/**
 * The gateway verifier admits a request only when the receipt VERIFIES and its
 * scope MATCHES. Most of these tests are refusals, because a verifier is only
 * as good as what it turns away — the admit case is one line and the ways to
 * get past it wrongly are many.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { checkRequest, gatewayVerifier, scopeMatches, REASON } = require('../src/index.js');
const { newSigner, mintV4, envelope } = require('./mint.js');

const KID = 'gw-k1';
const INTENT = { operation: 'deploy', target_uri: 'api://orders' };

const signer = newSigner(KID);
const keyring = new Map([[KID, { publicKey: signer.publicKey, status: 'active', retired_at: null }]]);

function issued(over = {}) {
  // `??`, not `||`: an empty-string execution_action is a case under test, and
  // `'' || 'CONTINUE'` silently substituted CONTINUE — the fixture then made the
  // "empty action is refused" test fail against code that refuses it correctly.
  const env = envelope({
    execution_action: over.execution_action ?? 'CONTINUE',
    decision: over.decision ?? 'ALLOW',
    extra: { ...INTENT, ...(over.extra || {}) },
  });
  return { env, token: mintV4(signer, env) };
}

const headersFor = ({ token, env }, over = {}) => ({
  'x-coderifts-receipt': token,
  'x-coderifts-decision': Buffer.from(JSON.stringify(env), 'utf8').toString('base64'),
  ...over,
});

/** Wrap a compact token as a DSSE envelope, the way an external emitter would. */
function dsse(token) {
  const [encoded, sig] = token.split('.');
  const fields = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{
      name: 'crchain.v1',
      digest: { sha256: crypto.createHash('sha256').update(token, 'utf8').digest('hex') },
    }],
    predicateType: 'https://coderifts.com/attestations/agent-action-authorization/v1',
    predicate: { compact: { form: 'crchain.v1', encoded_payload: encoded }, fields },
  };
  return JSON.stringify({
    payloadType: 'application/vnd.in-toto+json',
    payload: Buffer.from(JSON.stringify(statement), 'utf8').toString('base64'),
    signatures: [{ keyid: fields.kid, sig }],
  });
}

// ── THE ADMIT CASE ───────────────────────────────────────────────────────────
describe('gateway verifier — a valid, in-scope receipt is admitted', () => {
  it('admits, and reports what it verified', () => {
    const v = checkRequest({ headers: headersFor(issued()), intended: INTENT, keyring });
    assert.equal(v.allow, true, JSON.stringify(v));
    assert.equal(v.receipt_status, 'VERIFIED_CURRENT');
    assert.equal(v.execution_action, 'CONTINUE');
    assert.equal(v.receipt_form, 'compact');
  });

  it('admits a DSSE-wrapped receipt identically', () => {
    const iss = issued();
    const compact = checkRequest({ headers: headersFor(iss), intended: INTENT, keyring });
    const wrapped = checkRequest({
      headers: headersFor(iss, { 'x-coderifts-receipt': dsse(iss.token) }), intended: INTENT, keyring,
    });
    assert.equal(wrapped.allow, true, JSON.stringify(wrapped));
    assert.equal(wrapped.receipt_form, 'dsse');
    assert.equal(wrapped.receipt_status, compact.receipt_status);
  });

  it('CONTINUE_WITH_MONITORING admits but NAMES the unverified claim', () => {
    // The monitoring sink is not checked here. A green result that stayed quiet
    // about that would let an operator believe more was verified than was.
    const v = checkRequest({
      headers: headersFor(issued({ execution_action: 'CONTINUE_WITH_MONITORING' })),
      intended: INTENT, keyring,
    });
    assert.equal(v.allow, true);
    assert.equal(v.monitoring_claim_unverified, true);
  });

  it('header lookup is case-insensitive', () => {
    const iss = issued();
    const v = checkRequest({
      headers: {
        'X-CodeRifts-Receipt': iss.token,
        'X-CODERIFTS-DECISION': Buffer.from(JSON.stringify(iss.env), 'utf8').toString('base64'),
      },
      intended: INTENT, keyring,
    });
    assert.equal(v.allow, true, JSON.stringify(v));
  });
});

// ── A RECEIPT'S PRESENCE IS NOT A PASS ───────────────────────────────────────
describe('gateway verifier — presence is not a pass', () => {
  it('no receipt header → receipt_missing', () => {
    for (const h of [{}, { 'x-coderifts-receipt': '' }]) {
      assert.deepEqual(checkRequest({ headers: h, intended: INTENT, keyring }),
        { allow: false, reason: REASON.RECEIPT_MISSING });
    }
  });

  it('a receipt-shaped string that is not signed by a pinned key → receipt_invalid', () => {
    const stranger = newSigner('stranger-1');
    const env = envelope({ extra: INTENT });
    const v = checkRequest({
      headers: headersFor({ token: mintV4(stranger, env), env }), intended: INTENT, keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_INVALID);
  });

  it('a tampered signature → receipt_invalid', () => {
    const iss = issued();
    const [payload] = iss.token.split('.');
    const forged = `${payload}.${Buffer.from('not-a-signature').toString('base64url')}`;
    const v = checkRequest({
      headers: headersFor({ token: forged, env: iss.env }), intended: INTENT, keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_INVALID);
  });

  it('A SWAPPED DECISION ENVELOPE → receipt_invalid, not scope_mismatch', () => {
    // The scope only means something because the receipt is BOUND to the
    // envelope by body hash. Present a receipt with someone else's envelope and
    // verification fails before scope is ever considered — which is the order
    // this module depends on.
    const real = issued();
    const other = issued({ extra: { operation: 'delete', target_uri: 'api://everything' } });
    const v = checkRequest({
      headers: headersFor({ token: real.token, env: other.env }),
      intended: { operation: 'delete', target_uri: 'api://everything' },
      keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.RECEIPT_INVALID,
      'a caller swapped the envelope and the scope check was reached anyway');
  });

  it('a DSSE envelope whose predicate was rewritten → dsse_predicate_mismatch', () => {
    const iss = issued();
    const env = JSON.parse(dsse(iss.token));
    const st = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    st.predicate.fields.caller = 'attacker';
    env.payload = Buffer.from(JSON.stringify(st), 'utf8').toString('base64');
    const v = checkRequest({
      headers: headersFor(iss, { 'x-coderifts-receipt': JSON.stringify(env) }),
      intended: INTENT, keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.DSSE_PREDICATE_MISMATCH);
  });

  it('a non-passing execution_action → decision_not_allow', () => {
    for (const action of ['STOP', 'REQUEST_APPROVAL', '', 'CONTINUE_MAYBE']) {
      const v = checkRequest({
        headers: headersFor(issued({ execution_action: action })), intended: INTENT, keyring,
      });
      assert.equal(v.allow, false, `${action} was admitted`);
      assert.equal(v.reason, REASON.DECISION_NOT_ALLOW);
    }
  });

  it('a missing or unparseable decision header → named, never skipped', () => {
    const iss = issued();
    assert.equal(checkRequest({
      headers: { 'x-coderifts-receipt': iss.token }, intended: INTENT, keyring,
    }).reason, REASON.DECISION_MISSING);
    assert.equal(checkRequest({
      headers: headersFor(iss, { 'x-coderifts-decision': 'bm90LWpzb24=' }), intended: INTENT, keyring,
    }).reason, REASON.DECISION_MALFORMED);
  });
});

// ── SCOPE ────────────────────────────────────────────────────────────────────
describe('gateway verifier — the scope must match the request', () => {
  it('a valid receipt for a DIFFERENT operation → scope_mismatch', () => {
    const v = checkRequest({
      headers: headersFor(issued()),
      intended: { operation: 'delete', target_uri: 'api://orders' },
      keyring,
    });
    assert.equal(v.allow, false);
    assert.equal(v.reason, REASON.SCOPE_MISMATCH);
    assert.deepEqual(v.mismatches, [{ field: 'operation', receipt: 'deploy', request: 'delete' }]);
  });

  it('a valid receipt for a DIFFERENT target → scope_mismatch', () => {
    const v = checkRequest({
      headers: headersFor(issued()),
      intended: { operation: 'deploy', target_uri: 'api://billing' },
      keyring,
    });
    assert.equal(v.reason, REASON.SCOPE_MISMATCH);
    assert.equal(v.mismatches[0].field, 'target_uri');
  });

  it('EVERY mismatching field is reported, not only the first', () => {
    const v = checkRequest({
      headers: headersFor(issued()),
      intended: { operation: 'delete', target_uri: 'api://billing' },
      keyring,
    });
    assert.equal(v.mismatches.length, 2);
  });

  it('AN UNRESOLVED INTENT REFUSES — it does not wave the request through', () => {
    // The failure this guards: a gateway that could not work out what a route
    // means, admitting anyway, and looking enforced while enforcing nothing.
    for (const intended of [null, undefined, {}, 'deploy', 42]) {
      const v = checkRequest({ headers: headersFor(issued()), intended, keyring });
      assert.equal(v.allow, false, `intent ${JSON.stringify(intended)} admitted`);
      assert.equal(v.reason, REASON.INTENT_UNRESOLVED);
    }
  });

  it('a field the receipt does not carry is a mismatch, not a pass', () => {
    const v = checkRequest({
      headers: headersFor(issued()),
      intended: { ...INTENT, tenant_id: 'acme' },
      keyring,
    });
    assert.equal(v.reason, REASON.SCOPE_MISMATCH);
    assert.deepEqual(v.mismatches, [{ field: 'tenant_id', receipt: null, request: 'acme' }]);
  });

  it('an empty expectation is skipped, and an ALL-empty intent refuses', () => {
    // The bug this caught: counting SUPPLIED fields instead of COMPARED ones
    // meant `{ operation: '' }` admitted every request while looking like a
    // matched scope. Only `{}` was refused.
    assert.equal(scopeMatches({ operation: 'deploy' }, { operation: 'deploy', target_uri: '' }).ok, true);
    assert.equal(scopeMatches({ operation: 'deploy' }, { operation: '' }).ok, false);
    assert.equal(scopeMatches({ operation: 'deploy' }, { operation: '' }).reason, REASON.INTENT_UNRESOLVED);
    assert.equal(scopeMatches({ operation: 'deploy' }, { a: '', b: null }).reason, REASON.INTENT_UNRESOLVED);
  });
});

// ── THE MIDDLEWARE ───────────────────────────────────────────────────────────
describe('gateway verifier — the Express middleware', () => {
  const run = (mw, req) => new Promise((resolve) => {
    let nexted = false;
    const res = {
      statusCode: null,
      status(c) { this.statusCode = c; return this; },
      json(body) { resolve({ nexted, statusCode: this.statusCode, body }); return this; },
    };
    mw(req, res, () => { nexted = true; resolve({ nexted: true, statusCode: null, body: null, req }); });
  });

  it('calls next() and attaches the verdict on a valid request', async () => {
    const mw = gatewayVerifier({ keyring, resolveIntent: () => INTENT });
    const req = { headers: headersFor(issued()) };
    const out = await run(mw, req);
    assert.equal(out.nexted, true);
    assert.equal(req.coderifts.allow, true);
  });

  it('responds 403 with the named reason on refusal', async () => {
    const mw = gatewayVerifier({ keyring, resolveIntent: () => INTENT });
    const out = await run(mw, { headers: {} });
    assert.equal(out.nexted, false);
    assert.equal(out.statusCode, 403);
    assert.equal(out.body.reason, REASON.RECEIPT_MISSING);
  });

  it('a THROWING resolveIntent refuses — it never admits', async () => {
    const mw = gatewayVerifier({
      keyring, resolveIntent: () => { throw new Error('route table unavailable'); },
    });
    const out = await run(mw, { headers: headersFor(issued()) });
    assert.equal(out.nexted, false);
    assert.equal(out.body.reason, REASON.INTENT_UNRESOLVED);
  });

  it('construction refuses without a keyring or a resolver', () => {
    assert.throws(() => gatewayVerifier({ resolveIntent: () => INTENT }), /keyring is required/);
    assert.throws(() => gatewayVerifier({ keyring }), /resolveIntent\(req\) is required/);
  });
});

// ── C-ROUTE ──────────────────────────────────────────────────────────────────
describe('gateway verifier — customer-hosted, no CodeRifts dependency', () => {
  it('declares zero dependencies', () => {
    assert.deepEqual(require('../package.json').dependencies || {}, {});
  });

  it('the verify core is VENDORED, not imported from a package', () => {
    const src = require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'src', 'index.js'), 'utf8',
    );
    assert.match(src, /require\('\.\/verify\.js'\)/);
    assert.match(src, /require\('\.\/from-dsse\.js'\)/);
    assert.doesNotMatch(src, /require\('@coderifts\//);
  });

  it('THE CHECK PATH IS OFFLINE — proven by making any network call throw', () => {
    // MEASURED: a source scan is the wrong instrument here. verify.js carries
    // KEY-LOADING helpers (fetchKeyInfo / loadKeyring) that do fetch a registry
    // over HTTP — the gateway path never calls them, because the keyring is
    // pinned and passed in. Grepping the file therefore reports a network call
    // that the check never makes. Behaviour is the honest test.
    const realFetch = globalThis.fetch;
    globalThis.fetch = () => { throw new Error('the check path made a network call'); };
    try {
      const v = checkRequest({ headers: headersFor(issued()), intended: INTENT, keyring });
      assert.equal(v.allow, true, JSON.stringify(v));
      const d = checkRequest({ headers: {}, intended: INTENT, keyring });
      assert.equal(d.allow, false);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
