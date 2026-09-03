/**
 * CodeRifts gateway verifier — reject a request unless it carries a receipt that
 * verifies AND whose scope matches what the request is asking to do.
 *
 * ── WHAT THIS IS ────────────────────────────────────────────────────────────
 * A TARGET VERIFIER. It runs in your gateway, checks evidence the caller
 * already holds, and forwards or refuses. It does not call CodeRifts, does not
 * analyse the request, and has no network dependency: verification is offline
 * against a keyring you pin.
 *
 * It is NOT an analysis service. Nothing here asks "is this change risky" — that
 * question is answered upstream, before the caller ever reaches you, and its
 * answer is the receipt this checks.
 *
 * ── THE FLOW, mirroring the Contract Gate ───────────────────────────────────
 *     read the receipt header
 *  -> unwrap a DSSE envelope if that is what arrived
 *  -> verifyReceipt(token, { ctx: { keyring }, envelope, now })   ← the same checks
 *  -> the decision must be a passing execution_action
 *  -> the scope must match THIS request
 *  -> otherwise 403 with a named reason
 *
 * ── A RECEIPT'S PRESENCE IS NOT A PASS ──────────────────────────────────────
 * Every step above can refuse. A header containing something receipt-shaped
 * gets you as far as parsing. A DSSE envelope unwraps but does not
 * self-authorize — nothing is verified while reading one; the signature is over
 * the compact bytes and is checked afterwards, the same as if the compact token
 * had arrived directly.
 *
 * ── WHY THE SCOPE CHECK IS SAFE ─────────────────────────────────────────────
 * The scope comes from the decision envelope, which the caller also supplies —
 * so on its own it would be caller-controlled and worthless. It is trustworthy
 * here only because verify step 6 binds the receipt to that exact envelope by
 * body hash: swap the envelope and the receipt stops verifying. The order
 * matters, and this module never scope-checks before verifying.
 */
'use strict';

const { verifyReceipt } = require('./verify.js');
const { unwrapReceiptInput } = require('./from-dsse.js');
const { buildDenyRemedy, denyErrorForReason } = require('./deny-remedy.js');
const { verifyExecutionGrant, receiptDigest } = require('./verify-grant.js');

/** Header names. Overridable, because a gateway may already own a prefix. */
const DEFAULT_HEADERS = Object.freeze({
  receipt: 'x-coderifts-receipt',
  decision: 'x-coderifts-decision',
  /**
   * OPTIONAL execution grant (1307).
   *
   * MEASURED before this: this verifier read a receipt and a decision envelope and nothing else. A
   * receipt records that a decision was issued; a grant is the permission to act on it, bound to
   * one executor, one target and one use.
   *
   * IT FITS THE REQUEST SHAPE, which was the open question. A compact grant is a base64url token of
   * the same order as the receipt already carried here — ~700 bytes against the 8 KB per-header
   * limit proxies typically enforce. Nothing about ext-authz prevented it; it simply was not read.
   *
   * ADDITIVE: absent → every existing verdict is byte-identical. Present → verified offline against
   * the same pinned keyring and BOUND to the receipt in the sibling header. `requireGrant` turns
   * absence into a refusal for operators who want the stronger posture.
   */
  grant: 'x-coderifts-grant',
});

/**
 * Execution actions that permit the request through.
 *
 * MIRRORED from the Contract Gate. `CONTINUE_WITH_MONITORING` passes on the
 * caller's claim: this verifier does not check that a monitoring sink is
 * actually wired, and says so in the result rather than implying it did.
 */
const PASSING_ACTIONS = new Set(['CONTINUE', 'CONTINUE_WITH_MONITORING']);

/** Named refusal reasons. A gateway logs these; they are part of the contract. */
const REASON = Object.freeze({
  RECEIPT_MISSING: 'receipt_missing',
  GRANT_MISSING: 'grant_missing',
  GRANT_INVALID: 'grant_invalid',
  GRANT_NOT_BOUND: 'grant_not_bound',
  DECISION_MISSING: 'decision_missing',
  DECISION_MALFORMED: 'decision_malformed',
  DSSE_MALFORMED: 'dsse_malformed',
  DSSE_UNSUPPORTED: 'dsse_unsupported',
  DSSE_PREDICATE_MISMATCH: 'dsse_predicate_mismatch',
  RECEIPT_INVALID: 'receipt_invalid',
  DECISION_NOT_ALLOW: 'decision_not_allow',
  SCOPE_MISMATCH: 'scope_mismatch',
  INTENT_UNRESOLVED: 'intent_unresolved',
  VERIFIER_THREW: 'verifier_threw',
});

/**
 * A refusal, plus the next step when this refusal has one.
 *
 * The remedy is ADDITIVE and attached after the verdict: `allow` and `reason`
 * are byte-identical to what this returned before it existed, so a caller that
 * branches on them is unaffected. A reason that maps to no error class carries
 * no remedy rather than a guessed one.
 */
/**
 * The decision's own remediation SUGGESTION, read from an envelope this process has
 * ALREADY VERIFIED (I-1288f).
 *
 * The step lives inside decision_result, so decision_body_hash covers it and the receipt
 * signs it — which is why a gateway may forward it without calling the issuer, and why
 * this must never run before verifyReceipt returned valid. An unsigned step is an
 * attacker-supplied instruction wearing the issuer's voice: the decision envelope arrives
 * in a REQUEST HEADER here, so anyone who can reach the gateway can write one.
 *
 * Shape and closed action set: coderifts-app schemas/decision-result.v1.producer.json
 * properties.next_agent_step. A step without an action is not a step (same rule as
 * contract-gate readNextAgentStep).
 */
const readNextAgentStep = (envelope) => {
  const step = envelope && typeof envelope === 'object' ? envelope.next_agent_step : null;
  if (!step || typeof step !== 'object' || Array.isArray(step)) return null;
  if (typeof step.action !== 'string' || step.action.length === 0) return null;
  return step;
};

const deny = (reason, detail, remedyFields, verifiedEnvelope) => {
  const out = { allow: false, reason, ...(detail ? { detail } : {}) };
  const error = denyErrorForReason(reason);
  if (error) {
    const remedy = buildDenyRemedy({ error, ...(remedyFields || {}) });
    if (remedy) out.remedy = remedy;
  }
  // TWO DIFFERENT NEXT STEPS, and they can co-occur. `remedy` is THIS GATEWAY's refusal
  // class (the grant is missing, invalid, or scoped elsewhere). `next_step` is the
  // DECISION's, signed by the issuer. Only call sites holding a VERIFIED envelope pass
  // the fourth argument; every pre-verification refusal passes nothing.
  const nextStep = readNextAgentStep(verifiedEnvelope);
  if (nextStep) out.next_step = nextStep;
  return out;
};

/** Case-insensitive header read that works on a plain object or a Headers-like. */
function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === 'function') return headers.get(name);
  const lower = String(name).toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      const v = headers[key];
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return null;
}

/** The decision envelope travels base64 JSON (headers are not a place for raw JSON). */
function parseDecision(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return { ok: false, reason: REASON.DECISION_MISSING };
  const text = raw.trim().startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
  try {
    const env = JSON.parse(text);
    if (!env || typeof env !== 'object' || Array.isArray(env)) {
      return { ok: false, reason: REASON.DECISION_MALFORMED };
    }
    return { ok: true, envelope: env };
  } catch (_) {
    return { ok: false, reason: REASON.DECISION_MALFORMED };
  }
}

/**
 * Does the receipt's scope cover what this request is doing?
 *
 * `intended` is what the DEPLOYMENT says the request means. This library cannot
 * derive it: only you know that `POST /v1/orders/123/refund` is a `refund` on
 * `order:123`. A fixed method-to-operation table here would be a guess applied
 * to every customer, and a wrong guess admits requests.
 *
 * So an unresolved intent is a REFUSAL, not a skip. A verifier that waved a
 * request through because it could not work out what the request was would be
 * worse than no verifier: it would look like enforcement.
 */
function scopeMatches(envelope, intended) {
  if (!intended || typeof intended !== 'object') {
    return { ok: false, reason: REASON.INTENT_UNRESOLVED };
  }
  const mismatches = [];
  let compared = 0;
  for (const field of Object.keys(intended)) {
    const want = intended[field];
    // An empty expectation states nothing about that field, so it is skipped —
    // it must NOT read as a wildcard that the field matched.
    if (want === undefined || want === null || want === '') continue;
    compared += 1;
    const got = envelope[field];
    if (String(got) !== String(want)) {
      mismatches.push({ field, receipt: got === undefined ? null : String(got), request: String(want) });
    }
  }
  // COUNT WHAT WAS COMPARED, not what was supplied. `{}` and `{ operation: '' }`
  // are the same statement — nothing checkable — and an implementation that only
  // refused the first would admit every request under the second while looking
  // like it had matched a scope.
  if (compared === 0) return { ok: false, reason: REASON.INTENT_UNRESOLVED };
  return mismatches.length === 0 ? { ok: true } : { ok: false, reason: REASON.SCOPE_MISMATCH, mismatches };
}

/**
 * The decision. Pure: give it the headers and the intent, get allow/deny.
 *
 * @param {object}   o.headers    the request headers
 * @param {object}   o.intended   what the deployment says this request does,
 *                                as decision-envelope field names (e.g.
 *                                { operation: 'deploy', target_uri: 'api://x' })
 * @param {Map}      o.keyring    kid -> { publicKey, status, retired_at }
 * @param {object}  [o.headerNames]
 * @param {Date}    [o.now]
 */
function checkRequest({
  headers, intended, keyring, headerNames = DEFAULT_HEADERS, now,
  requireGrant = false, grantKeyring = null,
} = {}) {
  const rawReceipt = headerValue(headers, headerNames.receipt);
  const targetOf = (i) => (i && typeof i === 'object' && typeof i.target_uri === 'string'
    ? i.target_uri : null);
  if (rawReceipt == null || rawReceipt === '') {
    // No receipt was presented, so there is no fingerprint to report.
    return deny(REASON.RECEIPT_MISSING, undefined, { target: targetOf(intended) });
  }

  // Unwrap FIRST, verify after. Unwrapping checks no signature — a DSSE
  // envelope reaching this line has proven nothing yet.
  const unwrapped = unwrapReceiptInput(rawReceipt);
  if (!unwrapped.ok) {
    const code = String(unwrapped.code || '').toUpperCase();
    const reason = code === 'PREDICATE_MISMATCH' ? REASON.DSSE_PREDICATE_MISMATCH
      : code === 'UNSUPPORTED' ? REASON.DSSE_UNSUPPORTED
        : unwrapped.reason === 'missing_receipt' ? REASON.RECEIPT_MISSING : REASON.DSSE_MALFORMED;
    return deny(reason, unwrapped.detail);
  }

  const decision = parseDecision(headerValue(headers, headerNames.decision));
  if (!decision.ok) return deny(decision.reason);
  const envelope = decision.envelope;

  let result;
  try {
    // The same call the Contract Gate makes. Passing the envelope activates the
    // body-hash binding, which is what makes the scope check below meaningful.
    result = verifyReceipt(unwrapped.token, { ctx: { keyring, expectedKid: null }, envelope, now });
  } catch (err) {
    return deny(REASON.VERIFIER_THREW, String((err && err.message) || 'unknown').slice(0, 200));
  }
  if (!result || result.valid !== true) {
    return deny(REASON.RECEIPT_INVALID, result ? result.status : null, {
      target: targetOf(intended),
      fingerprint: typeof envelope.fingerprint === 'string' ? envelope.fingerprint : null,
      observed: { receipt_status: result ? result.status : null },
    });
  }

  const executionAction = typeof envelope.execution_action === 'string' ? envelope.execution_action : null;
  if (!executionAction || !PASSING_ACTIONS.has(executionAction)) {
    return deny(REASON.DECISION_NOT_ALLOW, executionAction, undefined, envelope);
  }

  const scope = scopeMatches(envelope, intended);
  if (!scope.ok) {
    const out = {
      allow: false,
      reason: scope.reason,
      ...(scope.mismatches ? { mismatches: scope.mismatches } : {}),
    };
    const error = denyErrorForReason(scope.reason);
    if (error) {
      const remedy = buildDenyRemedy({
        error,
        target: targetOf(intended),
        fingerprint: typeof envelope.fingerprint === 'string' ? envelope.fingerprint : null,
        observed: scope.mismatches ? { mismatches: scope.mismatches } : undefined,
      });
      if (remedy) out.remedy = remedy;
    }
    const nextStep = readNextAgentStep(envelope);
    if (nextStep) out.next_step = nextStep;
    return out;
  }

  // ── execution grant (1307) ────────────────────────────────────────────────────────────────
  //
  // LAST, after the receipt, the decision class and the scope. The grant is additional authority
  // over the same request, never a second door: a request whose receipt fails is refused on the
  // receipt no matter what grant it carries.
  const rawGrant = headerValue(headers, headerNames.grant);
  let grantStatus = null;
  if (rawGrant != null && rawGrant !== '') {
    let g;
    try {
      // MEASURED signature (verify-grant.js:227-233): (token, ctx, opts) — ctx carries
      // { keyring, expectedKid }, opts carries { now }. Folding `now` into ctx makes the ring
      // invisible to resolveEntry and every grant returns UNKNOWN_KEY.
      //
      // expectedKid null: accept any kid PRESENT IN THE PINNED RING. Rotation is additive; a kid
      // the ring does not carry is UNKNOWN_KEY, which is fail-closed.
      g = verifyExecutionGrant(
        String(rawGrant),
        { keyring: grantKeyring || keyring, expectedKid: null },
        { now },
      );
    } catch (err) {
      return deny(REASON.GRANT_INVALID, String((err && err.message) || 'verifier threw').slice(0, 200));
    }
    if (!g || g.valid !== true) {
      return deny(REASON.GRANT_INVALID, (g && g.status) || null, { target: targetOf(intended) });
    }
    // THE BINDING. A valid grant for a different receipt is two true documents about two different
    // things — and a proxy pairing any verified receipt with any verified grant would look complete.
    const boundTo = g.payload && (g.payload.receipt_digest || g.payload.receipt_hash);
    if (!boundTo || boundTo !== receiptDigest(unwrapped.token)) {
      return deny(REASON.GRANT_NOT_BOUND, g.status, { target: targetOf(intended) });
    }
    grantStatus = g.status;
  } else if (requireGrant === true) {
    return deny(REASON.GRANT_MISSING, null, { target: targetOf(intended) });
  }

  return {
    allow: true,
    receipt_status: result.status,
    // Null means ABSENT, not failed — an invalid grant never reaches this line.
    grant_status: grantStatus,
    execution_action: executionAction,
    receipt_form: unwrapped.form,
    // Named so a gateway operator is not left to infer it from a green result.
    monitoring_claim_unverified: executionAction === 'CONTINUE_WITH_MONITORING',
  };
}

/**
 * Express-style middleware. `resolveIntent(req)` is yours: it turns a request
 * into the decision-envelope fields that must match. Returning null/undefined
 * from it refuses the request rather than admitting it unchecked.
 */
function gatewayVerifier({ keyring, resolveIntent, headerNames = DEFAULT_HEADERS, now, onDeny } = {}) {
  if (!keyring) throw new Error('gatewayVerifier: keyring is required');
  if (typeof resolveIntent !== 'function') {
    throw new Error('gatewayVerifier: resolveIntent(req) is required — this library cannot guess '
      + 'what an HTTP route means in your domain, and guessing would admit requests');
  }
  return function coderiftsGatewayVerifier(req, res, next) {
    let intended = null;
    try {
      intended = resolveIntent(req);
    } catch (_) {
      intended = null;      // a throwing resolver refuses; it never admits
    }
    const verdict = checkRequest({ headers: req.headers, intended, keyring, headerNames, now });
    if (verdict.allow) {
      req.coderifts = verdict;
      return next();
    }
    if (typeof onDeny === 'function') return onDeny(verdict, req, res);
    res.status(403);
    return res.json({ error: 'coderifts_verification_failed', reason: verdict.reason, ...verdict });
  };
}

module.exports = {
  readNextAgentStep,
  checkRequest,
  gatewayVerifier,
  scopeMatches,
  REASON,
  PASSING_ACTIONS,
  DEFAULT_HEADERS,
};
