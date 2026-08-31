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
 *  -> verifyReceipt(token, { keyring }, { envelope, now })   ← the same checks
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

/** Header names. Overridable, because a gateway may already own a prefix. */
const DEFAULT_HEADERS = Object.freeze({
  receipt: 'x-coderifts-receipt',
  decision: 'x-coderifts-decision',
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

const deny = (reason, detail) => ({ allow: false, reason, ...(detail ? { detail } : {}) });

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
function checkRequest({ headers, intended, keyring, headerNames = DEFAULT_HEADERS, now } = {}) {
  const rawReceipt = headerValue(headers, headerNames.receipt);
  if (rawReceipt == null || rawReceipt === '') return deny(REASON.RECEIPT_MISSING);

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
    result = verifyReceipt(unwrapped.token, { keyring, expectedKid: null }, { envelope, now });
  } catch (err) {
    return deny(REASON.VERIFIER_THREW, String((err && err.message) || 'unknown').slice(0, 200));
  }
  if (!result || result.valid !== true) {
    return deny(REASON.RECEIPT_INVALID, result ? result.status : null);
  }

  const executionAction = typeof envelope.execution_action === 'string' ? envelope.execution_action : null;
  if (!executionAction || !PASSING_ACTIONS.has(executionAction)) {
    return deny(REASON.DECISION_NOT_ALLOW, executionAction);
  }

  const scope = scopeMatches(envelope, intended);
  if (!scope.ok) return { allow: false, reason: scope.reason, ...(scope.mismatches ? { mismatches: scope.mismatches } : {}) };

  return {
    allow: true,
    receipt_status: result.status,
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
  checkRequest,
  gatewayVerifier,
  scopeMatches,
  REASON,
  PASSING_ACTIONS,
  DEFAULT_HEADERS,
};
