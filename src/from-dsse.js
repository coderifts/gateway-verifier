/**
 * DSSE / in-toto envelope UNPACKING — MIRRORED from receipt-verifier/to-dsse.js
 * (`fromDSSE`). Not an npm import of receipt-verifier: this Action ships with
 * zero dependencies and vendors what it needs, the same discipline as
 * execution-grant-v2.js.
 *
 * Spec: RECEIPT_FORMAT.md §9 (DSSE / in-toto export). The constants below must
 * byte-match the source; dsse-input.test.js pins them.
 *
 * ── WHAT THIS DOES, AND WHAT IT EMPHATICALLY DOES NOT ───────────────────────
 * It UNPACKS. It returns the compact token that was wrapped, byte for byte, and
 * `verify.js verifyReceipt` then decides — the same checks, on the same bytes,
 * as if the compact token had arrived directly.
 *
 * NOTHING HERE VERIFIES. No signature is checked while reading an envelope. A
 * DSSE envelope arriving at the gate is not evidence of anything: an envelope
 * wrapping a receipt with a bad signature unpacks cleanly and then FAILS
 * verification, exactly as that compact token would have. The presence of a
 * standard container must never read as a pass.
 *
 * The signature travels in `signatures[0].sig` and is the compact token's own,
 * over the compact token's own bytes — which is why the payload segment is
 * carried verbatim rather than re-encoded (§9.4): re-serialising JSON is not
 * byte-stable, and a rebuilt payload would fail to verify for a reason that has
 * nothing to do with authenticity.
 */
'use strict';

const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const PREDICATE_TYPE = 'https://coderifts.com/attestations/agent-action-authorization/v1';

/** The compact forms an envelope may carry (RECEIPT_FORMAT.md §9.3). */
const FORM = Object.freeze({
  RECEIPT: 'crchain.v1',
  ATTESTATION: 'cr.exec.attest.v1',
});

class DsseError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'DsseError';
    this.code = code;
  }
}

/** Stable key order for the consistency comparison. Arrays keep their order. */
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = sortDeep(v[k]); return acc; }, {});
  }
  return v;
}

function decodePayload(encoded) {
  let obj;
  try {
    obj = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch (_) {
    throw new DsseError('payload segment is not base64url JSON', 'MALFORMED');
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new DsseError('payload is not a JSON object', 'MALFORMED');
  }
  return obj;
}

/**
 * Reassemble the compact token from a DSSE envelope.
 *
 * REFUSES rather than guesses. Every refusal is a case where returning a token
 * anyway would hand the gate bytes that do not correspond to the envelope a
 * human read.
 *
 * @param {object} envelope  a DSSE envelope
 * @returns {string} the compact token, byte-exact
 * @throws {DsseError} code MALFORMED | UNSUPPORTED | PREDICATE_MISMATCH
 */
function fromDSSE(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    throw new DsseError('fromDSSE: envelope must be an object', 'MALFORMED');
  }
  if (envelope.payloadType !== PAYLOAD_TYPE) {
    throw new DsseError(
      `fromDSSE: unsupported payloadType ${JSON.stringify(envelope.payloadType)}`, 'UNSUPPORTED',
    );
  }
  let statement;
  try {
    statement = JSON.parse(Buffer.from(String(envelope.payload), 'base64').toString('utf8'));
  } catch (_) {
    throw new DsseError('fromDSSE: payload is not base64 JSON', 'MALFORMED');
  }
  if (!statement || statement.predicateType !== PREDICATE_TYPE) {
    throw new DsseError(
      `fromDSSE: unsupported predicateType ${JSON.stringify(statement && statement.predicateType)}`,
      'UNSUPPORTED',
    );
  }
  const p = statement.predicate || {};
  const c = p.compact || {};
  const sigs = Array.isArray(envelope.signatures) ? envelope.signatures : [];
  if (sigs.length !== 1 || !sigs[0] || typeof sigs[0].sig !== 'string' || !sigs[0].sig) {
    throw new DsseError('fromDSSE: exactly one signature with a sig is required', 'MALFORMED');
  }
  if (typeof c.encoded_payload !== 'string' || !c.encoded_payload) {
    throw new DsseError('fromDSSE: predicate.compact.encoded_payload missing', 'MALFORMED');
  }

  // The predicate carries the payload twice — preserved bytes and decoded
  // fields. If they disagree, the readable half describes something the signed
  // half does not contain, and a reader without a CodeRifts verifier would
  // believe the readable half. Refuse instead (RECEIPT_FORMAT.md §9.7).
  let decoded;
  try {
    decoded = decodePayload(c.encoded_payload);
  } catch (err) {
    throw new DsseError(`fromDSSE: ${err.message}`, 'MALFORMED');
  }
  if (JSON.stringify(sortDeep(decoded)) !== JSON.stringify(sortDeep(p.fields || {}))) {
    throw new DsseError(
      'fromDSSE: predicate.fields does not match predicate.compact.encoded_payload — '
      + 'the readable half of this envelope disagrees with the signed half',
      'PREDICATE_MISMATCH',
    );
  }

  const sig = sigs[0].sig;
  if (c.form === FORM.ATTESTATION) {
    if (!c.tag || !c.kid) {
      throw new DsseError('fromDSSE: attestation form needs compact.tag and compact.kid', 'MALFORMED');
    }
    return [c.tag, c.kid, c.encoded_payload, sig].join('|');
  }
  if (c.form === FORM.RECEIPT) {
    return `${c.encoded_payload}.${sig}`;
  }
  throw new DsseError(`fromDSSE: unknown compact form ${JSON.stringify(c.form)}`, 'UNSUPPORTED');
}

/**
 * Is this input a DSSE envelope rather than a compact token?
 *
 * Keyed on `payloadType`, which is the envelope's own discriminator — not on
 * "does it look like JSON". A compact receipt is `<b64url>.<b64url>` and a
 * compact attestation is pipe-delimited; neither can be mistaken for an object
 * carrying an in-toto payloadType.
 */
function looksLikeDSSE(input) {
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    return input.payloadType === PAYLOAD_TYPE;
  }
  if (typeof input === 'string') {
    const t = input.trim();
    if (!t.startsWith('{')) return false;      // a compact token never does
    try {
      const parsed = JSON.parse(t);
      return !!parsed && typeof parsed === 'object' && parsed.payloadType === PAYLOAD_TYPE;
    } catch (_) {
      return false;
    }
  }
  return false;
}

/**
 * The receipt-input boundary: accept EITHER form and hand back the compact token.
 *
 * A DSSE envelope may arrive as an object or as its JSON text — an external
 * emitter puts whichever its transport gives it, and refusing one of the two
 * would be a format rule nobody stated.
 *
 * @returns {{ ok: true, token: string, form: 'compact'|'dsse' }
 *          |{ ok: false, reason: string, code: string }}
 */
function unwrapReceiptInput(input) {
  if (!looksLikeDSSE(input)) {
    if (typeof input === 'string' && input.length > 0) {
      return { ok: true, token: input, form: 'compact' };
    }
    return { ok: false, reason: 'missing_receipt', code: 'MALFORMED' };
  }
  const envelope = typeof input === 'string' ? JSON.parse(input) : input;
  try {
    return { ok: true, token: fromDSSE(envelope), form: 'dsse' };
  } catch (err) {
    // Named, not swallowed: an operator needs to know the envelope was the
    // problem rather than the receipt inside it.
    return {
      ok: false,
      reason: `dsse_${String(err && err.code ? err.code : 'ERROR').toLowerCase()}`,
      code: (err && err.code) || 'ERROR',
      detail: err && err.message,
    };
  }
}

module.exports = {
  fromDSSE,
  looksLikeDSSE,
  unwrapReceiptInput,
  DsseError,
  PAYLOAD_TYPE,
  PREDICATE_TYPE,
  FORM,
};
