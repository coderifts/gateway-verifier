/**
 * Reference integration — a standalone authorization check over HTTP.
 *
 * Shaped for the ext-authz pattern (Envoy, and anything that can ask an external
 * service "may this request proceed"): the gateway forwards the ORIGINAL
 * request's headers, this answers 200 (forward it) or 403 (do not).
 *
 * Uses `node:http` only, so it runs in the same container as the gateway with no
 * package to install. It is a REFERENCE: read it, then wire the library into
 * whatever your gateway actually speaks.
 *
 * ── FAIL-CLOSED ON ITS OWN FAILURES ─────────────────────────────────────────
 * A check service that returned 200 when it could not decide would be worse than
 * absent: the gateway would forward on an error and the deployment would look
 * enforced. Every path here that cannot reach a verdict answers 403.
 */
'use strict';

const http = require('node:http');
const { checkRequest, REASON } = require('./index.js');

/**
 * @param {Map}      o.keyring        kid -> { publicKey, status, retired_at }
 * @param {Function} o.resolveIntent  (headersObject) -> the decision-envelope
 *                                    fields the request must match, or null to refuse
 */
function createExtAuthzServer({ keyring, resolveIntent, headerNames, now } = {}) {
  if (!keyring) throw new Error('createExtAuthzServer: keyring is required');
  if (typeof resolveIntent !== 'function') {
    throw new Error('createExtAuthzServer: resolveIntent(headers) is required');
  }

  return http.createServer((req, res) => {
    const answer = (code, body) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    try {
      let intended = null;
      try {
        intended = resolveIntent(req.headers);
      } catch (_) {
        intended = null;
      }
      const verdict = checkRequest({ headers: req.headers, intended, keyring, headerNames, now });
      return answer(verdict.allow ? 200 : 403, verdict);
    } catch (err) {
      // An unexpected throw is a refusal, never a pass.
      return answer(403, {
        allow: false,
        reason: REASON.VERIFIER_THREW,
        detail: String((err && err.message) || 'unknown').slice(0, 200),
      });
    }
  });
}

module.exports = { createExtAuthzServer };
