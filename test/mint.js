'use strict';

/**
 * Test-only receipt minter. Generates a real Ed25519 keypair and mints v4 receipts that verify.js
 * accepts BYTE-FOR-BYTE (same signed-input reconstruction + same canonical body_hash). This keeps
 * the verify.js crypto path 100% real in tests — only the key IDENTITY is a test key, never the
 * verification logic. NOT a *.test.js file, so the runner does not execute it directly.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256hex } = require('../src/verify');

const SIGNING_PREFIX = 'crchain.v1';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/** Canonical body_hash of an envelope exactly as verify.js step 6 recomputes it. */
function bodyHash(envelope) {
  const rest = { ...envelope };
  delete rest.receipt;
  delete rest.decision_body_hash;
  return 'sha256:' + sha256hex(canonicalJson(rest));
}

function newSigner(kid = 'test-k1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return { kid, publicKey, privateKey, publicKeyPem };
}

/**
 * Mint a v4 receipt bound to `envelope`. `overrides` can force fields (e.g. expires_at in the past,
 * or a wrong kid) for negative tests.
 */
function mintV4(signer, envelope, overrides = {}) {
  const payload = {
    v: 4,
    kid: overrides.kid || signer.kid,
    fp: overrides.fp || (envelope.fingerprint || envelope.input_fingerprint || ('sha256:' + 'a'.repeat(64))),
    prev: overrides.prev || 'null',
    caller: overrides.caller || 'bundle',
    ts: overrides.ts || '2026-07-26T00:00:00.000Z',
    reg: overrides.reg || 'r'.repeat(64),
    ir: overrides.ir || ('sha256:' + 'b'.repeat(64)),
    expires_at: overrides.expires_at || '2027-01-01T00:00:00.000Z',
    bh: overrides.bh || bodyHash(envelope),
  };
  const signedInput = `${SIGNING_PREFIX}|${payload.kid}|${payload.fp}|${payload.prev}|${payload.caller}|${payload.ts}|${payload.reg}|${payload.ir}|${payload.expires_at}|${payload.bh}`;
  const sig = crypto.sign(null, Buffer.from(signedInput, 'utf8'), signer.privateKey);
  return `${b64url(JSON.stringify(payload))}.${b64url(sig)}`;
}

/** Flip one byte of a token's signature segment -> signature no longer verifies. */
function tamperSignature(token) {
  const [body, sig] = token.split('.');
  const raw = Buffer.from(sig, 'base64url');
  raw[0] ^= 0xff;
  return `${body}.${b64url(raw)}`;
}

/** Write a loadKeyring-compatible registry file for a signer's public key. */
function writeKeyringFile(dir, signer, status = 'active') {
  const file = path.join(dir, 'test-keyring.json');
  fs.writeFileSync(file, JSON.stringify({
    keys: [{ kid: signer.kid, alg: 'Ed25519', status, public_key_pem: signer.publicKeyPem }],
  }) + '\n');
  return file;
}

/** A minimal decision_result envelope with a given execution_action/decision. */
function envelope({ execution_action = 'CONTINUE', decision = 'ALLOW', extra = {} } = {}) {
  return {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: 'dec_test',
    correlation_id: 'corr_test',
    fingerprint: 'sha256:' + 'c'.repeat(64),
    input_fingerprint: 'sha256:' + 'd'.repeat(64),
    summary: `${decision} — test`,
    decision_body_hash: null,
    receipt: null,
    ...extra,
  };
}

module.exports = { newSigner, mintV4, tamperSignature, writeKeyringFile, envelope, bodyHash };
