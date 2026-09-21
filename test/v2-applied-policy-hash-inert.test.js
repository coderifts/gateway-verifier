/**
 * 1942 K-phase-1 — gateway grant verifier admits `applied_policy_hash` as inert.
 *
 * Dual-accept: (a) without the field still valid · (b) with the field valid and inert
 * · (c) a truly unknown field is still unknown_field.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  verifyExecutionGrant, V2_RESERVED_INERT, V2_REQUIRED_STRINGS, signingInputV2,
} = require('../src/verify-grant.js');

const KID = 'GW-APH-KEY';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const RING = new Map([[KID, { publicKey, status: null }]]);
const NOW = Date.UTC(2026, 8, 21, 12, 0, 0);
const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v)).digest('hex')}`;

const canon = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};

const BODY = Object.freeze({
  v: 'cr.exec.v2',
  kid: KID,
  grant_id: 'g-gw-aph-1',
  receipt_hash: sha('receipt'),
  tenant_id: 'tenant',
  executor_id: 'executor',
  adapter_id: 'adapter',
  operation: 'publish',
  target_uri: 'db://host/table',
  expected_state_token: 'state',
  after_payload_hash: sha('the authorized bytes'),
  nonce_hash: sha('nonce'),
  policy_hash: sha('policy'),
  audience_hash: sha('audience'),
  not_before: new Date(NOW - 1000).toISOString(),
  expires_at: new Date(NOW + 600000).toISOString(),
  max_attempts: 1,
});

const mint = (over = {}) => {
  const body = { ...BODY, ...over };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canon(body)}`, 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
};
const ask = (token, intended) => verifyExecutionGrant(token, {
  ctx: { keyring: RING, expectedKid: null }, now: NOW + 1, ...(intended ? { intended } : {}),
});
const verdict = (r) => `${r.valid}/${r.status}/${r.reason || '-'}`;
const INTENDED = { operation: 'publish', target_uri: 'db://host/table', after_payload: 'the authorized bytes' };

describe('gateway V2_RESERVED_INERT includes applied_policy_hash', () => {
  it('the name is reserved and not required', () => {
    assert.ok(V2_RESERVED_INERT.includes('applied_policy_hash'));
    assert.ok(!V2_REQUIRED_STRINGS.includes('applied_policy_hash'));
  });
});

describe('DUAL-ACCEPT (1942 verifier-admits)', () => {
  it('(a) a grant without the field still verifies', () => {
    assert.equal(verdict(ask(mint(), INTENDED)), 'true/GRANT_CURRENT/-');
  });

  it('(b) a grant carrying it verifies, and the value is not a gate', () => {
    const withField = ask(mint({ applied_policy_hash: sha('evaluated') }), INTENDED);
    assert.equal(verdict(withField), 'true/GRANT_CURRENT/-');
    assert.equal(withField.payload.applied_policy_hash, sha('evaluated'));
    assert.equal(
      verdict(ask(mint({ applied_policy_hash: sha('evaluated') }),
        { ...INTENDED, applied_policy_hash: sha('other') })),
      'true/GRANT_CURRENT/-',
    );
  });

  it('(c) a truly unknown field is still unknown_field', () => {
    assert.equal(verdict(ask(mint({ surprise: 'x' }))), 'false/MALFORMED/unknown_field');
  });
});

describe('signingInputV2 covers the whole body so the slot is signed', () => {
  it('a grant with and without the field sign different bytes', () => {
    const a = { ...BODY };
    const b = { ...BODY, applied_policy_hash: sha('evaluated') };
    assert.notEqual(signingInputV2(a), signingInputV2(b));
  });
});
