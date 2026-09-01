# CodeRifts gateway verifier

Reject an API request unless it carries a CodeRifts receipt that **verifies** and
whose **scope matches the request**.

Runs in your gateway. Offline, zero dependencies, keyring pinned by you.

---

## What this is

A **target verifier**. It checks evidence the caller already holds, then forwards
or refuses.

It is **not** an analysis service. Nothing here asks whether a request is risky —
that question is answered upstream, before the caller reaches you, and its answer
is the receipt this checks. If you are looking for the analysis step, it is a
different integration.

## Install

Copy `src/` into your gateway image, or `npm install` it from your own registry.
There are no dependencies and nothing to fetch at runtime.

## Use

```js
const { gatewayVerifier } = require('@coderifts/gateway-verifier');

app.use(gatewayVerifier({
  // kid -> { publicKey, status, retired_at }. YOU pin this.
  keyring: myKeyring,

  // What does this request mean in YOUR domain? Return the decision-envelope
  // fields that must match. Returning null refuses the request.
  resolveIntent: (req) => {
    const m = /^\/v1\/orders\/([^/]+)\/refund$/.exec(req.path);
    if (req.method === 'POST' && m) {
      return { operation: 'refund', target_uri: `order:${m[1]}` };
    }
    return null;          // an unmapped route is refused, not waved through
  },
}));
```

Headers the caller sends:

| header | contents |
| --- | --- |
| `X-CodeRifts-Receipt` | the compact receipt, or a DSSE/in-toto envelope |
| `X-CodeRifts-Decision` | the decision envelope, base64 JSON |

An `ext-authz`-style standalone check is in `src/ext-authz.js` for gateways that
call an external authorization service rather than running middleware.

## What it checks, in order

1. the receipt header is present;
2. a DSSE envelope is unwrapped to its compact token (**nothing is verified
   while unwrapping** — the signature is over the compact bytes and is checked
   next);
3. the decision envelope parses;
4. **the receipt verifies** against your keyring, including the body-hash binding
   to that exact decision envelope;
5. the `execution_action` is one that permits proceeding;
6. **the scope matches** what your `resolveIntent` says this request is doing.

Any step can refuse. Refusals are named:

`receipt_missing` · `decision_missing` · `decision_malformed` ·
`dsse_malformed` · `dsse_unsupported` · `dsse_predicate_mismatch` ·
`receipt_invalid` · `decision_not_allow` · `scope_mismatch` ·
`intent_unresolved` · `verifier_threw`

### The order is load-bearing

The scope comes from the decision envelope, which the **caller** supplies. On its
own that would be worthless. It is trustworthy only because step 4 binds the
receipt to that exact envelope by body hash: swap the envelope and the receipt
stops verifying. This never scope-checks before verifying.

### What a 403 body carries

| key | what it is |
|---|---|
| `remedy` | **this gateway's** refusal class — the grant is missing, invalid, or scoped elsewhere, and how to obtain one |
| `next_step` | **the decision's** own `next_agent_step`, verbatim from the `decision_result` envelope |

The two can co-occur; they answer different questions. `next_step` appears only when
the receipt verified: the field lives inside `decision_result`, so `decision_body_hash`
covers it and the receipt signs it. The envelope arrives in a request header, so anyone
who can reach the gateway can write one — a refusal reached before verification, or one
whose envelope was swapped after signing, renders no `next_step`.

This is the decision's remediation suggestion, not permission; branch on `execution_action`.

## What it proves

For an admitted request:

* a holder of a key **you pinned** signed a receipt;
* that receipt is bound to the decision envelope presented with it — not to some
  other decision;
* the decision's `execution_action` permits proceeding;
* the decision's scope matches what you said this request is doing.

## What it does NOT prove

* **That the action described actually happened, or will.** This gate is in front
  of the request; it does not observe the outcome.
* **That a monitoring sink is wired.** `CONTINUE_WITH_MONITORING` is admitted on
  the decision's claim. The result sets `monitoring_claim_unverified: true` —
  read it rather than assuming that half was checked.
* **That your route mapping is right.** `resolveIntent` is yours. If it says a
  destructive route is a read, this admits a receipt for a read. The verifier
  cannot check a mapping only you know.
* **That the caller is who they say.** This is authorization evidence, not
  authentication. Keep your existing authn.
* **That the key is uncompromised.** Everything reduces to "a holder of this key
  signed this". Custody is yours.

## Customer-hosted

You run it, in your gateway, against a keyring you pin. There is no call to
CodeRifts on the request path and no CodeRifts-operated service in the loop —
verification is a local signature check. If CodeRifts is unreachable, or gone,
this keeps working.

The verify core (`src/verify.js`, `src/arity.js`, `src/from-dsse.js`) is
**vendored**: copied in, not imported, so the artifact you audit is the artifact
that runs. The copied revision and the SHA-256 of each file are recorded in
[`VENDOR.md`](VENDOR.md) and `src/VENDOR.sha256`; `test/vendor-core.test.js`
fails if either file drifts from its pin, and separately re-checks the key-status
behaviour the pin exists to protect.

## Tests

```bash
npm test
```

## License

Apache-2.0
