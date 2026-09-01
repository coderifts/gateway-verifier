# Vendored verify core

This gateway verifier copies the public verifier. It does not `npm install` a CodeRifts-operated package and it does not fetch keys at verify time.

| File | Source | Revision |
|------|--------|----------|
| `src/verify.js` | `receipt-verifier/verify.js` | `ccc53f9a592aaa7f6072d5c80d724f36de30a8ab` |
| `src/arity.js` | `receipt-verifier/arity.js` | same |

SHA-256 of those copies at vendor time is in `src/VENDOR.sha256`, and `test/vendor-core.test.js` fails if the files drift from it. Do not edit the copied files in this tree; recopy from receipt-verifier.

`src/from-dsse.js` is a MIRROR of `receipt-verifier/to-dsse.js`'s `fromDSSE`, not a byte copy — it is pinned by its own constants test (`test/dsse-input.test.js`). Unpacking is not verification.
