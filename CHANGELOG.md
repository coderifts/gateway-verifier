# Changelog

## 0.1.2 - 2026-09-21

Re-vendor `verify.js` and `verify-grant.js` from the signed receipt-verifier **v1.0.3** (peeled `523e0a2`). The grant verifier admits `applied_policy_hash` as `V2_RESERVED_INERT` (1942: not interpreted, not bound, not required). A truly unknown field is still `MALFORMED/unknown_field`. Pin digest in `src/VENDOR.sha256` names the tag. Not a first publish — 0.1.0 and 0.1.1 are already on the public npm registry.

## 0.1.1 - 2026-09-20

README states what a verification proves and what it does not. Version on the registry as of 2026-09-20.

## 0.1.0 - 2026-09-19

First public npm release of the customer-hosted gateway target-verifier. Offline, zero dependencies, keyring pinned by the operator.
