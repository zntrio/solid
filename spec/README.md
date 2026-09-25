# solid — Quint formal model

Executable specification of the solid authorization-code + refresh-token
lifecycle, formalizing the security core of `zntr.io/solid`'s strict
profile (PAR → authorize → code → redeem → refresh → revoke).

## Files

- `solid.qnt` — the model: state, actions, invariants, witnesses.
- `solid_test.qnt` — deterministic scenario tests (run: `quint test
  solid_test.qnt --main solidTest`).

## Source correspondence map

| Quint action | solid source |
|---|---|
| `registerPAR` | `server/services/authorization/service.go` `Register` (PAR endpoint) |
| `authorizePAR` / `authorizeDirect` | `service.go` `Authorize` (PAR burn-after-read; pairwise encoding from `examples/authorizationserver/handlers/authorization.go`) |
| `redeem` | `server/services/token/grant_authorization_code.go` `authorizationCode` |
| `refresh` | `server/services/token/grant_refresh_token.go` `refreshToken` (+ `revokeGrantFamily`) |

## Verified properties

| ID | Property | RFC | Status |
|---|---|---|---|
| I1 | `inv_codeSingleUse` — a grant family receives at most one code-minted AT and one code-minted RT | 9700 §4.5 | ✔ |
| I2 | `inv_grantPurity` — one client / subject / user per GrantId family | 9700 §4.14.2 | ✔ |
| I3 | `inv_singleActiveRT` — at most one ACTIVE refresh token per family | 9700 §4.14.2 | ✔ |
| I4 | `inv_replayRevokesFamily` — RT replay ⇒ entire family revoked | 9700 §4.14.2 | ✔ |
| I5 | `inv_pairwiseNoCrossClientLinkage` — pseudonyms of different clients never collide | OIDC pairwise | ✔ |
| I6 | `inv_pairwiseSubjectInjective` — same pseudonym at a client ⇒ same user | OIDC pairwise | ✔ |
| I7 | `inv_dpopKeyContinuity` — every token of a grant family carries the key the code was bound to at authorization time | 9449 §10 | ✔ |

Verification: sampled simulation (`quint run`, no violations, 70k+ traces
incl. 120-step sweeps) and exhaustive bounded model checking (`quint verify`
/ Apalache, depth 5 — full lifecycle chain, `The outcome is: NoError`).

Witnesses (reachability of each action's effect): `w_parRegistered` 99.9%,
`w_codeIssued` 99.98%, `w_redeemed` 17.4%, `w_redeemedWithRT` 4.2%,
`w_dpopBoundGrantMinted` 14.1%, `w_refreshed` 0.24%, `w_replayDetected`
17.5%, `w_revoked` 17.4% — all non-zero, no dead actions.

Deterministic tests: 17/17 passing, covering the happy path, code
single-use (including the burn-before-check ordering: a wrong verifier or
wrong client still burns the code), PAR burn-after-read, client binding,
refresh rotation, replay-revokes-family, capability gating, owner-only
revocation, pairwise disjointness, consent-gated offline_access, the
no-openid mint-nothing path, and the DPoP code binding (bound-code redeem
with matching key, key-swap rejected, no-proof rejected, key continuity
through refresh).

## Deliberate abstractions

- **Cryptography**: PKCE S256 is an injective abstract function
  (`challengeOf`); signatures/DPoP/JARM/JWKS are assumed correct.
- **Expiry**: code TTL (60s) and RT expiry manifest as "absent from
  storage" — conflated with single-use exactly as in the implementation
  (in-memory TTL cache, lazy `ErrNotFound`).
- **Client authentication**: abstracted as a closed client registry with
  per-client capabilities (`grants`, `redirectUris`, pairwise `sector`).
- **Replay/monotonicity**: DPoP jti store and client-assertion jti burn are
  out of scope (separate mechanisms, verified independently).
- **Storage**: abstract maps keyed by fresh counters (freshness of random
  ids assumed — the model never reuses a code/token id).

## Findings → fixes (2026-09-25)

Four gaps surfaced by the initial modeling were fixed in code; the model
now encodes the enforced behavior:

| Finding | Fix |
|---|---|
| F1: `GrantAuthorizationCode.DpopJkt` parsed but never checked | `grant_authorization_code.go`: session `confirmation.jkt` (set at authorize time) MUST equal the grant's DPoP-verified `dpop_jkt` — constant-time compare, `invalid_grant` otherwise. |
| F2: PAR `RegistrationRequest.Confirmation` dropped | `service.go` `Register`: PAR-confirmed jkt is stamped into the stored request's `dpop_jkt` (new `AuthorizationRequest.dpop_jkt` field, RFC 9449 §10), which `Authorize` persists into the code session `confirmation`. |
| F3: PAR consume was Get-then-Delete (non-atomic) | `storage.AuthorizationRequestReader` gains atomic `DeleteAndGet`; `Authorize` consumes via it; inmemory implements it on `ttlCache.DeleteAndGet`. |
| F4: `resource` indicators unvalidated in code grant | `grant_authorization_code.go`: each `request.resource` is resolved via `ResourceReader`; unknown ⇒ `invalid_target` (RFC 8707 §2). |

## When to update

Re-verify this spec (typecheck → run invariants/witnesses → run tests, and
optionally `quint verify` for exhaustive bounded model checking) **before**
changing:
- `server/services/token/grant_authorization_code.go`
- `server/services/token/grant_refresh_token.go`
- `server/services/authorization/service.go`
- `server/storage/api.go` (authorization-request contract)

The spec is the ground truth. Never edit the spec to match broken code.
