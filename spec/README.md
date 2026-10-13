# solid — Quint formal model

Executable specification of the solid authorization-code + refresh-token
lifecycle, formalizing the security core of `zntr.io/solid`'s strict
profile (PAR → authorize → code → redeem → refresh → revoke).

All models re-synchronized against the code on 2026-10-13 (post
`7b68fc2` adversarial hardening + the atomic token-consume fix); see the
per-model "Sync note" entries and the KNOWN SPEC/CODE DIVERGENCE blocks
in each spec header for what changed and what remains a code-side
decision.

## Files

- `solid.qnt` — the model: state, actions, invariants, witnesses.
- `solid_test.qnt` — deterministic scenario tests (run: `quint test
  solid_test.qnt --main solidTest`).
- `xaa.qnt` — the Cross-App Access / ID-JAG model (XAA protocol).
- `xaa_test.qnt` — XAA deterministic scenario tests (run: `quint test
  xaa_test.qnt --main xaaTest`).
- `clientcredentials.qnt` / `clientcredentials_test.qnt` — machine-to-machine
  grant (run: `quint test clientcredentials_test.qnt --main clientcredentialsTest`).
- `devicecode.qnt` / `devicecode_test.qnt` — device_code grant, RFC 8628/10027
  (run: `quint test devicecode_test.qnt --main devicecodeTest`).
- `tokenexchange.qnt` / `tokenexchange_test.qnt` — token_exchange access-token
  path, RFC 8693 (run: `quint test tokenexchange_test.qnt --main tokenexchangeTest`).
- `ciba.qnt` / `ciba_test.qnt` — CIBA flow, OpenID CIBA Core 1.0 + RFC 9700
  §4.12 (run: `quint test ciba_test.qnt --main cibaTest`).

## Source correspondence map

### solid ( `solid.qnt` )

| Quint action | solid source |
|---|---|
| `registerPAR` | `server/services/authorization/service.go` `Register` (PAR endpoint) |
| `authorizePAR` / `authorizeDirect` | `service.go` `Authorize` (PAR burn-after-read; pairwise encoding in `server/httpkit/authorization.go` wired from `examples/authorizationserver/main.go`) |
| `redeem` | `server/services/token/grant_authorization_code.go` `authorizationCode` |
| `refresh` | `server/services/token/grant_refresh_token.go` `refreshToken` (+ `revokeGrantFamily`, atomic `ConsumeIfActive` consume) |


### XAA ( `xaa.qnt` )

| Quint action | solid source |
|---|---|
| `ssoLogin` | abstract SSO output (subject refresh token, as seeded by `integration/idjag_adversarial_test.go` `xaaSeedRefreshToken`) |
| `exchangeForJag` | `server/services/token/grant_token_exchange_idjag.go` `tokenExchangeIDJAG` (+ `sdk/idjag` signer) |
| `forgeJag` / `foreignIssuerJag` | attacker model (crypto abstraction: `authentic` iff genuinely signed) |
| `redeemJag` | `server/services/token/grant_jwt_bearer.go` `jwtBearer` (+ `sdk/idjag/verifier.go` `Verify`) |

Verified properties:

| ID | Property | RFC/draft | Status |
|---|---|---|---|
| J1 | `inv_signatureTrust` — every minted access token derives from an authentic ID-JAG of a trusted issuer | 7523 §3.4, chain §2.1 | ✔ |
| J2 | `inv_noGrantLaundering` — grants minted for another AS never mint tokens at the RAS | chain §2.3.3 | ✔ |
| J3 | `inv_clientContinuity` — redeemer == the client the IdP vouched for | ID-JAG §4.4.1 | ✔ |
| J4 | `inv_subjectTranscription` — token subject is the pairwise grant subject; raw user ids never cross the boundary | chain §2.5 | ✔ |
| J5 | `inv_noScopeEscalation` — token scope ⊆ grant scope ⊆ SSO context; an empty request carries the full granted context | chain §2.5 | ✔ |
| J6 | `inv_dpopKeyContinuity` — key-bound grants mint key-bound tokens with the same key (non-vacuous after the 2026-10-13 quantifier fix) | ID-JAG §9.8.1.2 | ✔ |
| J7 | `inv_noRefreshFromBearer` — jwt-bearer redemptions mint no refresh tokens (structural) | ID-JAG §4.4.3, chain §5.4 | ✔ |
| J8 | redemption guards: grant capability, 10-minute assertion lifetime cap, RFC 8707 resource/audience registry, DPoP client-policy binding, self-issuance rejection, authorization_details subset narrowing | 7523 §3, 8707 §2, 9449 | ✔ |

Verification: `quint run` (10000 traces × 41 steps, no violations) with
witnesses all live (`w_tokenMinted` 33.4%, attack-surface witnesses ~96% —
the attacker actions fire constantly; the guards are what stop them).
Deterministic tests: 26/26 passing (happy path, scope narrowing and
escalation at both hops, empty-scope carries context, forged signature,
untrusted issuer, grant laundering, expiry, 10-min lifetime cap, client
impersonation, DPoP wrong/matching proof, RAS DPoP policy binding,
subject-token client binding + refresh-token-type dispatch, per-audience
client mapping (mapped at AS_B, unmapped at AS_C), resource registry
validation, replay-until-expiry, pairwise-per-target disjointness,
authorization_details widening rejected).

Modeling finding fixed during verification: the first draft of
`redeemJag` accepted redemption at any `atAS`, letting a grant minted for
AS_C "redeem at AS_C" while the tracked state was AS_B's — the same
audience-laundering class J2 guards against. The guard `atAS == AS_B` (the
modeled stack) now pins it, matching the implementation where the
verifier's `localIssuer` is fixed at wiring time.

Sync note (2026-10-13): J6's quantifier bug (implication inside the
exists — vacuous in most states) was fixed and re-verified. New guards
from the drift analysis are encoded (J8); the three boundary laxities the
code still has (exp == now accepted, RT exp == now accepted, future-iat
accepted — each laxer than RFC 7523 §3) are kept STRICT in the spec and
listed under KNOWN SPEC/CODE DIVERGENCE in the spec header for the code
owner to decide.

### solid properties ( `solid.qnt` )

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

Deterministic tests: 19/19 passing, covering the happy path, code
single-use (including the burn-before-check ordering: a wrong verifier or
wrong client still burns the code), PAR burn-after-read, client binding,
refresh rotation (atomic consume: the rotated RT lands CONSUMED), replay
(of a CONSUMED token) revokes the family, refresh DPoP key-swap rejected
(burn-first still consumes), refresh scope narrowing + escalation
disabled, capability gating, owner-only revocation, pairwise
disjointness, consent-gated offline_access, the no-openid mint-nothing
path, and the DPoP code binding (bound-code redeem with matching key,
key-swap rejected, no-proof rejected — the strict profile requires a
confirmation at every redemption, key continuity through refresh).

Sync note (2026-10-13): the refresh action now encodes the atomic
`ConsumeIfActive` rotation (ACTIVE→CONSUMED compare-and-set; a replay of
a CONSUMED token triggers family revocation) and the RFC 9449 §8 jkt
continuity + RFC 6749 §6 scope-narrowing guards; redeem encodes the
unconditional DPoP confirmation requirement (`enforceSenderBinding`).


### client_credentials ( `clientcredentials.qnt` )

Source: `server/services/token/grant_client_credentials.go` (inline
guard chain — NOT the shared `validateGrantPreamble`; sender binding runs
first) + `grants.go` `enforceSenderBinding`.

| ID | Property | RFC | Status |
|---|---|---|---|
| CC1 | no `authorization_details` ever minted; scope ⊆ registered scope, unrestricted when the registration is open-ended (fail-closed consent authority) | 9396 | ✔ |
| CC2 | no refresh token can ever exist (structural) | v2.1 §4.4.3 | ✔ |
| CC3 | token subject == authenticated client id (impersonation impossible) | 6749 §4.4.2 | ✔ |
| CC4 | tokens mint only for CONFIDENTIAL/CREDENTIALED clients with the client_credentials capability | 6749 §2.1 | ✔ |
| CC5 | sender-binding policy (one-sided, as enforced): DPoP-bound client ⇒ token jkt ≠ 0; TLS-bound client ⇒ x5t present; an unbound client's presented proof is carried verbatim | 9449, 8705 §3 | ✔ |
| CC6 | each mint gets a fresh GrantId (distinct families) | 9700 §4.14.2 | ✔ |
| CC7 | minted audience is a registry-resolved resource indicator (or the validated audience parameter, or empty) — never a verbatim attacker string | 8707 §2 | ✔ |

Verification: `quint run` (10000-trace sweeps, no violations; witnesses
100%/99.2%/94.9%) and deterministic tests: 18/18 passing (happy paths,
public/unknown/non-capable client rejection, details smuggling
fail-closed, DPoP missing-proof rejection, unbound-with-proof ACCEPTED
(pins the one-sided `enforceSenderBinding` posture), scope smuggling,
open-ended registration unrestricted, fresh grant family, structural
no-RT, resource/audience registry validation, resource-over-audience
precedence).

Sync note (2026-10-13): the mint guard now encodes the RFC 8707
resource/audience registry validation and precedence, the TLS x5t branch
of `enforceSenderBinding`, and the open-ended-scope-registration escape.
The previous two-sided DPoP guard (unbound ⇒ no proof) encoded behavior
the code never had — the model now matches the one-sided implementation
(see the KNOWN SPEC/CODE DIVERGENCE note in the spec header).

### device_code ( `devicecode.qnt` )

Source: `server/services/device/service.go` (authorization + approval/
deny), `server/services/token/grant_device_code.go` (poll), `grants.go`
`enforceSenderBinding` / `enforcePollInterval`.

| ID | Property | RFC | Status |
|---|---|---|---|
| D1 | a device session mints at most one token (atomic consume; second poll ⇒ invalid_grant) | 8628 §3.5 | ✔ |
| D2 | no refresh token ever; `offline_access` stripped at issue | 10027 §6.1.9/6.1.10 | ✔ |
| D3 | token subject == the subject set at VALIDATE time (approver binding) | 8628 §3.3 | ✔ |
| D4 | token client == the session's requesting client | 8628 §3.4 | ✔ |
| D5 | poll throttle: interval monotone (+5 per slow_down); slow_down never advances lastPolledAt; the first poll of a fresh session is always admissible | 8628 §3.5 | ✔ |
| D6 | authorization_details fixed at device-auth time (no token-endpoint narrowing) and registry-validated at issue; audience frozen at issue (RFC 8707) | 9396, 8707 | ✔ |
| D7 | user-code brute-force latch: ≥5 failures by a subject within the 5-minute sliding window block further approvals; the latch decays after the window | — | ✔ |
| D8 | sender binding is client-registration policy (`dpop_bound_access_tokens` ⇒ proof required at poll), not session-bound; the presented confirmation is carried verbatim | 9449 | ✔ |

Verification: `quint run` (10000-trace sweep at 40 steps, no violations;
all 11 witnesses reachable) and deterministic tests: 31/31 passing
(happy path, single-use, pending/slow_down throttle cycles, deny
(unthrottled, un-expiry-checked — encoded faithfully), expiry as no-op
with the lenient `now == expiresAt`-is-live boundary, wrong client,
unknown code, capability gating, details fail-closed/frozen/registry-
validated, DPoP client-policy binding (bound without proof rejected,
bound with proof mints, unbound mints unkeyed), brute-force latch,
latch decay after the window, DENIED terminal, session independence, the
mint-inside-slow_down-window pin).

Sync note (2026-10-13): the phantom session-bound DPoP jkt mechanism was
removed (no such field exists in `DeviceCodeSession`); the real guard is
client-policy `enforceSenderBinding`. Expiry is lenient at equality;
the deny path checks only the PENDING transition; the brute-force latch
is a sliding 5-minute window, not absorbing. See the DIVERGENCES block in
the spec header.

### token_exchange ( `tokenexchange.qnt` )

Source: `server/services/token/grant_token_exchange.go` (access-token
subject path; the ID-JAG sub-path is covered by `xaa.qnt`).

| ID | Property | RFC | Status |
|---|---|---|---|
| T1 | subject preservation: minted subject == subject token's subject (never the exchanging client or actor) | 8693 §4.1.3.4 | ✔ |
| T2 | client attribution: minted exchanging-client == authenticated requester | 8693 §4.1.3.3 | ✔ |
| T3 | scope narrowing: minted scope ⊆ subject token scope; never widens | 8693 §4.1.3.3 | ✔ |
| T4 | may_act gate: gated tokens exchange only via a listed actor | 8693 §5 | ✔ |
| T5 | act chain == [actor.subject] ++ actor chain, depth ≤ 3 fail-closed | 8693 §4.4 | ✔ |
| T6 | cnf continuity: exchange cannot strip or swap the subject token's DPoP binding | 9449 §8 | ✔ |
| T7 | audience only ever a registry-resolved URN, never a verbatim request value | 8707 §2 | ✔ |
| T8 | no RT from exchange; authorization_details carried verbatim from the exchange request (mocked processing — RS evaluates) | 9396 §6/§7 | ✔ |

Verification: `quint run` (500-trace sweep at 30 steps, no violations; witnesses
39–100%) and exhaustive bounded model checking (`quint verify` / Apalache,
depth 5 — `The outcome is: NoError`). Deterministic tests: 20/20 passing
(plain/actor exchanges, may_act listed vs non-listed vs required, jkt
carried/swapped/stripped, scope narrowing vs escalation, unknown audience,
chain depth 3-OK / 4-rejected, details carried verbatim, capability,
requested type, RT never).

### CIBA ( `ciba.qnt` )

Source: `server/services/backchannel/service.go` (bc-authorize + approval),
`server/services/token/grant_ciba.go` (poll), `grants.go`
(`enforceSenderBinding`, `enforcePollInterval`).

| ID | Property | RFC | Status |
|---|---|---|---|
| B1 | session single-use: one token per auth_req_id; replay indistinguishable from unknown (invalid_grant) | CIBA §10.2 | ✔ |
| B2 | no refresh token ever; offline_access never on a minted token | 9700 §4.12.2 | ✔ |
| B3 | subject binding: minted subject == hint-resolved subject (approver substitution rejected at Validate); mints only from VALIDATED | CIBA §8/10.3 | ✔ |
| B4 | client binding: wrong-client poll mints nothing; token client == session client | CIBA §10.2 | ✔ |
| B5 | DPoP continuity: session-bound jkt ⇒ matching proof required and carried into the token | 9449 §10 | ✔ |
| B6 | details fixed at bc-authorize time | 9396 | ✔ |
| B7 | poll throttle: interval monotone (+5 per slow_down); slow_down never advances lastPolledAt; the FIRST poll of a fresh session is always admissible (Go zero-value LastPolledAt sentinel) | CIBA §8.4.1 | ✔ |
| B8 | no token from PENDING/DENIED/expired sessions (structural guard chain); expiry lenient at equality per code | CIBA §10 | ✔ |
| B9 | audience authority: minted audience is registry-resolved (unregistered audience burns the consumed session, invalid_target) | 8707 §2 | ✔ |
| B10 | sender-constrained policy, one-sided as enforced: DpopBoundAccessTokens client ⇒ jkt presented; TLS-bound client ⇒ x5t#S256 presented | 9449/8705/10027 | ✔ |

Verification: `quint run` (1000-trace sweep at 30 steps, no violations) and
deterministic tests: 51/51 passing (happy path, single-use, first-poll
admissible, pending/slow_down cycles and enforcement, deny — including
deny-after-expiry, expiry boundary at and past equality, subject-mismatch
rejection, wrong client, unknown auth_req_id, binding-message/
hint-cardinality/openid/subject-resolution rejections, signed-request
structural rules incl. aud-contains-issuer, DPoP match/mismatch/no-proof/
unbound, sender-binding dpop/tls rejection and verbatim carry, unregistered
audience burns session, offline stripping, details fixed, no RT).

Modeling findings pinned by the CIBA model: (1) a minting poll bypasses
`enforcePollInterval` — the interval check lives only in the PENDING branch
of the Go guard chain, so a VALIDATED session mints immediately even inside
a slow_down window (`mintBypassesThrottleTest`); (2) expiry is LENIENT at
equality in the code (only `expiresAt < now` is rejected —
`approveAtExpiryBoundaryOkTest` / `pollAtExpiryBoundaryMintsTest`); the
earlier "strict expiry" pin no longer matched the source. Divergences the
model documents but does NOT endorse (code-side decisions to revisit):
lenient expiry boundary, Deny ignoring the session clock, and the
post-consume audience check burning the session on invalid_target.

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

Re-verify the XAA model (`xaa.qnt`) before changing:
- `server/services/token/grant_token_exchange_idjag.go`
- `server/services/token/grant_jwt_bearer.go`
- `sdk/idjag/verifier.go`

Re-verify the client_credentials model (`clientcredentials.qnt`) before changing:
- `server/services/token/grant_client_credentials.go`
- `server/services/token/grants.go` (preamble, sender-binding policy)

Re-verify the device_code model (`devicecode.qnt`) before changing:
- `server/services/device/service.go`
- `server/services/token/grant_device_code.go`
- `server/services/token/poll_timing.go`

Re-verify the token_exchange model (`tokenexchange.qnt`) before changing:
- `server/services/token/grant_token_exchange.go`
- `server/services/token/authorization_details.go`

Re-verify the CIBA model (`ciba.qnt`) before changing:
- `server/services/backchannel/service.go`
- `server/services/token/grant_ciba.go`
- `server/services/token/poll_timing.go`
- `server/services/token/grants.go` (sender-binding policy, `enforcePollInterval`)

The spec is the ground truth. Never edit the spec to match broken code.
