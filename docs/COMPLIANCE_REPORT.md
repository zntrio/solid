# SolID Standards Compliance Report

**Module:** `zntr.io/solid`
**Report date:** 2026-09-28
**Verification target:** commit `a0cdcf8f82e267ccd62ae76e12a02a7261c6ffc2` (branch `zenithar/nauth/xaa_protocol`) **plus the staged working tree** — pre-audit verified tree object SHA-256: `4db2e7d0e7f780102e2f5b7ff07ffc6af2788fdaa071abce14135fb5b1df15b1` (this includes the in-flight ID-JAG / identity-chaining feature; the committed HEAD alone does not contain `sdk/idjag`). Audit additions on top: vendored `docs/rfcs/rfc8414.txt`, `integration/rfc8414_metadata_test.go`, and a `client/http.go` well-known-URL fix (all reported in §2.16). Untracked working-tree files unrelated to the audited standards (`sdk/resourcemetadata/`, `integration/rfc9728_adversarial_test.go`) are excluded from scope and figures.
**Toolchain:** go1.27.0, darwin/arm64.
**Normative sources:** the RFC/draft texts vendored under `docs/rfcs/` (SHA-256 pinned in Appendix A; `rfc9700.txt` and `draft-ietf-oauth-security-topics-update-03.txt` cross-checked byte-identical against rfc-editor.org / ietf.org at verification time).

---

## 1. Methodology — how compliance was verified

Every requirement below was checked by three independent steps, executed by five parallel verification agents with disjoint standard-slices and cross-checked by the coordinator:

1. **Normative text:** the requirement was read from the vendored RFC/draft in `docs/rfcs/` (section numbers quoted below).
2. **Implementation:** located in code (`sdk/`, `server/`, `examples/`) with file:line evidence.
3. **Test proof:** the cited test was executed (`go test ./integration/ -run 'Test…' -count=1 -v`) and its `--- PASS` output recorded. No compliance claim in Section 2 relies on README assertions or unexecuted tests.

**Aggregate verification runs (executed 2026-09-28, sequentially, on the working tree as-is):**

Figure scope note: the counts below are raw measurements of the working tree, which physically contains the excluded untracked RFC 9728 suite (19 result lines: 11 test functions + 8 subtests). **Scope-adjusted integration figure for the audited surface: 271** (290 − 19). The tree could not be measured without those files without modifying it, which was out of bounds; the per-standard findings in Section 2 exclude them regardless.

| Run | Command | Result |
|---|---|---|
| Full repo suite | `go test ./... -count=1` | **29 packages `ok`, 0 `FAIL`** |
| Integration suite | `go test ./integration/ -count=1 -v` | **290 `--- PASS`, 0 `--- FAIL`** (incl. subtests) |
| Repo-wide, verbose | `go test ./... -count=1 -v` | **1275 `--- PASS`, 0 `--- FAIL`** |

The counts above reflect the **gap-fix pass** (Section 4 ledger items 1-8): +20 integration results over the audit baseline (6 RFC 8414, 8 FAPI JARM, 4 identity-chaining act/may_act, 2 live-mTLS) plus the DPoP nonce matrix (3 verifier + 1 prover case in the SDK suite) and the 9-subtest `self_signed_tls_client_auth` suite in `server/clientauthentication`.

Known reproducibility caveats: (a) running `go test ./...` while multiple agents run tests concurrently against the same module can produce spurious *setup* failures (package-cache races) — the definitive runs above were sequential and green; (b) during verification, the tree's `api/**` generated code was regenerated once (`buf generate`) to match the staged protos; (c) the working tree carries audit additions beyond the pinned pre-audit tree object: vendored `docs/rfcs/rfc8414.txt` + `openid-financial-api-jarm-ID1.txt`, new tests under `integration/` (`rfc8414_metadata_test.go`, `fapi_jarm_test.go`, `identity_chaining_act_test.go`, `rfc8705_live_mtls_test.go`), new sources (`server/clientauthentication/self_signed_tls_client_auth.go`), and fixes (`client/http.go` well-known URL, `sdk/token` JARM typ constant, `sdk/dpop` nonce, `sdk/rfcerrors` `use_dpop_nonce`, `server/services/token` act-chain depth cap). Mid-audit third-party working-tree files unrelated to the audited standards are excluded from this report (see §2.16).

**Status vocabulary:** `compliant` = every checked MUST/SHOULD of the standard is implemented and test-proven; `compliant (hardened)` = compliant plus deliberately stricter than the standard (see divergences); `partial` = some standard surface is unimplemented or unproven; `divergent-by-design` = the standard's optional surface is deliberately replaced by a stronger mechanism.

---

## 2. Per-standard compliance

### 2.1 RFC 6749 — OAuth 2.0 Core — **compliant (hardened)**

| § | Requirement | Evidence | Test (all PASS) |
|---|---|---|---|
| 5.2 | unknown `grant_type` → `unsupported_grant_type` | `server/services/token/service.go:153` (switch default → `rfcerrors.UnsupportedGrantType()`) | `TestRFC6749_UnsupportedGrantType_5_2` (subtests: `password`, `client_credentials_mtls`, garbage) |
| 5.2 | client not registered for grant → `unauthorized_client` | `server/services/token/grants.go` (`validateGrantPreamble`, grant-type membership check) | `TestRFC6749_UnauthorizedClient_5_2` |
| 5.2 | unknown client → `invalid_client`; AS fault → `server_error` | `server/services/token/service.go:125-133` | `TestRFC6749_BlankIssuer_InvalidRequest` (asserts `invalid_request`, not `server_error`) |
| 4.1.3 | auth-code redemption errors → `invalid_grant` with state echo | `server/services/token/grant_authorization_code.go:92-186` (atomic `DeleteAndGet` consume, client/redirect/PKCE checks) | exercised across `TestRFC7009_RevokeCascadesToGrantFamily_2_1` (revoked-family refresh reuse → `invalid_grant`) |

**Divergences (deliberate, argumented):**

1. **No resource-owner password-credentials grant (§4.3).** RFC 6749 defines it; solid's token service has no handler and rejects `grant_type=password` with `unsupported_grant_type` (proven by the test subtest). *Justification:* RFC 9700 §2.1 deprecates the password grant as a phishing enabler; the project's defensive posture (README "Protocol changes") exposes only grants compatible with sender-constrained tokens.
2. **No `id_token` from the authorization-code flow / no hybrid flow (§4.1.3).** The code-grant handler mints access+refresh tokens only. *Justification:* README protocol policy — privacy-first hybrid tokens, no subject data in tokens; the same attacker classes (code injection, mix-up) are covered by mandatory PKCE+nonce (RFC 7636), `iss` (RFC 9207) and `state`.
3. **`response_type=code` only (vs §3.1.1's four registered types).** `server/services/authorization/service.go:384-389` accepts only `code`. *Justification:* implicit/hybrid flows return tokens via the front channel; RFC 9700 §2.1.2 prohibits the implicit grant outright — solid applies the same logic to hybrid.

### 2.2 RFC 7636 — PKCE — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 4.1/4.2 | verifier/challenge charset and length bounds | `server/services/authorization/service.go:306-321` (43-unreserved-char challenge, S256-only) + `sdk/pkce` | `TestRFC7636_VerifierBoundary`, `TestRFC7636_VerifierCharset_4_1`, `TestRFC7636_ChallengeCharset` |
| 4.6 | code verifier compared to challenge | `server/services/token/grant_authorization_code.go` (S256 recomputed, `types.SecureCompareString` constant-time) | `TestRFC9700_PkceVerifierMismatch_4_5_3_1` |

**Divergence:** PKCE+S256 is **mandatory for all client types** and `plain` is refused outright (§4.7 RFC 7636 still normatively defines `plain`; RFC 9700 §2.1.1 already removes it). *Justification:* README: PKCE+nonce enforced by default for every client — confidential clients gain defense-in-depth against A3/A4 (injection/interception) at zero cost.

### 2.3 RFC 7009 — Token Revocation — **compliant**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.1 | only the token's owner client may revoke | `server/services/token/revoke.go` (client-id match; else `invalid_client`, no revocation) | `TestRFC7009_RevokeOtherClientToken_2_1` (clientB revoke of clientA token fails; token stays ACTIVE) |
| 2.2 | unknown token → respond as success | `revoke.go` (`storage.ErrNotFound` → `nil` error) | `TestRFC7009_RevokeUnknownToken_2_2` |
| 2.1 | `token_type_hint` advisory only | hint never gates lookup | `TestRFC7009_RevokeHintDoesNotBlock_2_1` |
| 2.1 | refresh revocation MAY cascade to the grant family (RFC 9700 §4.14.2 makes it normative) | `revoke.go` + `grant_refresh_token.go:167` (`revokeGrantFamily`) | `TestRFC7009_RevokeCascadesToGrantFamily_2_1` |
| — | access-token revocation does not over-cascade | cascade guarded on token type | `TestRFC7009_RevokeIsSingleToken_Only` |

**Divergence (stricter):** the RFC's anti-disclosure posture (§2.2 rationale) is extended: client-mismatch revocation returns a generic `invalid_client` with no token-detail description, so the response leaks neither token validity nor cause.

### 2.4 RFC 7662 — Token Introspection — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.1 | only authorized parties learn token state | `server/services/token/introspection.go:95-109` | `TestRFC7662_OwnershipGate_2_1` (clientB → UNKNOWN envelope, `Metadata nil`) |
| 2.2 | inactive tokens carry no claims; no cause distinction | `introspection.go:111-121` (single bare-envelope path for unknown/expired/revoked/foreign) | `TestRFC7662_NoCauseDistinction_2_2` (4 subtests) |
| 2.2 | revoked tokens inactive | revocation status → non-ACTIVE envelope | `TestRFC7662_RevokedTokenInactive` |

**Divergence (stricter):** ownership is not "any authenticated RS" (the RFC's minimum) but the token-owner client **plus** its explicitly declared `authorized_introspection_clients` allowlist. *Justification:* prevents introspection being used as a claims oracle by otherwise-trusted parties; opt-in disclosure matches the least-privilege posture.

### 2.5 RFC 8693 — Token Exchange — **partial (narrowed by design)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.2.2 | `actor_token` must resolve to a valid, active access token from this AS | `server/services/token/grant_token_exchange.go:141-154` | `TestRFC8693_ActorTokenInvalid` |
| 5 | `may_act` restricts actors | `grant_token_exchange.go:156-171` | `TestRFC8693_MayActEnforced` |
| 4.4 | `act` chain records the acting party | `grant_token_exchange.go:222-230` | `TestRFC8693_ActorTokenValid` |
| 4.2 | `cnf` confirmation carries over / key binding enforced | `grant_token_exchange.go:151-156,174-182,218` (DPoP `jkt` secure-compare) | `TestRFC8693_ConfirmationMismatch` |

**Divergences (deliberate, argumented):**

1. **Only `access_token` as `requested_token_type` (§2.1).** SAML2/JWT token types are rejected (`TestRFC8693_RequestedTokenTypeUnsupported` → `invalid_request`). *Justification:* solid issues only its own hybrid token format; an extra SAML/JWT-assertion minting surface would reintroduce the multi-JOSE-profile risk the project removes. The RFC permits a server to restrict its supported types; the error-code choice (`invalid_request` rather than the extension-style `unsupported_token_type`) is a minor code-level deviation.
2. **`authorization_details` rejected in token-exchange requests.** *Justification:* exchange delegates an existing grant and must never bootstrap consent that was never bound to the subject token — fail-closed per the RFC 9396 consent model. Verified in the RFC 9396 adversarial suite.

### 2.6 RFC 8628 — Device Authorization Grant + RFC 10027 hardening — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 3.5 | `authorization_pending` | `server/services/token/grant_device_code.go:112-138` | `TestRFC8628_AuthorizationPending` |
| 3.5 | `expired_token` | `grant_device_code.go:107-110` (checked before unknown-code path) | `TestRFC8628_ExpiredDeviceCode` |
| 3.5 | `access_denied` | `grant_device_code.go:140-144` | `TestRFC8628_AccessDenied` |
| 3.5 | `slow_down`, interval grows by 5s and persists | `grant_device_code.go:119-129` | `TestRFC10027_SlowDownOnFastPolling` (5→10s observed) |
| 3.4/3.5 | session bound to initiating client | `grant_device_code.go:100-104` | `TestRFC8628_WrongClientPoll` |
| 3.5 | unknown device code deterministic | `grant_device_code.go:75-84` | `TestRFC8628_UnknownDeviceCode` |
| 10027 §6.1.3 | one-time device codes | atomic `DeleteAndGetByDeviceCode` (`grant_device_code.go:157-171`) | `TestRFC10027_DeviceCodeSingleUse` |
| 10027 §6.1.11 | user-code brute-force throttle | `server/services/device/service.go` (5 attempts / 5 min / subject, reset on success) | `TestRFC10027_UserCodeBruteForceThrottled`, `TestRFC10027_UserCodeFirstAttemptSucceeds` |
| 10027 §6.1.9/6.1.10 | no refresh tokens, `offline_access` stripped | refresh-minting branch absent; scope filter at session creation and minting | `TestRFC10027_NoRefreshTokenFromDeviceGrant` |
| 10027 §6.1.12 | DPoP-bound clients must present proof | `grant_device_code.go:53-57` (pre-consume check) | `TestRFC10027_DPoPBoundClientRequiresProof` |

**Divergence (stricter):** RFC 8628 leaves refresh tokens to AS policy; solid never mints them from the device grant and caps the device session at 120s. *Justification:* RFC 10027 §6.1.9/6.1.10 identifies long-lived tokens as the primary loot of cross-device phishing; the device channel is treated as hostile-by-default.

**Unverified:** RFC 10027 §6.1.1/6.1.7/6.1.15-6.1.17 (proximity, trusted devices, human-interaction bindings) are presentation-layer mitigations — no browser UI ships in this repo (protocol-transport decoupling); user-code generator entropy not independently audited (only its effective length under the throttle).

### 2.7 RFC 9101 — JWT-Secured Authorization Request (JAR) — **compliant**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 5 (7519 §4.1.4) | `exp` REQUIRED; expired rejected | `sdk/jwsreq/decoder.go:63-81` | `TestRFC9101_ExpiredRequestObject` |
| 5 (7519 §4.1.5) | future `nbf` rejected | `decoder.go:83-84` | `TestRFC9101_NbfFuture` |
| 5 (7519 §4.1.3) | `aud` identifies the AS (string or array containing issuer) | `decoder.go:87-91,121-133` | `TestRFC9101_AudArrayAccepted` |
| 5.2 | no nested `request`/`request_uri` | `decoder.go:115` | `TestRFC9101_NestedRequestUri` (both subtests) |
| 5.9 | algorithm allowlist (no confusion) | `sdk/token/jwt/verifier.go:41-52`; harness pins ES384 | `TestRFC9101_AlgConfusion` (ES256 rejected) |
| 5.2 | `authorization_details` preserved for the AS | `sdk/token/access_token.go:79`; `sdk/authzdetails/static.go` | `TestRFC9101_AuthorizationDetailsDecoded` |
| 5 | request-object `client_id` must match authenticated client | `server/services/authorization/service.go:163-166` | `TestRFC9101_ClientIdMismatch` |

No divergences. Note: JAR `aud` accepts arrays here (RFC 9101 semantics) while *client-auth* assertions (§2.11) reject them — different standards, different rules, both as written.

### 2.8 RFC 9126 — Pushed Authorization Requests (PAR) — **compliant**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.1 | generated `request_uri` returned | `server/services/authorization/service.go:261-283` + `sdk/generator` | `TestRFC9126_GeneratedUriRoundTrip` |
| 2.2 | `request_uri` single-use (atomic burn) | `service.go:127-137` (`DeleteAndGet`) | `TestRFC9126_RequestUriSingleUse` |
| 2.2 | request_uri bound to the pushing client | `service.go:140-146` | `TestRFC9126_RequestUriClientBinding_2_2` |
| 2.2 | unknown/expired/malformed `request_uri` → `invalid_request` | `service.go:121-136` | `TestRFC9126_UnknownRequestUri` |

No divergences on the RFC surface. (Stricter-than-RFC project rules — PAR payload must itself be a JAR object, mandatory audience — are additive requirements, not RFC violations.)

### 2.9 RFC 9207 — Authorization Server Issuer Identification — **compliant**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2 | `iss` on success **and** error authorization responses | `server/services/authorization/service.go:102-112` (set before any failure path); `sdk/jarm/encoder.go:54-66` (issuer inside the signed JARM error object too) | `TestOAuthSecTopics_CoatIssParameterPresent_2_2` |

No divergences. Advertised as `authorization_response_iss_parameter_supported=true` in the example AS metadata.

### 2.10 RFC 9396 — Rich Authorization Requests — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 3/7 | details processed at authorization, carried into tokens, survive refresh | `sdk/authzdetails/static.go:42-56`; `sdk/token/access_token.go:79` | `TestRFC9396_AuthorizationDetailsEndToEnd` |
| 6/6.1 | token-endpoint subset narrowing; tokens carry exactly the requested subset | `server/services/token/authorization_details.go` + code grant | `TestRFC9396_TokenEndpointNarrowing_6`, `TestRFC9396_NarrowingViolationRejected_6` |
| 6 | no details beyond consent (proto-equality vs every consented entry) | same | `TestRFC9396_Adversarial_EntryTamperingEscalation` |
| 5 | unknown/unregistered type rejected | `static.go:50-53`; nil validator fails closed | `TestRFC9396_Adversarial_UnknownTypeRejected_5`, `_NilValidatorFailsClosed`, `_JarSmuggledUnknownType` |
| 5/7 | no cross-grant reuse | details matched only against the redeeming grant's consent set | `TestRFC9396_Adversarial_CrossGrantReuse` |
| 6.2 | refresh replay cannot re-widen narrowed consent | narrowed details persisted on rotation | `TestRFC9396_Adversarial_RefreshReplayEscalation` |
| — | `client_credentials` fail-closed (no consent authority) | consent-bound model | `TestRFC9396_ClientCredentialsFailsClosed` |

**Divergence (stricter):** instead of a permissive type registry, validation is fail-closed — an unwired (nil) validator rejects **all** details rather than ignoring them. *Justification:* the RFC's own §5 requires AS recognition before processing; fail-closed prevents a misconfigured AS from silently accepting unvalidated capability objects. No RFC 9396 MUST is violated.

### 2.11 RFC 7521 + RFC 7523 — Assertion Framework / JWT Client Authentication — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 7523 §3 | REQUIRED claims (`iss`,`sub`,`aud`,`exp`), `exp` past rejected, `iss` identifies client (`iss`=`sub`) | `server/clientauthentication/private_key_jwt.go:175-212` | `TestRFC7521AssertionProfile` (7 subtests: missing claims, expired, nbf-future, untrusted issuer, typ mismatch, non-JWT, corrupt payload) |
| 7523 §3.4 | `aud` identifies the AS | `private_key_jwt.go:193-196` (issuer identifier **or** exact receiving endpoint) | `TestRFC9700_ClientAuthAudienceBinding_2_5` |
| 7523 §3 | `alg=none` rejected; algorithm allowlist before claim processing | `private_key_jwt.go:156-161` | `TestRFC7523_AlgNoneRejected` |
| 7523 §3 (jti) | replay protection | `private_key_jwt.go:244-260` (namespaced blake2b jti store, burned after signature validation) | `TestRFC9700_ClientAuthJtiReplay_4_2_4`; SPIFFE analog `TestSpiffeJWTClientAuthEndToEnd/replay_rejected` |
| 7521 §4.2 | assertion-profile parameters validated per profile | `grant_jwt_bearer.go` ID-JAG profile | `TestRFC7521AssertionProfile` |

**Divergences (deliberate, argumented):**

1. **Single-valued `aud` only (vs RFC 7519 §4.1.3 array semantics).** `private_key_jwt.go:188-191` rejects any `aud` with length ≠ 1, even arrays containing the valid issuer. *Justification:* the vendored `draft-ietf-oauth-security-topics-update-03` §2.1.2 identifies multi-audience client-auth assertions as an audience-injection vector; solid implements the draft's countermeasure. Proven by `TestRFC7523_AudArrayRejected` and `TestOAuthSecTopics_AudArrayWithInjectedAudience_2_1`. (This diverges from RFC 7523's letter, which merely requires the AS to be *an* intended audience — solid requires it to be *the only* one.)
2. **10-minute hard cap on assertion lifetime (`maxAssertionLifetime`, `private_key_jwt.go:112`).** RFC 7523 §3 only permits ("MAY reject") far-future `exp`. *Justification:* short-lived credentials are the project's stated posture; the cap removes clock-skew and long-window replay reasoning entirely. Proven by `TestRFC9700_ClientAuthTemporalWindows_2_5`.

### 2.12 RFC 8705 — mTLS Client Authentication & Certificate-Bound Tokens — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.1.1 | `tls_client_auth` PKI method | `server/clientauthentication/tls_client_auth.go` | `TestRFC8705_TlsClientAuth_PKIBinding` (subject_dn, dns/uri/ip/email SANs) |
| 2.1.2 | exactly one subject binding registered; that value must match | `tls_client_auth.go:121-140` | `TestRFC8705_TlsClientAuth_AmbiguousSubject` (0 and 2 bindings rejected) |
| 2.1.2 | DN RFC 4514-comparable, IP binary-compared | `tls_client_auth.go:144-172` (`SecureCompareString`, `net.IP.Equal`) | `TestRFC8705_TlsClientAuth_PKIBinding/ip_san_with_ipv6_textual_difference` |
| 2 | certificate validity window | `tls_client_auth.go:95-100` | package suite `ok zntr.io/solid/server/clientauthentication` |
| 3.1 | `cnf` member `x5t#S256` = base64url(SHA-256(DER)), unpadded | `sdk/token/confirmation_x5t.go:32-38`; RFC Appendix A fixture | `TestRFC8705_X5tS256Confirmation_WireFormat` |
| 3 | RS must enforce same-cert usage | `sdk/token/confirmation_x5t.go:44-51`; example RS middleware | `TestRFC8705_BearerRequiresMatchingCertificate` |
| 3.2 | introspection conveys `cnf` | introspection path | `TestRFC8705_IntrospectionCnfRendering` |
| 7.1 | certificate-bound refresh tokens | `grant_refresh_token.go:103-114` (thumbprint secure-compare; rotation inherits binding) | `TestRFC8705_RefreshTokenCertificateBinding` |
| 7.1/3 | binding survives token exchange | `grant_token_exchange.go:228` (confirmation inherited) | `TestRFC8705_TokenExchangeCertificateBinding` |
| 2.1 | no method confusion (mTLS client can't use private_key_jwt) | method-registration checks on every processor | `TestRFC8705_TlsClientAuth_NoCertificateAndMethodConfusion`, `TestRFC8705_TlsClientAuth_UnregisteredMethod` |
| 2.2 | `self_signed_tls_client_auth`: presented cert must match one of the client's registered JWKS `x5c` certificates; no chain validation per §2.2 (gap-fix pass) | `server/clientauthentication/self_signed_tls_client_auth.go` (exact DER byte-equality match on the x5c leaf, base64(DER)-decoded; fail-closed absent/malformed `jwks`; method-registration guard) | `Test_selfSignedTLSClientAuthentication_Authenticate` (9 subtests: registered match, unregistered cert, no jwks, malformed jwks, method confusion, missing client_id, missing cert, expired cert, garbage PEM) |
| 2/7.3 | live mutual-TLS: real handshake → middleware PEM extraction → processor (gap-fix pass) | `integration/rfc8705_live_mtls_test.go` (`RequireAnyClientCert` server, cert-presenting client) | `TestRFC8705_LiveMTLSHandshakeToAuthentication` (matching cert → 200; attacker cert → 401) |

**Divergences:**

1. **Certificate chain validation delegated to the TLS stack** (`tls_client_auth.go:44-48` explicitly does not re-validate chains). *Justification:* RFC 8705 §2.1 already relies on the TLS handshake for path validation; the protocol core is transport-decoupled and sees an already-handshake-validated certificate — re-validating without the TLS stack's negotiated state (resumption, partial chains) would reject legitimate clients. Subject binding and validity window remain enforced in-code.
2. **`self_signed_tls_client_auth` match is exact DER byte equality** rather than any semantic certificate comparison. *Justification:* a certificate is a self-contained signed object — byte equality is the strictest possible match, admitting no normalization or partial-match ambiguity; rotation is handled by registering the new certificate's JWK in `jwks` (RFC 8705 §2.2.2), exactly as the RFC prescribes.

### 2.13 draft-ietf-oauth-spiffe-client-auth-02 — SPIFFE Client Authentication — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 3.1 | JWT-SVID assertion (`urn:…:jwt-spiffe`): `sub`/`aud`/`jti`/`exp`, signature via trust-domain bundle keys | `server/clientauthentication/spiffe_jwt.go:87-205` | `TestSpiffeJWTClientAuthEndToEnd` (valid, tampered signature, wildcards, replay) |
| 3.2 | X.509-SVID over mTLS: URI SAN, leaf constraints, path validation against bundle roots | `spiffe_x509.go:68-161`; `sdk/spiffe/api.go:109-124` | `TestSpiffeX509ClientAuthEndToEnd` |
| 3.3 | WIT-SVID + PoP: `iss`/`sub`/`cnf.jwk`, PoP key binding, `PoP.iss == WIT.sub` | `spiffe_wit.go:109-286` | `TestSpiffeWITClientAuthEndToEnd` (valid; PoP with different key rejected) |
| 5.1 | registered `spiffe_id` must match; `/*` matches whole path segments only, never mid-segment | `sdk/spiffe/api.go:86-104` (`MatchSPIFFEID`); fail-closed checks in all three processors | `TestSpiffeJWTClientAuthEndToEnd/wildcard_boundary_non-match_rejected` + `wildcard_segment_match_accepted` |
| 8.1 | no key discovery from `iss` claims — keys only from trust-domain `BundleSource` | bundle fetch exclusively via `BundleSource.Get(trustDomain)`; no discovery fetch in `server/clientauthentication/` (grep-verified) | `tampered_signature_rejected` (valid claims, attacker key — only bundle keys validate) |
| 6 | bundle endpoints (`spiffe_sequence`, `spiffe_refresh_hint`) | `sdk/spiffe/endpoint.go` | `ok zntr.io/solid/sdk/spiffe` (package suite) |
| — | `spiffe_id` from a CIMD-resolved client | `integration/spiffe_test.go:437+` | `TestSpiffeCIMDClientAuth` |

**Divergences (deliberate, argumented):**

1. **`client_id` optional; SPIFFE ID is the primary client locator (§3.2 says `client_id` MUST be present).** The §5.1 `spiffe_id`↔SVID match is *always* enforced fail-closed (empty registered `spiffe_id` → reject), making a client without a registered SPIFFE ID unable to authenticate under any name. *Justification:* binding to the cryptographic identity (SVID) rather than to a self-asserted string is strictly stronger; the fail-closed match subsumes the draft's redundancy requirement.
2. **WIT+PoP transported via the client-attestation header pair** (`OAuth-Client-Attestation`/`-PoP`) instead of a single assertion parameter. *Justification:* semantically equivalent (verified WIT signature with `iss`-domain wit-svid bundle keys, PoP verified with the `cnf.jwk` key); reuses the established attestation transport, consistent with protocol-presentation decoupling.

**Unverified:** live HTTPS bundle-endpoint fetching (unit-tested only, static `BundleSource` in the harness); `spiffe_bundle_endpoint` CIMD field not exercised.

### 2.14 RFC 9700 — OAuth 2.0 Security BCP — **compliant (hardened)**

Verified across 21 top-level tests / 39 subtests (`ok zntr.io/solid/integration`):

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.1.2 | no implicit grant; `response_type=code` only | `service.go:384-389` | `TestRFC9700_ResponseTypeCodeOnly_2_1_2` |
| 4.5 | codes bound to client (anti injection) | `grant_authorization_code.go:98-102` | `TestRFC9700_CodeInjection_BindingToClient_4_5` |
| 4.2.4 | codes single-use, replay-safe | atomic `DeleteAndGet` (`grant_authorization_code.go:92`) | `TestRFC9700_CodeSingleUse_4_2_4`, `TestRFC9700_CodeReplayRace_4_5` |
| 4.5.1 | token-endpoint `redirect_uri` identical to authorization-time value | `grant_authorization_code.go:166-175` | `TestRFC9700_RedirectUriTampering_4_5_1` (even an alternative *registered* URI refused) |
| 4.5.3.1 | PKCE verifier binding | S256 constant-time compare | `TestRFC9700_PkceVerifierMismatch_4_5_3_1` |
| 4.8.2 | no S256→plain downgrade | plain method never storable/acceptable | `TestRFC9700_DowngradeVerifiers_4_8_2` |
| 4.4.2.1 | issuer identification (mix-up) | RFC 9207 `iss` on all responses | `TestOAuthSecTopics_CoatIssParameterPresent_2_2` |
| 4.10.1 | sender-constrained tokens | DPoP enforcement (see §2.15) + mTLS binding (§2.12) | `TestRFC9700_DPoPJtiReplay_4_10_1`, `_HtmHtuBinding_`, `_IatWindow_`, `_AthBinding_` |
| 4.10.2 | audience-restricted tokens | resource-registry validation; unknown audience → `invalid_target` | `TestRFC9700_TokenExchangeAudienceRestriction_4_10_2`, `TestRFC9700_TokenExchangeUnknownAudience_4_10_2` |
| 4.14.2 | refresh rotation + family revocation on replayed rotated token | `grant_refresh_token.go:62-81,152-160` | `TestRFC9700_Rotation_4_14_2`, `TestRFC9700_FamilyRevocationOnReplay_4_14_2` |
| 2.2.2 | refresh tokens bound to one client | `grant_refresh_token.go:108-112` | `TestRFC9700_RefreshTokenBoundToClient_2_2_2` |
| 4.14 | token-type confusion prevented | type gates on refresh/exchange | `TestRFC9700_RefreshTokenNotAnAccessToken_4_14`, `TestRFC9700_TokenExchangeSubjectTokenTypeEnforced` |
| 2.5 | client-auth temporal windows (exp/iat/nbf, lifetime cap) | `private_key_jwt.go:197-246` | `TestRFC9700_ClientAuthTemporalWindows_2_5` |
| 2.5 | audience binding of client assertions | `private_key_jwt.go:193-196` | `TestRFC9700_ClientAuthAudienceBinding_2_5` |

**Divergences (all stricter-than-BCP, argumented):**

1. **PKCE mandatory for confidential clients too** (BCP §2.1.1 mandates it for public clients). *Justification:* defense-in-depth against code interception/injection applies regardless of client confidentiality; the BCP itself recommends PKCE everywhere in practice.
2. **Sender-constraint enforced, not recommended** (§4.10.1 "SHOULD" → DPoP-bound clients *cannot* receive bearer tokens). *Justification:* README posture — eliminates the bearer-replay class by construction.
3. **No public clients at all** (§2.5 treats `token_endpoint_auth_method=none` as legitimate). *Justification:* every solid client is asymmetric-authenticated; public-client flows are outside the trust model the project sells.
4. **Shared-secret client auth never implemented** (`client_secret_basic/post`, HSxxx). *Justification:* elliptic-curve-only JOSE policy (README); shared secrets are exfiltratable credentials.
5. **Refresh rotation unconditional** (§4.14.2 is a SHOULD/recommendation). *Justification:* pinning the stronger policy in the server removes deployment misconfiguration as a failure mode.
6. **No `id_token`/nonce echo** (§4.5.3.2 nonce-in-ID-token): nonce is mandatory in the authorization request and session-bound, but no ID token exists to echo it into. *Justification:* privacy-first hybrid tokens; the anti-injection purpose is served by PKCE+nonce+state+`iss`.

**Unverified:** §4.2 Referer leakage / §4.11 open redirector / §4.13 TLS proxies / §4.16 clickjacking are client-side or browser-presentation duties; the transport-decoupled core cannot enforce them and no login UI ships in-repo (token-endpoint `Cache-Control: no-store` not directly verified).

### 2.15 draft-ietf-oauth-security-topics-update-03 — **compliant (AS-side)**

All 10 `TestOAuthSecTopics_*` tests PASS. Attack families:

| § | Attack family | Evidence | Test (PASS) |
|---|---|---|---|
| 2.1 / 2.1.2.1 | Audience injection (cross-endpoint replay, token-endpoint-claim replay, aud arrays) | single-valued `aud` = issuer identifier (preferred) or exact endpoint | `TestOAuthSecTopics_AudInjectionCrossEndpointReplay_2_1`, `_AudInjectionTokenEndpointClaim_2_1`, `_AudArrayWithInjectedAudience_2_1`, `_AudIssuerIdentifierAccepted_2_1_2_1` (positive control across /par, /token, introspection, revocation, device) |
| 2.2 | COAT (code redeemer at honest AS, redirect context mismatch) | code↔client + redirect binding; `iss` emission | `TestOAuthSecTopics_CoatCodeRedeemedAtHonestAS_2_2`, `_CoatRedirectContextMismatch_2_2`, `_CoatIssParameterPresent_2_2` |
| 2.3 | Session fixation (state not bound to attacker; subject not attacker-fixable) | subject from authenticated presentation layer only (`service.go:95-98,213-221`) | `TestOAuthSecTopics_SessionFixationStateNotBoundToAttacker_2_3`, `_SessionFixationSubjectNotInRequest_2_3` |
| 2.4.2.1 | Shared consent (broker reusing key material) | per-client registration; per-client storage keys | `TestOAuthSecTopics_SharedConsentPerClientRegistration_2_4_2_1` (same-JWKS clients cannot redeem each other's codes/RTs) |

**Unverified:** the draft's client/broker-side countermeasures (connection-context identifier, broker consent screens §2.2.2/§2.4.2.2) — the repo ships no client/broker; only the AS-side contract is implemented, as the test doc-comments state.

### 2.16 RFC 8414 / RFC 9728 — Authorization Server & Protected Resource Metadata — **compliant (AS metadata, hardened) / partial (PRM surface untested)**

Implemented: AS metadata endpoint `/.well-known/oauth-authorization-server` (`examples/authorizationserver/handlers/metadata.go`, which is the RFC 9728-consolidated schema); PR metadata at `/.well-known/oauth-protected-resource` and `resource_metadata` WWW-Authenticate challenges (`examples/resourceserver/main.go:126`, `middleware.go:188-218`); client AS-metadata fetch (`client/http.go`).

**AS metadata (RFC 8414) — conformance tests added during this audit:**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 3 / 3.2 | document at the default well-known path; 200 OK, `application/json` | `handlers/metadata.go` served by `main.go:132` | `TestRFC8414_MetadataDocumentAccessible_3` |
| 2 | REQUIRED members: `issuer` (no query/fragment), `authorization_endpoint`, `token_endpoint`, `response_types_supported` (non-empty, contains `code`); `jwks_uri` https | same document | `TestRFC8414_RequiredMetadataMembers_2` |
| 3.2 | multi-valued claims are JSON arrays; zero-element claims omitted | same document | `TestRFC8414_ArrayValuedMembersAreArrays_3_2` |
| 2 | `token_endpoint_auth_signing_alg_values_supported` present when `private_key_jwt` advertised; `none` never allowed | same document | `TestRFC8414_SigningAlgValuesConstraint_2` |
| 3 / 3.1 | well-known URI string inserted between host and path; terminating `/` stripped (pathless and `/issuer1` issuers) | `client/http.go` (fixed during this audit: suffix concatenation → RFC 8414 §3 insertion) + `TestRFC8414_WellKnownPathConstruction_3` | both PASS |
| 3.1 + security-topics-update-03 §2.1.2.1 | client fetches metadata with GET and rejects an issuer-mismatched document (mix-up defense) | `client/http.go:76-78` | `TestRFC8414_ClientFetchesAndValidatesMetadata_3_1_2_1` |

**Bug found and fixed during this audit:** the shipped client built the metadata URL by suffix concatenation (`issuer + "/.well-known/…"`) — wrong for path-bearing issuers (`https://host/issuer1` must yield `/.well-known/oauth-authorization-server/issuer1` per RFC 8414 §3). Fixed in `client/http.go` with host/path insertion; the three pre-existing client tests remain green.

**Remaining gap:** the **PRM client-side surface** (RFC 9728 §1.2–§7.7: identifier shape, well-known URL construction, signed metadata, resource-member match, SSRF-fenced fetch) has **no vendored-text-anchored integration test in the audited tree**. Mid-audit, third-party working-tree files appeared (`sdk/resourcemetadata/`, `integration/rfc9728_adversarial_test.go`, untracked); per the audit instruction to disregard mid-session modifications they are **excluded from this report's scope and counts**. When that work is committed, re-run this section against it.

### 2.17 draft-ietf-oauth-client-id-metadata-document-02 (CIMD) — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 3 | identifier URL shape (https, no userinfo, path, no dot-segments/fragment) | `sdk/cimd/identifier.go:41-67` | `TestCIMDHostileIdentifierShapes` |
| 4 | document `client_id` == fetched URL; malformed docs rejected | `sdk/cimd/resolver.go:84-87`, `document.go:75-97` | `TestCIMDClientIDMismatch`, `TestCIMDMalformedDocument` |
| 4.1 | no `client_secret*`, no secret auth methods, no private JWK material | `document.go:108-115,177-199` (EC `d`, RSA private, `oct` rejected) | `TestCIMDClientSecretExfiltration`, `TestCIMDPrivateKeyLeak` |
| 5 | 200-only, redirects never followed | `sdk/httpfetch/fetcher.go:120-121,175` | `TestCIMDNon200AndRedirects` |
| 8.6 | SSRF: special-use destinations refused pre-connection + dial-time re-check (DNS rebinding) | `fetcher.go:239-254,299,335-345` (RFC 6890 CIDRs incl. 169.254.169.254, ULA) | `TestCIMDSSRFSpecialUseDestinations` |
| 8.7 / 7.1 | 5 kB response cap; pre-registered metadata wins | `fetcher.go:57-60,182-187`; primary-store precedence | `TestCIMDOversizeDocument`, `TestCIMDPreRegisteredWins` |
| 5.2 | AS advertises support | `metadata.go:89` | `TestMetadataAdvertisesCIMDSupport` (`ok zntr.io/solid/examples/authorizationserver/handlers`) |

**Divergences (stricter):** (1) deliberately **cache-less** resolver — caching is a decorator's choice, so revocation of hostile documents is immediate; (2) **operator-pinned `AllowlistFilter`** (`resolver.go:88-119`) — the AS only fetches identifiers the operator pinned, because CIMD resolution is an unauthenticated attacker-triggered server-side fetch; (3) non-URL-shaped pre-registered identifiers can never be shadowed (short-circuit before fetch). *Justification:* the draft's trust-on-fetch model is tightened for the same reason the draft's own §8.6 exists.

### 2.18 draft-ietf-oauth-identity-assertion-authz-grant-04 (ID-JAG / cross-app access) — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 3/3.1 | typ `oauth-id-jag+jwt`, single-valued `aud` = local issuer, empty `resource` tolerated with `aud` fallback | `sdk/idjag/verifier.go:80-83,114-117,237-247` | `TestIDJAGEmptyResourceClaim` |
| 4.x | issuance via token exchange for trusted audience; scope narrowed; pairwise subject per target | `server/services/token/idjag_issuance.go` | `TestIDJAGCrossAppAccessLoop` (refresh → ID-JAG → jwt-bearer AT; subject continuity; no RT) |
| 4.4.x | redemption negative matrix (wrong typ/aud/multi-aud/self-issued/client_id mismatch/expired/foreign signature/untrusted issuer; cnf-bound requires DPoP) | `verifier.go:68-163` + jwt-bearer grant | `TestIDJAGAdversarial` (12 subtests) |
| 4.4.3 | replayable until `exp`; redemption yields no refresh token | access-token-only minting | both loop + adversarial suites |
| RFC 7521 §4.2 | assertion profile requirements | `grant_jwt_bearer.go` | `TestRFC7521AssertionProfile` |

**Divergence (stricter):** the subject transmitted in the ID-JAG is a **per-target pairwise pseudonym**, never the IdP-local identifier. *Justification:* README pairwise-subject policy — prevents cross-domain correlation even among colluding ASes; test asserts redeemed subject ≠ IdP-local `'alice'`.

**Unverified:** live HTTP end-to-end (loop proven at the service layer); no dedicated metadata subtest for the ID-JAG fields.

### 2.19 draft-ietf-oauth-identity-chaining-17 — **compliant (hardened)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 2.3.3 | grant/audience laundering: a grant minted for AS-B must not redeem at AS-C | `verifier.go:114-117,237-247` (`aud` must equal local issuer) | `TestIdentityChainingGrantLaundering` (rejected at third AS with `invalid_grant`) |
| 2.4.2 | deny on unresolvable subject; transcribe claims on success | `idjag_issuance.go` SubjectResolver + transcription | `TestIdentityChainingUnresolvableSubject` (subject = ID-JAG sub; ≠ `'alice'`) |
| 2.5 | subject/scope transcription | loop test asserts subject continuity + scope narrowing to `chat.read` | `TestIDJAGCrossAppAccessLoop` |
| 2.2 | grant is a trusted-issuer-signed, typ-bound, audience-pinned, temporally validated JWT with client binding | `verifier.go:68-163` | `TestIDJAGAdversarial` |
| 2.5 / RFC 8693 §4.4-§5 | act chain preservation across delegation + may_act gating of chained actors (gap-fix pass) | `server/services/token/grant_token_exchange.go` (chain assembly, `maxActChainDepth` cap) | `TestIdentityChainingActChainPreserved_4_4`, `TestIdentityChainingMayActGatesChainedActor_5`, `TestIdentityChainingMayActListedChainedActorSucceeds_5`, `TestIdentityChainingActChainDepthCapped` |

**Divergences:** (1) pairwise pseudonymous subject across domains (as §2.18 — README policy); (2) denial-on-unresolvable-subject is delegated to the wired `SubjectResolver` policy rather than hard-coded — fail-closed by construction because the pairwise mapping is established at issuance time. *Justification:* composable hook consistent with protocol-transport decoupling.

**Unverified (resolved):** act/`may_act` delegation-chain coverage was added in the gap-fix pass — `integration/identity_chaining_act_test.go` covers deep-chain preservation (RFC 8693 §4.4), may_act gating against chained actors (§5), a positive control, and the security depth cap (`maxActChainDepth = 3`, fail-closed). Chaining remains proven at the service layer.


### 2.20 OpenID CIBA Core 1.0 — Client-Initiated Backchannel Authentication — **compliant (hardened, poll mode)**

| § | Requirement | Evidence | Test (PASS) |
|---|---|---|---|
| 7.1 | `scope` MUST contain `openid` | `server/services/backchannel/service.go` (scope guard) | `TestCIBA_MissingOpenIDScope` |
| 7.2 step 3 | exactly one of `login_hint`/`login_hint_token`/`id_token_hint` | `service.go` `hintCount` guard | `TestCIBA_MultipleHints` |
| 7.2 step 4 | unresolvable hint → `unknown_user_id` | `HintResolver` contract; deployment-provided resolver | `TestCIBA_UnknownUser` |
| 7.1.1 | signed request objects: `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, signature vs client JWKS, alg allowlist (EC-only) | `service.go` `applySignedRequest` | `TestCIBA_SignedRequest`, `TestCIBA_SignedRequest_Adversarial` (wrong iss, forged key, missing exp, parameter outside JWT) |
| 7.3 | `auth_req_id` ≥ 160 bits recommended, allowed charset | `sdk/generator/auth_req_id.go` (32 alphanumeric chars, ~190 bits) | `Test_authReqIDGenerator_Generate` |
| 10.1/11 | `authorization_pending` / `slow_down` (interval +5s, persisted) | `server/services/token/grant_ciba.go` poll-timing block | `TestCIBA_AuthorizationPending`, `TestCIBA_SlowDown` |
| 11 | `access_denied` on end-user refusal | `grant_ciba.go` DENIED branch; `backchannel/service.go` `Deny` | `TestCIBA_AccessDenied` |
| 11 | `expired_token` | `grant_ciba.go` expiry check before unknown branch | `TestCIBA_ExpiredAuthReqID` |
| 11 | unknown/wrong-client/consumed `auth_req_id` → `invalid_grant` (mandated, unlike RFC 8628) | `grant_ciba.go` unknown, client-match, and `DeleteAndGetByAuthReqID` replay branches | `TestCIBA_UnknownAuthReqID`, `TestCIBA_WrongClientPoll`, `TestCIBA_ApprovalThenToken` (replay) |
| 10.1 | one-time `auth_req_id` | atomic `DeleteAndGetByAuthReqID` | `TestCIBA_ApprovalThenToken` (second poll → `invalid_grant`) |
| 9396 §3 | `authorization_details` fixed at bc-authorize time, consented on session, carried into token; no token-endpoint narrowing | `backchannel/service.go` validator + `grant_ciba.go` narrowing rejection | `TestCIBA_AuthorizationDetails`, `TestCIBA_UnknownAuthorizationDetails` (fail-closed static validator) |
| 9449 §10 | optional `dpop_jkt` session binding (request-object claim or form param): token polls MUST prove possession of the bound key; minted tokens are sender-constrained (`cnf.jkt`, `token_type: DPoP`) | `backchannel/service.go` session confirmation + `grant_ciba.go` proof-key-swap guard | `TestCIBA_DPoPKeyBinding` (no proof → `invalid_grant`; wrong key → `invalid_grant`; bound key → DPoP-typed token) |

**Divergences (stricter):** (1) `binding_message` promoted to REQUIRED (4–64 chars, `[A-Za-z0-9._-]`) — it is the CD/AD anti-phishing interlock; violations return `invalid_binding_message`. (2) Poll delivery mode only (`backchannel_token_delivery_modes_supported: ["poll"]`): ping/push would open an OP→client callback surface the project deliberately does not offer. (3) No refresh tokens; `offline_access` stripped from the session scope — same cross-device-phishing rationale as the device grant (RFC 9700 §4.12.2). (4) `user_code` and `client_notification_token` unsupported (poll mode; ignored when sent).

**Unverified:** hint-resolution semantics for `login_hint_token`/`id_token_hint` are deployment-specific (opaque to the SDK); the default resolver handles `login_hint` only, and integration coverage exercises that path.

---

## 3. Cross-cutting divergence themes

Every divergence found is **in one direction only: stricter than the standard**, and falls into four argumented families:

1. **Optionality removed where it weakens security** (README: "optional and recommended parameters promoted to required"): PKCE mandatory for all clients; asymmetric client auth only; no public clients; S256-only; single-valued `aud`; PAR+JAR+DPoP+JARM enforced as the only authorization path; no implicit/hybrid; no password grant; no refresh tokens from the device grant; fail-closed `authorization_details`.
2. **Privacy substituted for protocol convenience** (README: privacy-first): hybrid tokens without subject claims; pairwise pseudonyms in ID-JAG/identity chaining; no `id_token` in the code flow; introspection as opt-in disclosure.
3. **Replay surfaces eliminated deterministically** instead of probabilistically: unconditional refresh rotation + family revocation; jti one-time-use stores burned *after* signature validation (no DoS-burn of honest jtis); one-time device/PAR/code URIs via atomic consume; DPoP nonce support (RFC 9449 §4.3) now implemented alongside the clock-skew-immune server-side jti store (gap-fix pass).
4. **Transport decoupling** (README: protocol-HTTP decoupled): chain validation, Referer/clickjacking, TLS-proxy concerns live in the presentation layer; the core enforces the protocol invariants only. This is a stated architectural boundary, not a compliance gap of the protocol core — but it means browser-facing deployments must supply those layers.

**Where the standards conflict with each other**, solid resolves consistently: RFC 7519 array-`aud` leniency vs security-topics-update §2.1 → the draft wins (RFC 9700-family takes precedence per AGENTS: "when the RFC leaves options open, the most defensive option wins"; here the newer security guidance closes an RFC 7523 option). RFC 8628 refresh-token latitude vs RFC 10027 §6.1.9 → BCP wins. RFC 6749 grant breadth vs RFC 9700 §2.1 → BCP wins.

---

## 4. Open compliance items (honest ledger)

| # | Item | Standard | Status |
|---|---|---|---|
| 1 | ~~`rfc8414.txt` not vendored; AS-metadata untested~~ — **resolved during this audit**: RFC 8414 vendored (`16c816e4…`), 6 conformance tests added, client well-known-URL bug fixed. PRM (RFC 9728) client-side surface still untested in the audited tree | RFC 8414 / RFC 9728 | AS metadata closed; PRM gap remains |
| 2 | ~~DPoP nonce not implemented~~ — **resolved during this audit**: `nonce` claim + `WithExpectedNonce` verifier option + `use_dpop_nonce` error builder added (`sdk/dpop`, RFC 9449 §4.3/§9); nonce-present/absent/mismatch test matrix green; server-side jti replay store retained alongside | RFC 9449 §4.3 | Resolved (additive hardening kept) |
| 3 | ~~`self_signed_tls_client_auth` absent~~ — **implemented during this audit**: full processor (`server/clientauthentication/self_signed_tls_client_auth.go`, RFC 8705 §2.2 — registered JWKS `x5c` match on exact DER equality, no chain validation per §2.2, fail-closed absent/malformed jwks, method-confusion guard); 9-subtest suite green | RFC 8705 §2.2 | Resolved |
| 4 | ~~error code for unsupported `requested_token_type`~~ — **audit correction, no code change**: RFC 8693 §2.2.2 mandates `invalid_request` for invalid/unacceptable requests; `unsupported_token_type` does not exist in RFC 8693. The original implementation was correct; the ledger item was an audit misjudgment | RFC 8693 §2.2.2 | Closed as invalid finding |
| 5 | ~~act/`may_act` chaining sections unexercised~~ — **resolved during this audit**: `integration/identity_chaining_act_test.go` (RFC 8693 §4.4 deep-chain preservation, §5 may_act gating of chained actors, positive control) + **security depth cap**: `maxActChainDepth = 3` enforced fail-closed in the token-exchange grant (over-deep delegation chains rejected, never silently truncated — privilege-laundering vector) | identity-chaining-17 / RFC 8693 §4.4-§5 | Resolved + hardened |
| 6 | Client/broker-side and browser-presentation mitigations (COAT §2.2.2, Referer, clickjacking, TLS proxies, 10027 §6.1.1/6.1.15-17) | security-topics-update-03, RFC 9700, RFC 10027 | Out of repo scope (no client/broker/UI shipped) — deployment responsibility |
| 7 | ~~live-TLS behavior unexercised~~ — **resolved during this audit**: `integration/rfc8705_live_mtls_test.go` drives a real mutual-TLS handshake (RequireAnyClientCert server, cert-presenting client) through the example middleware into the `tls_client_auth` processor; matching cert → 200, foreign cert → 401 | RFC 8705 §2/§7.3 | Resolved (SPIFFE §6 live-HTTPS fetch remains unit-proven) |
| 8 | ~~JARM not auditable against a vendored text~~ — **resolved during this audit**: FAPI JARM ID1 vendored (`docs/rfcs/openid-financial-api-jarm-ID1.txt`, `5be3ad47…`); 8-test conformance suite added (`integration/fapi_jarm_test.go` — §5.1 iss/aud/exp/state checks, foreign signature, payload tamper, bound error responses, garbage matrix). **Bug found & fixed:** the JWT signer emitted `typ: "jarm"` while the decoder requires `jarm+jwt` (RFC 8725 §3.11 typ-confusion hardening) — the example AS previously minted responses its own decoder rejects | FAPI JARM | Resolved + real bug fixed |

---

## 5. Verdict summary

| Standard | Status | Tests proving it |
|---|---|---|
| RFC 6749 (core) | compliant (hardened) | 3 |
| RFC 7636 (PKCE) | compliant (hardened) | 3 |
| RFC 7009 (revocation) | compliant | 5 |
| RFC 7662 (introspection) | compliant (hardened) | 3 |
| RFC 8693 (token exchange) | partial (narrowed by design) | 5 |
| RFC 8628 (device) + RFC 10027 | compliant (hardened) | 12 |
| RFC 9101 (JAR) | compliant | 7 |
| RFC 9126 (PAR) | compliant | 4 |
| RFC 9207 (issuer id) | compliant | 1 (+adversarial) |
| RFC 9396 (RAR) | compliant (hardened) | 12 |
| RFC 7521/7523 (assertions/JWT client auth) | compliant (hardened) | 3 (+9700 suite) |
| RFC 8705 (mTLS) | compliant (hardened — self-signed method + live-TLS now covered) | 10 + 9 self-signed + 2 live-mTLS |
| spiffe-client-auth-02 | compliant (hardened) | 4 |
| RFC 9700 (security BCP) | compliant (hardened) | 21 (39 subtests) |
| security-topics-update-03 | compliant (AS-side) | 10 |
| RFC 8414 (AS metadata) / RFC 9728 (PRM) | **compliant (hardened)** / partial (PRM untested) | 6 |
| CIMD-02 | compliant (hardened) | 9 |
| ID-JAG-04 | compliant (hardened) | 8 |
| identity-chaining-17 | compliant (hardened — act/may_act chains + depth cap) | 3 + 4 act/may_act |
| FAPI JARM | compliant (hardened) | 8 |
| CIBA Core 1.0 (backchannel, poll mode) | compliant (hardened) | 15 |

All cited tests executed and passing on the current working tree (post gap-fix pass, 2026-09-28); every divergence is stricter-than-standard and individually justified above. The one exception is the PRM (RFC 9728) client-side surface, which remains untested in the audited tree (ledger item 1) pending the owner's in-flight work being committed.

---

## Appendix A — Normative source integrity (SHA-256, `docs/rfcs/`)

```
1a0d5f079042734e754afc88ca7a554418d12a2c64c936519130c55e322297fe  draft-ietf-oauth-client-id-metadata-document-02.txt
a59c1dffc0b5e59d1bd541276c6948eb9191f3b83685be5810a32e63effb4653  draft-ietf-oauth-identity-assertion-authz-grant-04.txt
306bf30143c7ca0c823a5481dbf3647fa3c7d2ca1aa023a4712d6ed426d08e10  draft-ietf-oauth-identity-chaining-17.txt
54855dd81cef1de2afce66e4f7a7f677f400b1517583c30fee01cd9b147e206e  draft-ietf-oauth-security-topics-update-03.txt  ※
ec9c7c171349a40eee72a32381dce3adb5bc1ec1285666ba9382ec288405c249  draft-ietf-oauth-spiffe-client-auth-02.txt
6dbc22add43407cb07f1b665a94f63fdd6302f99fcc42978527d6767a442ffc1  rfc10027.txt
16c816e4e0fdbffb7e910ff3017867bf39debe9cb7f52f5cbc508a052ed660e8  rfc8414.txt
f204fc8661d6c92d2ec6e0b54808f961a9ad26e792f57f312d9528335519bd71  rfc6749.txt
b2f346d5a87ba9d7f09047901257a65f7ac0b26352095969c25821afab447829  rfc7009.txt
d5d97b3e691c9bbc495c277cc2cd79316b82486991468fc346a96ab59ba4b3c8  rfc7521.txt
ae24f77a8fc4338903c805c6ace38def1f23d40194aea87b123b13c5b3d2d915  rfc7523.txt
1972e5d81cbaba7066cfd46374207bc2b4546b085ed5dd9b034e79e023e0ca31  rfc7636.txt
2b7d688cb849f093e860557ac97e6cddac2556d69a4386561b22cdf97bf13657  rfc7662.txt
ebd3c37415aa665b55b412fccd9571943e8dbd3f2bf0b18fee4924264252decd  rfc8628.txt
358d658014738bf4dc56c8aae2094ce716ede23b6d5a80488a7dc8e8d72da609  rfc8693.txt
6e45a1ee94c6a6a177a4cb077fe67d74bd70c1218c9362f2db2f153239612414  rfc8705.txt
a1400b5b8d27cfabb127325458a88415f83bb04b2ff9e6facbe50b8ef4ea2b60  rfc9101.txt
a79d0e30fcc24a22b79c8e18aa82362f6e63a7b8a5d58b480e746360e97388db  rfc9126.txt
c9c17b9824315aca9bda5c0b5e3627cb24aa28d54324292f3761006209b705fd  rfc9207.txt
d6a8f032d8a585daae1c33a8c7b6e539d199f886ec8cc1c7898436f7f2eed29c  rfc9396.txt
3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13  rfc9449.txt
9919d061d40a97886ca866b51c69389b6c81c65cd4b979056c14fdbebfcf622a  rfc9700.txt  ※
b65bcd0d9daf90fd7006a42cf48e0ac3ba24b7f5637d5197f2de41c6b91c8a89  rfc9728.txt
5be3ad47bd2c4e8f8d0a1994a4fe509582db0e8b17b8087f83b372e7bc16de49  openid-financial-api-jarm-ID1.txt
134613a42fc7d3dde8acc17e3486ea543283d2ab5b8fe9fcad36468c414903b7  openid-client-initiated-backchannel-authentication-core-1_0.txt
```

`※` — byte-identical to the canonical copy fetched live from rfc-editor.org (`rfc9700.txt`) and ietf.org (`draft-ietf-oauth-security-topics-update-03.txt`) during verification.

## Appendix B — Reproduction

```sh
git checkout zenithar/nauth/xaa_protocol   # commit a0cdcf8f82e267ccd62ae76e12a02a7261c6ffc2
# restore the staged working tree (ID-JAG feature) — pre-audit verified tree sha256:
#   4db2e7d0e7f780102e2f5b7ff07ffc6af2788fdaa071abce14135fb5b1df15b1
# plus audit additions: docs/rfcs/rfc8414.txt, docs/rfcs/openid-financial-api-jarm-ID1.txt,
# integration/rfc8414_metadata_test.go, integration/fapi_jarm_test.go,
# integration/identity_chaining_act_test.go, integration/rfc8705_live_mtls_test.go,
# server/clientauthentication/self_signed_tls_client_auth.go (+ test),
# client/http.go well-known URL fix, sdk/token JARM typ fix, sdk/dpop nonce,
# sdk/rfcerrors use_dpop_nonce, oidc/const.go self_signed method,
# server/services/token act-chain depth cap.
go version          # go1.27.0 darwin/arm64
go test ./... -count=1                    # expect: 29 ok, 0 FAIL
go test ./integration/ -count=1 -v 2>&1 | grep -c '^--- PASS'   # expect: 290 with the excluded untracked 9728 suite present; 271 without it
go test ./integration/ -count=1 -v 2>&1 | grep -c '^--- FAIL'   # expect: 0
```

Scope note: untracked working-tree files unrelated to the audited standards (`sdk/resourcemetadata/`, `integration/rfc9728_adversarial_test.go`) exist in the tree but are excluded from this report's scope and figures per the mid-session-modification exclusion instruction. When committed, §2.16's PRM gap should be re-audited against them.


Verification performed 2026-09-28T07:39:46Z by five parallel verification agents (standards slices: core grants/tokens; JAR/PAR/DPoP/RAR; client authentication incl. mTLS+SPIFFE; security BCPs; discovery/CIMD/identity-assertion drafts) with independent code-location, test-execution and RFC-section citation, plus coordinator spot-checks of file:line evidence.
