# SolID — Grounded Design Decisions

**Module:** `zntr.io/solid`
**Date:** 2026-10-08
**Tree:** `e03a55b` plus staged token-exchange work (anchors re-verified on this tree)

This document is the per-decision design record. It states what SolID does. It states how each decision relates to the governing standard. It gives the evidence for every claim. Each evidence item is one of these four kinds:

1. **Code:** a `file:line` anchor in this repository. Run `grep` or `read` on the anchor to check the claim.
2. **RFC:** a section in a vendored text under `docs/rfcs/`. The texts are pinned by SHA-256 in `docs/rfcs/index.jsonl`. Check the quoted sentence against the vendored file.
3. **Test:** a named test. Run `go test ./integration/ -run 'TestName' -count=1` to execute the proof.
4. **Model:** a property in `spec/*.qnt`. Run `quint test` per `spec/README.md` to execute the proof.

The word **MUST** and its RFC 2119 siblings (SHOULD, MAY, REQUIRED, MUST NOT, SHOULD NOT) in this document carry the RFC 2119 meanings. An RFC 2119 keyword always binds the party named in the sentence.

Companion artifacts:

- `docs/COMPLIANCE_REPORT.md` — per-standard conformance with executed test proof.
- `docs/solid.jsonl` — the same postures in machine-readable form.
- `spec/` — executable Quint formal models of the flow cores.
- `docs/rfcs/` — vendored normative texts. This is the source of truth for every standard citation in this document.

---

## 0. How to read this document

### 0.1 Relation vocabulary

| Relation | Meaning |
|---|---|
| **REPRESENTS** | SolID implements the rule that the standard states. The rule and the implementation match. |
| **NEGATES** | SolID refuses a surface that the standard itself permits. The refusal is deliberate. This document gives the reason. |
| **ENHANCES** | SolID adds a rule or a mechanism that no standard asks for. |
| **HARDENS** | SolID implements the standard with stricter parameters. Mandatory where the standard states SHOULD or MAY. One value where the standard offers a menu. |

### 0.2 Override rules

These rules settle conflicts between standards and between a standard and SolID.

**OR-1.** Where a newer security BCP tightens an older standard, SolID MUST implement the BCP or a stricter rule.

**OR-2.** Where a newer draft weakens a BCP requirement, SolID MUST keep the BCP level.

*Example.* draft-ietf-oauth-v2-1-16 §4.3.3 states "MAY revoke the old refresh token". RFC 9700 §4.14.2 requires rotation or sender-constraining for public clients. SolID rotates unconditionally. See D-13.

**OR-3.** Where the standard leaves an option open, SolID MUST select the most defensive option.

**OR-4.** A decision in this document changes only through a new dated entry that supersedes the old one. A test failure or an integration request does not change a decision.

**OR-5.** A decision moves in one direction only: toward the stricter side. A proposal to move toward the weaker option of the standard is a project non-goal (README "What is not").

### 0.3 Verification contract

Every claim in this document has one of the four evidence kinds above. A claim without an anchor does not belong in this document. If an anchor breaks after a refactor, update the anchor. Do not change the decision to match broken code (rule shared with `spec/README.md`).

---

## 1. Architecture

### D-01 — The protocol core does not depend on the wire — **ENHANCES**

**Decision.** The domain model is protobuf-defined (`proto/oidc/**`, generated into `api/`). All protocol logic lives in transport-agnostic services. Their contracts take and return protobuf types. Presentation layers — HTTP (`server/httpkit`), gRPC (`server/grpckit`), CoAP (`examples/coapace`) — assemble the services. A presentation layer MUST NOT implement protocol rules.

**Relation.** The OAuth and OIDC standards bind the protocol to HTTP by design. SolID treats that binding as a presentation concern. No decision below depends on HTTP.

**Reason.** The standards conflict with each other partly because they bind protocol to presentation. OAuth 2.0 core assumes HTTP redirects. ACE assumes CoAP. The decoupling lets the same security decisions hold on every transport.

**Rejected alternative.** HTTP-first with a CoAP shim. This leaks HTTP semantics into the core. It makes ACE conformance an adaptation problem instead of a codec problem.

**Consequence.** Browser-facing mitigations (Referer, clickjacking, COAT chain validation) live in the presentation layer, not in `server/services`. Deployments MUST supply those layers. See `docs/COMPLIANCE_REPORT.md` ledger item 6.

**Evidence.**
- Code: `server/services/api.go` — context-first, protobuf-typed contracts.
- Code: `examples/coapace/server.go` and `server/httpkit/*` drive the same service implementations.
- Code: `sdk/ace` carries the CBOR wire codec. It carries no protocol logic.

### D-02 — The token serialization format is an assembler decision — **ENHANCES**

**Decision.** Grant logic is token-format agnostic. Only `sdk/token` implements final encoders: signed UUIDv7 reference tokens, JWT, HPKE-encrypted JWT, CWT, SD-CWT. A grant handler MUST NOT depend on a serialization format. The consumer of the SDK selects the format at assembly time.

**Relation.** RFC 6750, RFC 7519, and RFC 8392 define serializations. No standard requires the use of one. SolID implements each serialization as a swappable strategy.

**Reason.** Baking JWT into grant handlers would make the CWT and HPKE paths second-class. It would re-couple the protocol core to JOSE, which D-01 forbids.

**Consequence.** Every format rule (D-11) MUST be enforced at the encoder boundary. A new encoder MUST repeat the algorithm allowlists. `sdk/token/jwt/verifier.go` and `sdk/token/cwt/signer.go` carry independent allowlists today.

**Evidence.**
- Code: `sdk/token/api.go` — `Signer` and `Verifier` interfaces. Grant handlers receive a `token.Signer`.
- Code: `SOLID_EXAMPLE_TOKEN_FORMAT` switch in `examples/coapace`.
- Test: `integration/cwt_token_test.go` — CWT round-trip through the real token service.

---

## 2. Flows

### D-03 — `response_type=code` only. No implicit, no hybrid — **NEGATES** RFC 6749, **HARDENS** per RFC 9700

**Decision.** The authorization endpoint accepts `code` only. It rejects `token` and all hybrid response types with `unsupported_response_type`.

**Relation.** RFC 6749 §3.1.1 registers four response types. SolID NEGATES that menu. RFC 9700 §2.1.2 states: "clients SHOULD NOT use the implicit grant (response type token) or other response types issuing access tokens in the authorization response". SolID closes the SHOULD NOT at the server side and makes it MUST NOT.

**Override statement.** The authorization server MUST reject every response type other than `code`.

**Reason.** Front-channel token delivery causes token leakage and token replay (RFC 9700 §2.1.2, lines 342-345 of `docs/rfcs/rfc9700.txt`). Hybrid types return tokens on the front channel too. The same argument covers them.

**Rejected alternative.** Support implicit "for compatibility". One weak client weakens the platform posture for all clients (README "What I observed in real life").

**Consequence.** SolID cannot pass full OIDC basic and hybrid conformance. This is a documented non-goal (README "What is not").

**Evidence.**
- Code: `server/services/authorization/service.go:344-348` — the `switch` accepts `oidc.ResponseTypeCode` only. The default returns `rfcerrors.UnsupportedResponseType()`.
- Code: `server/profile/profile_strict.go:76` — the service profile advertises an empty response-type list.
- RFC: `docs/rfcs/rfc9700.txt` §2.1.2, lines 342-363.

### D-04 — PAR is the mandatory authorization entry point — **ENHANCES** RFC 9126

**Decision.** The `authorization_code` flow MUST start with a pushed authorization request. The client posts a signed request object. The AS returns a `request_uri`. The user-agent then starts the flow with that `request_uri` only. A request built from user-agent parameters MUST NOT start the flow.

**Relation.** RFC 9126 offers PAR as an alternative to front-channel parameters. It is optional in the standard. SolID makes it the only path.

**Override statement.** The authorization server MUST accept a `request_uri` from the PAR endpoint as the sole entry to the authorization code flow.

**Reason.** PAR removes the authorization request from the front channel. An attacker who controls the user's browser cannot change the request the AS evaluates. Combined with D-05, the AS signs and authenticates the authorization request before any user interaction.

**Rejected alternative.** Front-channel requests with `request` or `request_uri` parameters (RFC 9101 §5 permits these). This reopens the injection surface that PAR closes.

**Consequence.** A client without asymmetric credentials cannot use the authorization code flow. D-10 already requires asymmetric credentials for every client, so the constraint costs nothing extra.

**Evidence.**
- Code: `server/services/authorization/service.go:117` — atomic `authorizationRequests.DeleteAndGet`. This is the burn-after-read consume that fixed formal-model finding F3 (`spec/README.md`).
- Code: `server/httpkit/par.go` — PAR endpoint wiring.
- Test: `TestRFC9126_RequestUriSingleUse` (`integration/rfc9126_par_test.go:77`).
- Test: `TestRFC9126_RequestUriClientBinding_2_2` (`integration/rfc9126_par_test.go:118`).
- RFC: `docs/rfcs/rfc9126.txt` §2.2.

### D-05 — Authorization requests are JWT-signed request objects — **REPRESENTS** RFC 9101, made mandatory

**Decision.** Every pushed authorization request is a signed request object per RFC 9101. Unsigned request objects are rejected.

**Relation.** RFC 9101 permits signed request objects. It does not require them. SolID represents the RFC 9101 validation rules and makes signing mandatory on every request.

**Override statement.** The authorization server MUST reject an unsigned request object. The AS MUST check all of these: `aud` equals the AS issuer. `exp` is present and not expired. `nbf` is not future. No nested `request` or `request_uri` parameter exists. The object's `client_id` equals the authenticated client.

**Reason.** Unsigned parameters are attacker-writable input. A signed object makes the authorization request an authenticated artifact.

**Evidence.**
- Code: `sdk/jwsreq/decoder.go` — the aud/exp/nbf/nesting checks.
- Code: `server/services/authorization/service.go` — client_id match against the authenticated client.
- Test: `TestRFC9101_ExpiredRequestObject` (`integration/rfc9101_jar_test.go:62`).
- RFC: `docs/rfcs/rfc9101.txt` §5.

### D-06 — Authorization responses are JWT-secured only — **HARDENS** (FAPI JARM, RFC 9207)

**Decision.** With `response_type=code`, the response mode MUST be `query.jwt`, `fragment.jwt`, or `form_post.jwt`. Plain `query`, `fragment`, and `form_post` modes are not offered, for success and error responses. RFC 9207 `iss` is present in every response mode.

**Relation.** JARM is an optional FAPI profile. RFC 6749's default for the code flow is the plain query mode. SolID negates the plain modes and makes the optional signing profile mandatory.

**Override statement.** The authorization server MUST sign every authorization response, success and error, in a JWT response mode.

**Reason.** A signed, issuer-identified response cannot be forged or substituted by a hostile page. This covers mix-up on the response side. PKCE covers injection. `state` covers client-side binding.

**Consequence.** Clients MUST check JARM responses. One bug class was found and fixed during the audit: the signer emitted `typ: "jarm"` where the decoder required `jarm+jwt` (RFC 8725 §3.11 typ confusion). See `docs/COMPLIANCE_REPORT.md` ledger item 8.

**Evidence.**
- Code: `server/services/authorization/service.go:371-374` — plain modes rejected for the code flow.
- Code: `sdk/jarm/encoder.go:54` — RFC 9207 §2 `iss` plus the JARM claim set, on error responses too.
- Test: `integration/fapi_jarm_test.go` — 8-test conformance suite against the vendored FAPI text.

### D-07 — PKCE is mandatory, S256-only, for every client — **HARDENS**

**Decision.** `code_challenge` and `code_challenge_method=S256` are REQUIRED for every client, confidential included. The `plain` method is refused. The verifier comparison is constant-time.

**Relation.** RFC 7636 scopes PKCE to public clients and still defines `plain`. RFC 9700 §2.1.1 states "Authorization servers MUST support PKCE" and "Public clients MUST use PKCE". The same section names S256 as the only non-exposing method ("Currently, S256 is the only such method", line 319). Draft-ietf-oauth-v2-1-16 §7.5.2 states "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1" (line 3552). SolID takes the strongest position in that lineage: mandatory for all clients, S256 only.

**Override statement.** The authorization server MUST require `code_challenge` with `code_challenge_method=S256` for every client. The AS MUST reject the `plain` method. The AS MUST compare the verifier in constant time.

**Reason.** RFC 9700 §4.8 warns about PKCE downgrade (lines 1442-1444). The warning reads: "an authorization server that supports PKCE but does not make its use mandatory for all flows can be susceptible to a PKCE downgrade attack". The section concludes that mandatory PKCE "implicitly implement[s] this security measure" (lines 1524-1525). Confidential clients gain protection against code injection and interception (attacker classes A3/A4). The cost is zero.

**Evidence.**
- Code: `proto/oidc` protovalidate annotations — RFC 7636 §4.2 charset and length bounds, enforced as the first validation level.
- Code: `server/services/authorization/service.go:316-320` — protovalidate first level.
- Code: `server/services/token/grant_authorization_code.go:184` — `types.SecureCompareString` on the recomputed S256 challenge.
- Test: `TestRFC9700_PkceVerifierMismatch_4_5_3_1` (`integration/rfc9700_authorization_test.go:149`).
- Test: `TestRFC7636_VerifierBoundary`, `TestRFC7636_VerifierCharset_4_1`, `TestRFC7636_ChallengeCharset`.
- RFC: `docs/rfcs/rfc9700.txt` §2.1.1 (lines 293-338), §4.8 (lines 1440-1525).
- RFC: `docs/rfcs/draft-ietf-oauth-v2-1-16.txt` §7.5.2 (lines 3550-3553).

### D-08 — Device grant: no refresh tokens, one-time codes, throttled polling — **REPRESENTS** RFC 8628, **HARDENS** per RFC 10027

**Decision.** The `device_code` grant implements RFC 8628 §3.5 semantics: `authorization_pending`, `expired_token`, `access_denied`, and `slow_down` with a +5s persistent interval. The grant layers these RFC 10027 mitigations on top:

- one-time device codes (atomic consume)
- user-code brute-force throttling (5 attempts per 5 minutes per subject)
- no refresh tokens ever, `offline_access` stripped
- mandatory DPoP proofs for DPoP-bound clients

**Relation.** RFC 8628 leaves refresh tokens to AS policy. RFC 10027 §6.1.9/§6.1.10 say do not issue them. OR-1 applies: the BCP wins. The device channel is hostile by default because long-lived tokens are the primary loot of cross-device phishing.

**Override statement.** The AS MUST NOT mint a refresh token from the device grant. The AS MUST consume each device code exactly once. The AS MUST throttle user-code approvals per subject.

**Consequence.** A device that needs continuity must re-authorize. Accepted.

**Evidence.**
- Code: `server/services/token/grant_device_code.go` — poll semantics, atomic `DeleteAndGetByDeviceCode`, pre-consume DPoP check.
- Code: `server/services/device/service.go` — approval throttle.
- Test: `TestRFC10027_SlowDownOnFastPolling` (`integration/rfc10027_device_test.go:65`).
- Test: `TestRFC10027_DeviceCodeSingleUse`, `TestRFC10027_NoRefreshTokenFromDeviceGrant`, `TestRFC10027_UserCodeBruteForceThrottled`.
- Model: `spec/devicecode.qnt` properties D1-D7 — exhaustively model-checked, `NoError` (`spec/README.md`).
- RFC: `docs/rfcs/rfc8628.txt` §3.5, `docs/rfcs/rfc10027.txt` §6.1.

### D-09 — CIBA: poll mode only, binding message required, no refresh tokens — **REPRESENTS** CIBA Core, **HARDENS**

**Decision.** CIBA runs in poll delivery mode. `binding_message` is required, not optional. Signed request objects are verified against client JWKS. Optional `dpop_jkt` session binding enforces proof-of-possession at the token endpoint (RFC 9449 §10). `authorization_details` are fixed at bc-authorize time. No refresh tokens. `offline_access` is stripped per RFC 9700 §4.12.2.

**Relation.** CIBA Core makes `binding_message` optional and offers ping and callback modes. SolID represents the core §10 token-endpoint semantics and hardens the optionality away.

**Override statement.** The AS MUST require a binding message. The AS MUST NOT mint a refresh token from CIBA. The AS MUST freeze `authorization_details` at bc-authorize time.

**Reason.** The binding message is the only channel binding the user can check in cross-device authentication. Without it, the approval screen is phishable. Ping and callback add server-to-client attack surface for marginal benefit.

**Evidence.**
- Code: `server/services/backchannel/service.go`.
- Code: `server/services/token/grant_ciba.go:124` — DPoP jkt secure-compare.
- Test: `integration/ciba_adversarial_test.go` — 15 tests.
- Model: `spec/ciba.qnt` properties B1-B8 — model-checked, `NoError` (`spec/README.md`).
- RFC: `docs/rfcs/openid-client-initiated-backchannel-authentication-core-1_0.txt` §10, `docs/rfcs/rfc9700.txt` §4.12.2.

---

## 3. Client authentication

### D-10 — Asymmetric client authentication only — **NEGATES** RFC 6749 §2.3.1, **REPRESENTS** the asymmetric family

**Decision.** No symmetric client authentication exists anywhere: no HTTP Basic, no `client_secret_post`, no `client_secret_jwt`. The implemented methods are `private_key_jwt` (RFC 7523), `tls_client_auth` and `self_signed_tls_client_auth` (RFC 8705), `attest_jwt_client_auth` (draft-ietf-oauth-attestation-based-client-auth), and `spiffe_jwt`, `spiffe_wit`, `spiffe_x509` (draft-ietf-oauth-spiffe-client-auth).

**Relation.** RFC 6749 §2.3.1 defines client passwords as a first-class method. SolID negates that surface entirely. Each asymmetric method is represented with its own standard's validation rules. Cross-method confusion fails closed: a client registered for one method cannot authenticate via another. Each processor checks `client.TokenEndpointAuthMethod`.

**Override statement.** The authorization server MUST NOT accept a shared secret for client authentication. A client registered for one authentication method MUST NOT authenticate via another.

**Reason.** Shared secrets phish and leak from repositories and configuration. Every supported method binds the authentication to a cryptographic proof: key possession, certificate, attestation, or SVID. This makes D-04's authenticated POST free.

**Consequence.** Dynamic client registration (RFC 7591) never issues secrets. The registered client must already own a key or a JWKS. Registration is operator-gated. RFC 7592 management rides the registration access token only.

**Evidence.**
- Code: `server/clientauthentication/` — processors: `private_key_jwt.go`, `tls_client_auth.go`, `self_signed_tls_client_auth.go`, `client_attestation.go`, `spiffe_jwt.go`, `spiffe_wit.go`, `spiffe_x509.go`. No Basic or secret processor exists.
- Code: `server/httpkit/client_auth.go:127` — selector dispatch.
- Code: `server/profile/profile_strict.go` — metadata advertises asymmetric methods only.
- Test: `integration/rfc8705_mtls_test.go` (fixture-anchored and live-mTLS), `integration/spiffe_test.go`, `integration/attestation_adversarial_test.go`.

### D-11 — EC and ML-DSA algorithms only, double allowlists — **REPRESENTS** RFC 8725 §3.4/§3.5, **NEGATES** the JOSE registry breadth

**Decision.** JWT and CWT signers accept elliptic-curve algorithms (ES256, ES384, ES512, EdDSA) and ML-DSA (44, 65, 87 per RFC 9964) only. The signer constructor panics on any other algorithm. The verifier enforces a second allowlist. No HS, RS, PS, or `none` algorithm exists anywhere in the tree. Every assertion-bearing credential (client assertion, attestation, JAR object, DPoP proof) passes an allowlist check before claim processing.

**Relation.** RFC 8725 §3.4/§3.5 require explicit algorithm pinning. SolID represents those rules and negates the registry breadth.

**Override statement.** A token signer or verifier MUST NOT accept an algorithm outside {ES256, ES384, ES512, EdDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87}. An assertion processor MUST check the algorithm allowlist before it processes claims.

**Reason.** Algorithm confusion and `none`-class downgrades are verification-time bugs. The defense is structural: the insecure option cannot be constructed. RSA is refused for a second reason: equal security levels require unequal computation, which burdens constrained clients.

**Consequence.** Clients that hold RSA keys MUST migrate to EC or ML-DSA keys.

**Evidence.**
- Code: `sdk/token/jwt/signer_test.go:282-286` — the allowlist test enumerates the seven identifiers and asserts construction panics otherwise.
- Code: `sdk/token/jwt/verifier.go:116` — verifier allowlist, panic on construction with a bad algorithm.
- Code: `sdk/token/cwt/signer.go` — the ES + ML-DSA COSE allowlist.
- Code: `server/clientauthentication/private_key_jwt.go:157-160`, `client_attestation.go:290-292` — allowlist before claims.
- Code: `sdk/jwk/mldsa.go` — ML-DSA key support.
- Test: RFC 9964 Appendix A/B vectors as tests in `sdk/token/jwt/mldsa_test.go`.

---

## 4. Tokens

### D-12 — No PII in access or refresh tokens, pairwise subjects, no `id_token` from the code flow by default — **NEGATES** OIDC Core, **ENHANCES** (privacy) *(id_token clause superseded by D-12.1, 2026-10-08; the rest stands)*

**Decision.** Access and refresh tokens embed protocol-validation claims only: issuer, expiry, grant family, confirmation. The token does not carry the subject. The `jti` references an AS-only record. The external subject identifier is pairwise, computed per sector. By default the `authorization_code` flow issues no `id_token` (the opt-in is D-12.1). User details come from `user_info` at consent time.

**Relation.** OIDC Core requires an `id_token` from the code flow and defines public subject types. SolID negates both. Pairwise subjects are represented (OIDC Core §8).

**Override statement.** The AS MUST NOT write subject data into an access or refresh token. The AS MUST NOT issue an `id_token` from the authorization code flow. The AS MUST expose the subject as a pairwise identifier per sector.

**Reason.** A stealable artifact SHOULD carry nothing worth stealing. Protocol-validation claims let any party check expiry and audience locally. Subject resolution requires AS access. That is a capability boundary by design. Pairwise identifiers also prevent cross-client correlation of the same person.

**Consequence.** Resource servers that need subject attributes MUST call `user_info` or introspection (D-15). This trades one round trip for subject-data containment. OIDC conformance for the code-flow `id_token` is a documented non-goal.

**Evidence.**
- Code: `server/services/token/grant_authorization_code.go` — the handler mints access and refresh tokens only; no ID-token generator is wired by default (D-12.1 opt-in).
- Code: `sdk/pairwise` — per-sector encoder, salted at assembly (`examples/authorizationserver/main.go`).
- Model: `spec/solid.qnt` properties I5 and I6 — pairwise disjointness and injectivity, model-checked, `NoError` (`spec/README.md`).

### D-13 — Refresh rotation unconditional, replay revokes the grant family — **HARDENS** (RFC 9700 §4.14.2 kept over draft v2-1)

**Decision.** Every refresh-token use rotates: the presented token is revoked and a new one is issued. Presenting a revoked refresh token revokes the entire grant family. Refresh issuance is gated on the client's registered capability.

**Relation.** RFC 9700 §4.14.2 (lines 1983-1984) requires the AS to pick one of two methods to detect refresh-token replay for public clients. The methods are sender-constrained refresh tokens or rotation. Draft v2-1 §4.3.3 then states the AS "MAY revoke the old refresh token after issuing a new refresh token" (line 2639). OR-2 applies. SolID keeps the BCP level and drops the method choice. Rotation is unconditional and replay always revokes the family.

**Override statement.** The AS MUST rotate the refresh token on every use. The AS MUST revoke the entire grant family when a revoked refresh token is presented.

**Reason.** Replay of a rotated token is theft: the legitimate client already moved on. Probabilistic recovery for racy clients trades a clean theft detector for resumability. SolID prefers deterministic elimination (COMPLIANCE_REPORT divergence family 3).

**Evidence.**
- Code: `server/services/token/grant_refresh_token.go:79-82` — replay detects a revoked token and calls `revokeGrantFamily`.
- Code: `server/services/token/grant_refresh_token.go:200-205` — family revocation by grant id.
- Code: `server/services/token/grant_refresh_token.go:112-121` — stored `x5t#S256` binding secure-compare at refresh (RFC 8705 §7.1).
- Test: `TestRFC7009_RevokeCascadesToGrantFamily_2_1`.
- Model: `spec/solid.qnt` properties I1-I4 — single active RT, family revocation, model-checked, `NoError`.
- RFC: `docs/rfcs/rfc9700.txt` §4.14.2 (lines 1983-2009). `docs/rfcs/draft-ietf-oauth-v2-1-16.txt` §4.3.3 states "MAY revoke the old refresh token" (line 2639).

### D-14 — Sender-constrained tokens, gate in-core — **REPRESENTS** RFC 9449 / RFC 8705 §3, **HARDENS** (fail-closed, all grants)

**Decision.** Client-level binding policy is enforced centrally for every grant. A `DpopBoundAccessTokens` client MUST present a DPoP proof. The proof's `jkt` is minted into the token. A `TlsClientCertificateBoundAccessTokens` client MUST present its certificate (`x5t#S256`). Refresh grants honor stored confirmations with `invalid_grant` semantics. Token exchange propagates the subject token's binding without strip-or-swap. A jkt-bound token presented as plain Bearer is rejected.

**Relation.** RFC 9449 defines DPoP as opt-in per deployment. RFC 8705 §3 defines certificate binding as an AS option. SolID represents both mechanisms and hardens the enforcement: not per request, not per handler — one shared in-core gate that every grant handler must pass.

**Override statement.** Every grant handler MUST enforce the client's sender-binding policy after the grant preamble. A client with `DpopBoundAccessTokens` MUST NOT receive a token without a DPoP proof. A jkt-bound token MUST NOT be honored as a plain Bearer token.

**Reason.** Bearer tokens are "token is here, you are admin" credentials. This project started against that anti-pattern (README "What I observed in real life"). Sender-constraint converts possession into proof. A structural gate prevents a future grant from regressing to bearer.

**Evidence.**
- Code: `server/services/token/grants.go:95-98` — the `enforceSenderBinding` gate.
- Code: wiring in every grant: `grant_client_credentials.go:53`, `grant_jwt_bearer.go:54`, `grant_refresh_token.go:124`, `grant_authorization_code.go:62`, `grant_device_code.go:64`, `grant_ciba.go:65`.
- Code: `sdk/dpop/verifier.go` — typ, embedded JWK alg-binding, htm case-insensitive compare (RFC 9110), htu normalization (RFC 3986 §6.2.2/§6.2.3), exp window, nonce (§4.3), jti single-use. The jti burn runs after full validation (lines 157-161).
- Code: `examples/resourceserver/middleware.go:104` — a jkt-bound token is rejected as Bearer.
- Test: `TestEnforceSenderBinding` (8 cases), `integration/rfc8705_mtls_test.go`.
- Model: key-continuity properties I7 (`solid.qnt`), T6 (`tokenexchange.qnt`), J6 (`xaa.qnt`), B5 (`ciba.qnt`), device variant — all model-checked, `NoError`.

### D-15 — Introspection is opt-in disclosure — **HARDENS** RFC 7662

**Decision.** Only the token-owner client plus its explicitly declared `authorized_introspection_clients` learn token state. Unknown, expired, revoked, and foreign tokens return the same bare inactive envelope. No cause distinction. No claims.

**Relation.** RFC 7662 §2.1 requires "authorized parties" and permits any authenticated resource server to introspect. SolID represents §2.2 exactly (indistinguishable inactive responses) and hardens §2.1: authorization is an allowlist, not mere authentication.

**Override statement.** The AS MUST NOT disclose token state to a client outside the owner's `authorized_introspection_clients` list. The introspection response for a non-ACTIVE token MUST be identical for every cause of inactivity.

**Reason.** With broad rights, introspection becomes a claims oracle for otherwise-trusted parties. Least-privilege disclosure matches the privacy posture (D-12).

**Evidence.**
- Code: `server/services/token/introspection.go:103-110` — the ownership gate resolves the owner and checks `AuthorizedIntrospectionClients`.
- Code: `server/services/token/introspection.go:119-121` — the single bare-envelope path for every inactive cause.
- Test: `TestRFC7662_OwnershipGate_2_1` (`integration/rfc7662_introspection_test.go:148`), `TestRFC7662_NoCauseDistinction_2_2`.

---

### D-12.1 — Opt-in selectively disclosable `id_token` from the code flow — **NEGATES** OIDC Core's default, **ENHANCES** beyond it *(added 2026-10-08)*

**Decision.** An assembly MAY wire an opt-in ID-token generator for the authorization code flow (`token.WithIDTokenGenerator`; nil — the default — issues none). When wired and `openid` was granted, the AS mints an `id_token` that is a signed SD-JWT (RFC 9901, `id+jwt`, `sdk/sdtoken` `IDTokenProfile`): `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `nonce`, `auth_time`, `acr` are protected; every user claim is selectively disclosable — the token carries digests only, the values travel in the response `id_token_disclosures` parameter over the client-authenticated back channel. The subject is pairwise. The nonce of the authorization request is echoed. `aud` is the `client_id`. The id_token spec is never persisted: introspection can never surface its disclosures. The id_token is deliberately NOT encrypted in this amendment (HPKE-encrypting it to the client's registered `use=enc` key is future work).

**Relation.** OIDC Core requires an `id_token` from the code flow carrying the user's claims in cleartext. SolID negates the default and offers a strictly-harder opt-in — not an OR-5 weakening: a plaintext-claims id_token remains non-constructible through the SDK surface.

**Reason.** D-12's objection targets the artifact's content: SD removes the user values from the token — a stolen or logged token yields digests only. The values travel in `id_token_disclosures` over the client-authenticated back channel, treated as credential-grade data: excluded from logs and caches, transport-protected. A stealable artifact then carries nothing worth stealing even when the opt-in is armed.

**Evidence.**
- Code: `server/services/token/service.go` — `WithIDTokenGenerator` option (assembly-wired, default off).
- Code: `server/services/token/grant_authorization_code.go` — the opt-in mint in `mintAuthorizationCodeTokens` (nonce, auth event, pairwise subject, aud = client_id; no persistence).
- Code: `sdk/token/sd/generators.go` — `IDTokenWithSelectiveDisclosure` (metadata-sourced `nonce`/`acr`/`auth_time`).
- Code: `server/httpkit/token.go` — `id_token` + `id_token_disclosures` response parameters.
- Test: `Test_service_authorizationCode_idtoken` (unit), `TestSDIDTokenHTTPResponse` + `TestSDIDTokenDefaultOff` (integration).

---

## 5. Replay and lifecycle

### D-16 — Replay surfaces are eliminated deterministically — **ENHANCES**

**Decision.** Single-use artifacts (authorization codes, PAR `request_uri`s, device codes, CIBA `auth_req_id`s) are consumed by an atomic delete-and-get. The consume happens before the checks that follow: a wrong verifier or wrong client still burns the artifact. Replayable identifiers (DPoP `jti`, client-assertion `jti`, attestation PoP `jti`) burn only after full validation. Garbage cannot pre-burn an honest party's jti.

**Relation.** RFC 9700 and RFC 9449 ask for replay protection per mechanism. The atomicity and the burn-ordering are beyond any of the texts.

**Override statement.** The AS MUST consume a single-use artifact atomically before it checks the redemption request. The AS MUST burn a replayable jti only after full validation of the proof.

**Reason.** Check-then-delete fails under concurrency, and attacks start under concurrency. The burn-after-validation ordering also removes a denial-of-service path: garbage proofs cannot consume honest jtis.

**Evidence.**
- Code: `storage.AuthorizationRequestReader.DeleteAndGet` — the atomic consume interface (fix for model finding F3).
- Code: `server/services/token/grant_authorization_code.go:93` — atomic code consume, burn-before-check.
- Code: `sdk/dpop/verifier.go:157-161` — the jti cache check runs last, after full validation.
- Code: `server/clientauthentication/client_attestation.go:257-259` — the attestation jti is burned after full validation (draft §12.1).
- Model: burn-before-check pinned by `spec/solid.qnt` deterministic tests (code single-use with wrong verifier and wrong client).

### D-17 — Token-exchange delegation chains are depth-capped, fail-closed — **REPRESENTS** RFC 8693, **HARDENS**

**Decision.** Token exchange preserves subject, client attribution, and scope narrowing (never widening). `may_act` gates actors. The `act` chain is capped at depth 3, enforced fail-closed: an over-deep chain is rejected, never truncated. The subject token's confirmation carries over with secure-compare. `authorization_details` are carried verbatim for the target resource server to evaluate.

**Relation.** RFC 8693 §4.4 leaves chain policy to server discretion. SolID represents the §4.1.3 and §5 semantics and fills the discretion per OR-3.

**Override statement.** The AS MUST reject a token-exchange request whose resulting act chain exceeds depth 3. The AS MUST NOT silently truncate the chain. The AS MUST propagate the subject token's confirmation without strip-or-swap.

**Reason.** Every delegation hop is another party that may have mis-delegated. Unbounded chains are a privilege-laundering vector and an unbounded resolution cost. Truncation would misrepresent authorization history to the resource server. Consent-narrowing of `authorization_details` at this AS would require a consent store the AS does not assume. The target RS is the evaluation authority (exercised in `examples/agentclient`).

**Evidence.**
- Code: `server/services/token/grant_token_exchange.go:45` — `maxActChainDepth = 3`.
- Code: `server/services/token/grant_token_exchange.go:249-251` — fail-closed rejection.
- Code: `server/services/token/grant_token_exchange.go:196` — cnf secure-compare.
- Test: `TestRFC8693_MayActEnforced` (`integration/rfc8693_exchange_test.go:136`), `integration/identity_chaining_act_test.go`, `integration/rfc9396_token_exchange_details_test.go`.
- Model: `spec/tokenexchange.qnt` properties T1-T8 — model-checked, `NoError` (`spec/README.md`).

---

## 6. Platform

### D-18 — Application-type strict profiles gate the surface — **ENHANCES**

**Decision.** `server/profile` maps each client `application_type` (`web`, `native`, `device`, `service`) to an allowlist of grant types, response types, and token-endpoint auth methods. `browser` is deliberately excluded. Enforcement lives in the shared HTTP layer, so every assembly inherits it. A client whose application type has no profile entry falls back to its registration metadata.

**Relation.** RFC 7591 checks a client's declared metadata against server capability. The standard trusts the client's declaration. The profile layer adds a server-side gate the standards never define.

**Override statement.** A client MUST NOT receive a grant type, response type, or auth method outside its application-type profile. The `browser` application type MUST NOT be registered into any flow surface.

**Reason.** The deployer selects a use case. The security posture comes with the selection. It does not arrive as an intersection of per-client options that each deployer must understand. This is the README thesis, applied at registration time.

**Evidence.**
- Code: `server/profile/profile_strict.go` — the four profiles, empty service response types, asymmetric-only methods.
- Code: `server/profile/gates.go` — `AllowsGrantType` and `AllowsResponseType`.
- Code: enforcement in `server/httpkit` shared handlers.

### D-19 — Protovalidate-first, three-level validation — **ENHANCES**

**Decision.** Syntactic request validation lives in protovalidate annotations on the protobuf domain model: required fields, length bounds, URI and charset patterns. One example is the RFC 7636 §4.2 PKCE challenge charset. Every service runs it as a uniform first level. Semantic checks (cross-field rules, storage state, cryptography) live in business logic. Adversarial tests in `integration/` pin the behavior.

**Relation.** The RFCs specify validation outcomes, not where the code implements them. Centralizing the syntactic layer in the schema makes the standard's format rules executable and reviewed once, instead of re-implemented per endpoint and per transport.

**Reason.** This is what makes D-01 safe: a CoAP adapter cannot forget a bound that lives in the message schema.

**Evidence.**
- Code: `proto/oidc/**` — annotations.
- Code: `server/services/authorization/service.go:316-320` — `msgval.ValidateOrError` first level.
- Code: `server/services/backchannel/service_test.go:85` — the test injects algorithms at construction. The code does not hard-code them.

### D-20 — Quint formal models pin the flow cores — **ENHANCES** (beyond any standard)

**Decision.** An executable Quint specification mirrors each grant core: state, actions, invariants, witnesses (`spec/*.qnt`). Sampled simulation, exhaustive bounded model checking (Apalache, depth 5, all `NoError`), and deterministic scenario tests prove each model. The models are ground truth for their flow. An implementer MUST re-check the model before changing the mapped source files. An implementer MUST NOT edit a spec to match broken code.

**Relation.** No implemented RFC asks for formal verification. The invariants encode the standards' security intents (RFC 9700 §4.5 and §4.14.2, RFC 8693 §4.1.3 and §5, CIBA §10, pairwise injectivity). The models represent the standards' goals in a stronger formalism.

**Reason.** Single-use, family revocation, key continuity, and pairwise disjointness are state-machine properties. Tests sample them. Model checking exhausts them. The modeling pass paid for itself: findings F1-F4 (DPoP jkt parsed but never checked, PAR confirmation dropped, non-atomic PAR consume, unvalidated resource indicators). The code fixes landed before the gaps became attack surface (`spec/README.md`).

**Evidence.**
- Model: `spec/solid.qnt` I1-I7, `spec/xaa.qnt` J1-J7, `spec/clientcredentials.qnt` CC1-CC6, `spec/devicecode.qnt` D1-D7, `spec/tokenexchange.qnt` T1-T8, `spec/ciba.qnt` B1-B8 — verification runs recorded in `spec/README.md`.
- Code: findings F1-F4 fixes cited in `spec/README.md`.

### D-21 — CIMD documents are policy-governed before enforcement — **REPRESENTS + HARDENS**

**Decision.** Client ID Metadata Documents fetched at resolution time pass through a client metadata policy (OpenID Federation 1.0 §6.1.3.1 standard operators: `value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, `essential`, applied in the spec's order) BEFORE the draft's §4.1 credential and key-material enforcement. The policy-applied document is what the restrictions validate. The policy is operator configuration at assembly level (`cimd.NewPolicyResolver`), one global JSON object per deployment, applied inside the operator-pinned allow-list. A violation fails the whole client — the same unknown-client error surface as an unfetchable document.

**Relation.** OpenID Federation 1.0 Final (vendored, `docs/rfcs/openid-federation-1_0.txt`) defines the operators for Trust Chain metadata. SolID applies the vocabulary to a different transport (CIMD over the OAuth client role) without the federation trust machinery. Two hardenings: policy entries naming `client_id` are rejected outright (the identifier match of draft §4 is an invariant a policy must not rewrite — the Federation spec has no such rule); and the before-enforcement ordering itself (the spec has no equivalent because its enforcement point differs).

**Override statement.** A fetched client's final metadata is the policy-applied document, never the raw fetch. The §4.1 restrictions (no shared-secret methods, no secrets, no private key material) MUST validate the final document. Redirect URIs in the final document (including policy-added ones) MUST be https or RFC 8252 loopback, fragment-free — the same rule the registration endpoint enforces.

**Reason.** A fetched client should behave like a well-registered one: the operator defaults, constrains, and augments remote metadata instead of trusting it to self-declare a secure posture. The example AS policy defaults `dpop_bound_access_tokens` for CIMD clients — the AI-agent examples (`agentclient`, `mcpserver`) prove DPoP on every token request accordingly (actor tokens mint `token_type: DPoP` with `cnf.jkt`), and the pre-policy gap (a proof-less client_credentials mint for the agent) is closed by the policy, not by trusting the remote document.

**Evidence.**
- Code: `sdk/cimd/policy.go` — the seven operators, spec application order, Table 1 essential+subset matrix, scope space-list rule.
- Code: `sdk/cimd/resolver.go` — `NewPolicyResolver` seam (policy between identifier match and `ToClient`), double client_id re-check.
- Code: `sdk/cimd/document.go` — redirect-URI gate on the final document (gap closed).
- Code: `examples/authorizationserver/main.go` — the demonstration policy inside the allow-list stack.
- Tests: `sdk/cimd/policy_test.go` (16 operator cases incl. the smuggle-proof order), `policy_resolver_test.go` (9 e2e/adversarial incl. the AI-agent dpop default), `client_cimd_e2e_test.go` (+2 policy subtests). Live end-to-end run recorded in `docs/COMPLIANCE_REPORT.md` §2.52.

---

## 7. Decision index

| # | Decision | Standard(s) | Relation |
|---|---|---|---|
| D-01 | Transport-agnostic protocol core | none (architecture) | ENHANCES |
| D-02 | Token serialization is an assembler decision | RFC 6750, 7519, 8392 | ENHANCES |
| D-03 | `code` only, no implicit, no hybrid | RFC 6749 vs RFC 9700 §2.1.2 | NEGATES / HARDENS |
| D-04 | PAR-only authorization entry | RFC 9126 | ENHANCES + HARDENS |
| D-05 | Signed request objects mandatory | RFC 9101 | REPRESENTS + HARDENS |
| D-06 | JARM-only response modes | FAPI JARM, RFC 9207 | HARDENS |
| D-07 | PKCE mandatory, S256-only, all clients | RFC 7636, 9700 §2.1.1, v2-1 §7.5.2 | HARDENS |
| D-08 | Device grant: no RT, one-time codes, throttle | RFC 8628, 10027 | REPRESENTS + HARDENS |
| D-09 | CIBA poll-only, binding message required, no RT | CIBA Core, 9700 §4.12.2 | REPRESENTS + HARDENS |
| D-10 | Asymmetric client auth only | RFC 6749 §2.3.1 vs RFC 7523/8705/drafts | NEGATES / REPRESENTS |
| D-11 | EC + ML-DSA algorithms only, double allowlists | RFC 8725 §3.4/§3.5, RFC 9964 | NEGATES / REPRESENTS |
| D-12 | No PII in tokens, pairwise subjects, no `id_token` | OIDC Core | NEGATES / ENHANCES |
| D-13 | Unconditional refresh rotation + family revocation | RFC 9700 §4.14.2 vs v2-1 §4.3.3 | HARDENS (stronger side) |
| D-14 | Sender-constrained tokens, in-core gate | RFC 9449, RFC 8705 §3 | REPRESENTS + HARDENS |
| D-15 | Introspection as opt-in disclosure | RFC 7662 §2.1/§2.2 | REPRESENTS + HARDENS |
| D-16 | Deterministic replay elimination | RFC 9700/9449 (beyond) | ENHANCES |
| D-17 | act-chain depth cap, fail-closed | RFC 8693 §4.4 | REPRESENTS + HARDENS |
| D-18 | Application-type strict profiles | RFC 7591 (beyond) | ENHANCES |
| D-19 | Protovalidate-first three-level validation | none (architecture) | ENHANCES |
| D-20 | Quint formal models as flow ground truth | none (beyond standards) | ENHANCES |
| D-21 | CIMD documents are policy-governed before enforcement | OpenID Federation 1.0 §6.1.3.1, CIMD-02 | REPRESENTS + HARDENS |

---

## 8. Maintenance

An implementer MUST follow these rules when a decision above conflicts with new work.

1. **Supersede, never relax quietly.** A change to any decision requires a new dated entry in this document. The entry states what changed and why (OR-4).
2. **One direction only.** A decision moves toward the stricter side, never toward the weaker option of the standard (OR-5). A move toward the weaker side is a project non-goal.
3. **Track advancing drafts.** When a vendored draft advances (draft-ietf-oauth-v2-1, attestation-based-client-auth, identity-chaining), apply OR-1 and OR-2. If the new text weakens a HARDENS position, SolID stays. If the new text hardens further, follow it.
4. **Update anchors, not decisions.** The file:line anchors reflect the tree of 2026-10-08. After a refactor, update the anchor. The executable proof lives in `docs/COMPLIANCE_REPORT.md`. This document argues why. That document proves what.
5. **Check before changing pinned cores.** Re-check the mapped Quint model before changing any file listed in `spec/README.md` "When to update".

---

*Verification basis: the author verified every code anchor on the working tree of 2026-10-08 (commit `e03a55b` plus staged token-exchange work). The author checked every RFC quote against the vendored text in `docs/rfcs/`. Model claims transcribe the verification runs recorded in `spec/README.md`. Compliance claims transcribe the executed-test audit in `docs/COMPLIANCE_REPORT.md` (2026-09-28).*
