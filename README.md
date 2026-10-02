# SolID

An OIDC authorization server building blocks with security and privacy by design
philosophy.

This will not provide a full-featured standalone OIDC Server but a limited and
secure settings according to your use cases :

* `online users` using `authorization_code` flow with mandatory PKCE via Pushed
  Authorization Request with state enforcement;
* `machine-to-machine` using `client_credentials` based on asymetric
  authentication schemes;
* `devices and constrained environments`, you know for IO(v)T (Internet Of vulnerable Thing);
* `offline users` using `refresh_token` flow for application that need to
  `act as an online user but without its online interaction`.
* `impersonation / delegation` using `token_exchange` flow fro resource server
  who wants to access authenticated external resource on behalf of the subject
  with a restricted resource level privilege set.

## What and Why

I have been developing OAuth/OIDC/UMA providers since 2012, in multiple
languages and environments. `People generally don't understand` OIDC flows.

> It's like driving a car that requires you to know how engine work and how
> the car is built. But the only thing you want is to drive your car.

OAuth / OIDC is often criticized in favor of SAML, but implementations are more
vulnerables than the protocol itself. OAuth is just offered as a developer
framework, but it's true to say that not all developers are aware of security
problems.

Implementations are done by developers that don't have/take the time to browse
the specification maze, they read them quickly with their own belief in mind.
As a consequence the specifications are not understood but barely interpreted,
that will produce faulty implementations.

> Also security products are often associated with [NIH](https://en.wikipedia.org/wiki/Not_invented_here) syndrom.

What I observed in real life:

* Not using `authorization_code` because it doesn't have user/password in the
  flow;
* `client_credentials` grant type to be used as `customer credentials` like
  `password` grant type but for external customer user access (login form with
  client credentials);
* Using `client_credentials` from a JS public UI (hardcoded client_secret);
* Dynamic authorization application based on token claims without signature
  checks;
* Authentication based on the fact the you can retrieve the token ... not
  validating token content (Token is here => You are admin);

Many OIDC providers give you a lot of features that you have to understand and
choose to maximize your security posture. So that your security posture is
correlated to your understanding of OAuth and OIDC and their implementations
in the product.

> I don't like this idea to be honest.

I understand the requirements of commercial products to have a wide compatibility
matrix, but by allowing insecure settings for one client you can compromise the
the whole platform, and also lose the customer inside the `feature fog`.

But OAuth / OIDC specification are only tools in a toolbox, and they need to be
orchestrated in a proper way to provide a simple, efficient and secure service.

That's the reason why I've started this project as an OSS project, to provide a
simple and solid implementations of 4 OAuth flows.

## Objectives

* Enforce OIDC features as a complete suite according to selected use-case;
* Provide a complete toolchain to enforce security and privacy without the
  complete knowledge of all related protocols;
* Enhance security posture based on security objectives not the understand of
  security protocols;
* Provide a battle-tested framework;
* Provide a wire protocol decoupled framework, OIDC is tighly coupled to HTTP but
  it can be easily decoupled to become portable between other wire protocols (CoAP);

## What is not

* A complete OIDC compliant server. By making some **optional** and **recommended**
  parameters as **required**, `solid` can't pass the OIDC compliance tests;

## Getting started

I made sample server and various integrations inside `examples/` folder.
See [`examples/README.md`](examples/README.md) for how to run them; every
example directory also carries a `README.md` with a mermaid sequence diagram
describing the exact flow its `main.go` implements.

## Features

### Protocol changes

* `PAR+DPoP+JARM` is enabled and enforced for `authorization_code` flow;
* `hybrid` flow is not and will be supported; Web applications must use server
  side component (or lambda) to negociate authorizations; By design, your
  client-side application code (JS) should not be exposed until you are identified;
* Only response_type `code` will be supported to enforce server-side negociation;
* `PKCE+Nonce` is enforced by default for all client types during `authorization_code`
  flow;
* `authorization_code` flow could not be started by the `user-agent`, as the
  default behavior, the `client` must use PAR protocol to retrieve a `request_uri`
  that will qualify and start the `authorization_code` flow;
* Asymetric authentication methods are enforced by default;
* No `HSxxx` / `RSxxx` support as JOSE signature algorithms;
  * `HSxxx` doesn't provide digital signature;
  * `RSxxx` uses RSA algorithms that needs to have high computation to improve
    security protection level so that it will be more difficult for constrained
    environment (IoT) to have same security protection level as a normal application;
  * Only `elliptical curves` involved algorithms will be used;
* `access_token` / `refresh_token` are `hybrid` tokens so that they embed protocol
  validation details (expiration, etc.) without any privacy related info (sub).
  These informations are referenced via an embeded `jti` claim that will address
  an AS-only accessbile record that will contains extra data;
* `audience` parameter is mandatory for request that need `scope` in order to
  target the corresponding application. This will allow various validations between
  `client` and `application`, and `consent` management;
* `PAR` must use JWT encoded request payload to due request registration;
* Application-type profiles (`server/profile`) constrain clients whose
  `application_type` maps to a strict profile entry — grant types, response
  types and token-endpoint authentication methods per profile (`web`, `native`,
  `device`, `service`; `browser` deliberately excluded). Enforcement lives in
  the shared HTTP layer (`server/httpkit`) so every assembly inherits it;
  clients without a profile-known application type fall back to their
  registration metadata.
* Token serialization is an assembler decision: the same transport-agnostic
  services mint opaque verifiable reference tokens (signed UUIDv7), JWTs,
  HPKE-encrypted JWTs, or RFC 8392 CWTs — see `sdk/token` and the
  `SOLID_EXAMPLE_TOKEN_FORMAT` switch in `examples/coapace`.
* Syntactic request validation (required fields, length bounds, charset
  patterns) is expressed as `buf.validate` annotations on the protobuf domain
  model (`proto/oidc/**`) and enforced by a protovalidate first level in every
  service; semantic rules stay in business logic.

### Framework

* OAuth Core
  * [x] [draft-ietf-oauth-v2-1-16 - The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — vendored (`docs/rfcs/draft-ietf-oauth-v2-1-16.txt`), core requirements enforced and adversarially tested (`integration/oauth21_adversarial_test.go`)
  * [x] [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) — implemented and adversarially tested (`integration/`)
  * [x] [draft-ietf-oauth-security-topics-update-03 - Updates to OAuth 2.0 Security Best Current Practice](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-update-03.txt) — vendored and adversarially tested (`integration/securities_adversarial_test.go`); AS-side audience hardening (§2.1) and client-side issuer-identifier audience (§2.1.2.1) applied
* OAuth Extensions
  * Discovery
    * [x] [RFC8414 - OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
  * Identity authentication
    * [ ] [Nonce pattern authenticator](https://curity.io/resources/learn/nonce-authenticator-pattern/)
  * Cross-App Access / identity chaining
    * [x] [RFC8693 - OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693) — `token_exchange` grant with `may_act` gating, `act` delegation-chain preservation (fail-closed depth cap), and confirmation (`cnf`) key binding carried over secure-compared
    * [x] [draft-ietf-oauth-identity-chaining-17 - OAuth 2.0 Identity Chaining](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining) — identity-chained access tokens minted via token exchange; `act`/`may_act` semantics adversarially tested (`integration/identity_chaining_act_test.go`)
    * [x] [draft-ietf-oauth-identity-assertion-authz-grant-04 - OAuth 2.0 Identity Assertion Authorization Grant (Cross-App Access)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) — ID-JAG issuance at the IdP AS, redemption by the Resource AS via the JWT Bearer grant (`sdk/idjag`, `server/services/token`); serialization-format agnostic, pairwise subject identifiers, adversarially tested (`integration/idjag_adversarial_test.go`)
  * Client authentication
    * Asymmetric authentication
      * [x] [RFC7523 - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
      * [x] [RFC7521 - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7521.html)
      * [x] `private_key_jwt` - <https://oauth.net/private-key-jwt/>
      * [x] `attest_jwt_client_auth` - [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) — header transport (`OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP`) with attestation `typ: oauth-client-attestation+jwt` and PoP `typ: oauth-client-attestation-pop+jwt` (draft-11 §§4, 5.1), registry-pinned Client Attester trust, `cnf` private-material rejection, `client_id`↔`sub` binding (§7.5), jti-burn replay protection (§12.1); adversarially tested (`integration/attestation_adversarial_test.go`, demo client in `examples/attestationclient`)
      * [x] `spiffe_jwt` / `spiffe_wit` / `spiffe_x509` - [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) — all three SVID credential types (JWT-SVID via `client_assertion_type: ...jwt-spiffe`, WIT-SVID via the attestation headers, X.509-SVID via mutual TLS); trust-domain signing keys resolved exclusively from `BundleSource`s keyed by trust domain (draft §6: static pre-configured bundles or SPIFFE bundle endpoints with refresh-hint polling, `sdk/spiffe`), never from SVID issuer claims (§8.1); fail-closed `spiffe_id` client binding with `/*` path-segment wildcards (§5.1); implemented and adversarially tested (`integration/spiffe_test.go`, demo client in `examples/spiffeclient`)
      * [x] `tls_client_auth` - [RFC8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/rfc8705) — PKI mutual-TLS client authentication (§2.1): the TLS peer certificate is matched fail-closed against exactly one registered subject binding (`subject_dn`, `san_dns`, `san_uri`, `san_ip` binary-compared, `san_email`; `server/clientauthentication/tls_client_auth.go`); certificate-bound tokens via the `x5t#S256` `cnf` member (§3.1, `sdk/token`), enforced at the refresh grant (§7.1) and the example resource server; RFC Appendix A fixture-anchored and adversarially tested (`integration/rfc8705_mtls_test.go`)
  * Grant Types
    * [x] `client_credentials` grant type
    * [x] `authorization_code` grant type
      * [x] [RFC7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636) - <https://oauth.net/2/pkce/>
      * [x] [RFC9126 - OAuth 2.0 Pushed Authorization Requests (PAR)](https://tools.ietf.org/html/rfc9126.html) - <https://oauth.net/2/pushed-authorization-requests/>
      * [x] [RFC9101 - The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://tools.ietf.org/html/rfc9101) (JAR)
      * [x] [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/openid-financial-api-jarm.html)
      * [x] [RFC9207 - OAuth 2.0 Authorization Server Issuer Identification](https://tools.ietf.org/html/rfc9207.html)
      * [x] [RFC9396 - OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396) (`authorization_details` carried in JAR request objects; deep-equal subset narrowing at the token endpoint; fail-closed for `client_credentials`/`token_exchange`)
    * [x] `refresh_token` grant type
    * [x] RFC8628 - `urn:ietf:params:oauth:grant-type:device_code` grant type — `expired_token` / `access_denied` / `slow_down` semantics all enforced server-side - [rfc8628](https://tools.ietf.org/html/rfc8628)
    * [x] [RFC7523 - JWT Bearer grant](https://tools.ietf.org/html/rfc7523#section-4) — `urn:ietf:params:oauth:grant-type:jwt-bearer` (`server/services/token/grant_jwt_bearer.go`); used to redeem ID-JAG assertions at the Resource AS
    * [x] `urn:openid:params:grant-type:ciba` grant type — [OpenID Connect Client Initiated Backchannel Authentication Flow](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) (poll delivery mode; `binding_message` promoted to required; signed request objects verified against client JWKS; optional `dpop_jkt` session binding with enforced proof-of-possession at the token endpoint — RFC 9449 §10; `authorization_details` fixed at bc-authorize time; no refresh tokens, `offline_access` stripped — RFC 9700 §4.12.2) — adversarial tests in `integration/ciba_adversarial_test.go`
  * Resource
    * [x] [RFC8707 - Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/rfc8707)
    * [x] [RFC9470 - OAuth 2.0 Step Up Authentication Challenge Protocol](https://tools.ietf.org/html/rfc9470)
    * [x] [RFC9728 - OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
  * Client
    * [x] [RFC7591 - OAuth 2.0 Dynamic Client Registration](https://tools.ietf.org/html/rfc7591) — minimal defensive dynamic client registration via the gRPC `ClientRegistrationService` (`server/services/clientregistration`): asymmetric auth methods only (no client secrets issued), `code` response type only, implemented-grant allowlist, loopback-redirect exception, operator-gated
    * [x] [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592) — Read/Update/Delete via the gRPC `ClientRegistrationManagementService` (`server/grpckit`): per-client registration access token issued at registration time is the sole management credential (invalid-token attempts revoke it), updates are full replacement re-validated with the RFC 7591 rules, delete removes the client and revokes every issued token; no client secrets
    * [x] [(DRAFT) OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)
    * [ ] [OAuth 2.0 Client ID Scheme](https://datatracker.ietf.org/doc/html/draft-looker-oauth-client-id-scheme)
  * Tokens
    * Privacy
      * [x] [Pairwise subject identifier](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
      * [x] [RFC 9901 - Selective Disclosure for JSON Web Tokens (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.txt) — `sdk/sdtoken` core (wire-agnostic disclosure forgery/processing) with the JWT serialization in `sdk/sdtoken/sdjwt`: compact-serialization SD-JWT/SD-JWT+KB issuer/holder/verifier, recursive disclosures, decoy digests, mandatory key binding posture; vendored (`docs/rfcs/rfc9901.txt`); adversarially tested (`integration/sdjwt_adversarial_test.go`)
      * [x] [draft-ietf-spice-sd-cwt-08 - Selective Disclosure CBOR Web Tokens (SD-CWT)](https://www.ietf.org/archive/id/draft-ietf-spice-sd-cwt-08.txt) — `sdk/sdtoken/sdcwt`: COSE_Sign1 SD-CWT/KBT issuer/holder/verifier with `redacted_claim_keys` (simple 59) / tag 60 elements, nesting and decoy validation, definite-length and duplicate-map-key enforcement; adversarially tested (`integration/sdcwt_adversarial_test.go`)
    * Scheme
      * [x] [RFC6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
      * [x] [RFC7800 - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)](https://datatracker.ietf.org/doc/html/rfc7800) 
      * [x] [RFC9449 - OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
      * [x] [RFC8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/rfc8705) — certificate-bound tokens (`x5t#S256` `cnf` member, §3.1); client authentication (`tls_client_auth` / `self_signed_tls_client_auth`) listed under Client authentication
    * Authentication by reference
      * [x] Random string
      * [x] Verifiable token (signed UUID)
    * Authentication by value
      * [x] [RFC7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
      * [x] [RFC8392 - CBOR Web Token (CWT)](https://www.rfc-editor.org/rfc/rfc8392) — COSE_Sign1 signers/verifiers (`sdk/token/cwt`, elliptic-curve + ML-DSA algorithms only, RFC 8392 §7.1 claim keyasint map); wired as an alternative token generator in the CoAP/ACE example (`SOLID_EXAMPLE_TOKEN_FORMAT=cwt`) and round-trip tested through the real token service (`integration/cwt_token_test.go`)
      * [x] [draft-ietf-jose-hpke-encrypt-22 - Use of HPKE with JWE](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/) — token encryption strategy `sdk/token/hpke` (Integrated + Key Encryption modes, stdlib `crypto/hpke`); HPKE-encrypted JWT access/refresh tokens in `examples/authorizationserver`; RFC conformance via draft Appendix A vectors (`sdk/token/hpke/testdata/jose-vectors.json`); adversarially tested (`integration/jose_hpke_test.go`)
      * [x] [draft-ietf-cose-hpke-27 - Use of HPKE with COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/) — CWT token encryption strategy `sdk/token/cwt` (`CoseHPKEEncrypter` / `CoseHPKEKeyEncryptionEncrypter` / `CoseHPKEVerifier`, Integrated + Key Encryption modes, stdlib `crypto/hpke`); draft conformance via section 5 examples; both strategies share the wire-agnostic ciphersuite registry and key conversion of `sdk/hpke` (JWE labels + COSE identifiers)
  * Token Management
    * [x] [RFC7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
    * [x] [RFC7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)

  * Constrained Environments (ACE)
    * [x] [RFC 9200 - Authentication and Authorization for Constrained Environments (ACE-OAuth)](https://www.rfc-editor.org/rfc/rfc9200) — `application/ace+cbor` wire codec (`sdk/ace`), CBOR-abbreviated token/introspection payloads and AS Request Creation Hints; full CoAP triangle demo (`examples/coapace`, adversarially tested in `integration/ace_adversarial_test.go`)
    * [x] [RFC 9201 - COSE Profile of ACE](https://www.rfc-editor.org/rfc/rfc9201) — COSE_Key confirmation members (cnf) for PoP keys
    * [x] [RFC 9202 - DTLS Profile of ACE](https://www.rfc-editor.org/rfc/rfc9202) — `coap_dtls` profile: mutual DTLS 1.2 client authentication and certificate-bound tokens
    * [x] [RFC 8747 - Proof-of-Possession Key Semantics for CBOR Web Tokens (CWTs)](https://www.rfc-editor.org/rfc/rfc8747) — cnf confirmation members (COSE_Key by value, kid by reference) in the ACE codec

### Integrations

* HTTP
  * Authorization Server
    * [ ] Standalone
    * [x] Shared HTTP building blocks (`server/httpkit`: RFC 6749/9126/8414
      handlers, client-authentication and security-headers middleware,
      profile enforcement) — assembled by the reference example
      `examples/authorizationserver`
    * [ ] Caddy plugin
  * Reverse Proxy
    * [ ] Caddy plugin
* CoAP
  * Authorization Server
    * [x] Standalone (RFC 9200 ACE-OAuth over mutual DTLS 1.2 — `examples/coapace`, `sdk/ace` CBOR wire codec; coap_dtls profile per RFC 9202)
* AWS
  * Auhtorization Server
    * [x] AWS Lambda

## References

* [OAuth 2.0](https://oauth.net/2/)
* [OAuth 2.0 Client Authentication](https://medium.com/@darutk/oauth-2-0-client-authentication-4b5f929305d4)
* [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
* The standard texts of the implemented RFCs (6749, 7009, 7521, 7523, 7636, 7662, 8392, 8414, 8693, 8705, 8747, 9101, 9126, 9200, 9201, 9202, 9207, 9396, 9449, 9700, 9728, 10027) and drafts (draft-ietf-oauth-v2-1-16, draft-ietf-oauth-client-id-metadata-document-02, draft-ietf-oauth-identity-assertion-authz-grant-04, draft-ietf-oauth-identity-chaining-17, draft-ietf-oauth-security-topics-update-03, draft-ietf-oauth-spiffe-client-auth-02) are vendored under `docs/rfcs/` as the source of truth for conformance and adversarial testing.
* [OpenID Connect Client-Initiated Backchannel Authentication Flow (CIBA) Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) — vendored as `docs/rfcs/openid-client-initiated-backchannel-authentication-core-1_0.txt`
* [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) — SPIFFE workload identity (SVIDs) as OAuth client credentials
* [SPIFFE](https://spiffe.io/) — Secure Production Identity Framework For Everyone (SPIFFE IDs, trust domains, SVIDs, bundle endpoints)
* [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.html)
* [Financial-grade API - Part 1: Read-Only API Security Profile](https://openid.net/specs/openid-financial-api-part-1.html)
* [Financial-grade API - Part 2: Read and Write API Security Profile](https://openid.net/specs/openid-financial-api-part-2.html)
* [PKCE vs. Nonce: Equivalent or Not?](https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/)
* [An Extensive Formal Security Analysis of the OpenID Financial-grade API](https://arxiv.org/abs/1901.11520)
* [Mix-Up, Revisited](https://danielfett.de/2020/05/04/mix-up-revisited/)
* [Financial-grade API: JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/openid-financial-api-jarm-ID1.html)
