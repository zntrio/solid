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
* `PAR` must use JWT encoded request payload to due request registration.

### Framework

* OAuth Core
  * [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) - <https://oauth.net/2.1/>
  * [x] [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) — implemented and adversarially tested (`integration/`)
  * [x] [draft-ietf-oauth-security-topics-update-03 - Updates to OAuth 2.0 Security Best Current Practice](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-update-03.txt) — vendored and adversarially tested (`integration/securities_adversarial_test.go`); AS-side audience hardening (§2.1) and client-side issuer-identifier audience (§2.1.2.1) applied
* OAuth Extensions
  * Discovery
    * [x] [RFC8414 - OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
  * Identity authentication
    * [ ] [Nonce pattern authenticator](https://curity.io/resources/learn/nonce-authenticator-pattern/)
  * Client authentication
    * Asymmetric authentication
      * [x] [RFC7523 - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
      * [x] [RFC7521 - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7521.html)
      * [x] `private_key_jwt` - <https://oauth.net/private-key-jwt/>
      * [x] `attest_jwt_client_auth` - [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-looker-oauth-attestation-based-client-auth/)
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
    * [x] RFC10027 - BCP 247 cross-device flow security — device grant hardened: one-time device codes, server-enforced polling interval (`slow_down`), user-code attempt throttling, DPoP-flag enforcement, no refresh tokens from the device grant; proximity / trusted-device mitigations are deployment concerns - [rfc10027](https://www.rfc-editor.org/rfc/rfc10027.txt)
    * [ ] `urn:openid:params:grant-type:ciba`grant type - [OpenID Connect Client Initiated Backchannel Authentication Flow](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
  * Resource
    * [x] [RFC8707 - Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/rfc8707)
    * [x] [RFC9470 - OAuth 2.0 Step Up Authentication Challenge Protocol](https://tools.ietf.org/html/rfc9470)
    * [x] [(DRAFT) OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-resource-metadata-03.html)
  * Client
    * [ ] [RFC7591 - OAuth 2.0 Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
    * [ ] [RFC7592 - OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)
    * [x] [(DRAFT) OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)
    * [ ] [OAuth 2.0 Client ID Scheme](https://datatracker.ietf.org/doc/html/draft-looker-oauth-client-id-scheme)
  * Tokens
    * Privacy
      * [x] [Pairwise subject identifier](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
    * Scheme
      * [x] [RFC6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
      * [x] [RFC7800 - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)](https://datatracker.ietf.org/doc/html/rfc7800) 
      * [x] [RFC9449 - OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
      * [ ] [RFC8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/rfc8705)
    * Authentication by reference
      * [x] Random string
      * [x] Verifiable token (signed UUID)
    * Authentication by value
      * [x] [RFC7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
      * [x] PASETO - [draft-paragon-paseto-rfc-00](https://paseto.io/)
      * [x] [RFC8392 - CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392)
  * Token Management
    * [x] [RFC7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
    * [x] [RFC7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
    * [x] (DRAFT) - JWT Response for OAuth Token Introspection - [draft-ietf-oauth-jwt-introspection-response](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-12)

### Integrations

* HTTP
  * Authorization Server
    * [ ] Standalone
    * [ ] Caddy plugin
  * Reverse Proxy
    * [ ] Caddy plugin
* CoAP
  * Authorization Server
    * [ ] Standalone
* AWS
  * Auhtorization Server
    * [x] AWS Lambda

## References

* [OAuth 2.0](https://oauth.net/2/)
* [OAuth 2.0 Client Authentication](https://medium.com/@darutk/oauth-2-0-client-authentication-4b5f929305d4)
* [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
* The standard texts of the implemented RFCs (6749, 7009, 7523, 7636, 7662, 8628, 8693, 9101, 9126, 9207, 9396, 9449, 9700, 9728, 10027) and drafts (draft-ietf-oauth-client-id-metadata-document-02, draft-ietf-oauth-security-topics-update-03, draft-ietf-oauth-spiffe-client-auth-02) are vendored under `docs/rfcs/` as the source of truth for conformance and adversarial testing.
* [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) — SPIFFE workload identity (SVIDs) as OAuth client credentials
* [SPIFFE](https://spiffe.io/) — Secure Production Identity Framework For Everyone (SPIFFE IDs, trust domains, SVIDs, bundle endpoints)
* [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.html)
* [Financial-grade API - Part 1: Read-Only API Security Profile](https://openid.net/specs/openid-financial-api-part-1.html)
* [Financial-grade API - Part 2: Read and Write API Security Profile](https://openid.net/specs/openid-financial-api-part-2.html)
* [PKCE vs. Nonce: Equivalent or Not?](https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/)
* [An Extensive Formal Security Analysis of the OpenID Financial-grade API](https://arxiv.org/abs/1901.11520)
* [Mix-Up, Revisited](https://danielfett.de/2020/05/04/mix-up-revisited/)
* [Financial-grade API: JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/openid-financial-api-jarm-ID1.html)
