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

* OAuth
  * Client authentication
    * [x] `private_key_jwt` client authentication
    * [ ] `tls_client_auth` client authentication
  * Core
    * [x] `client_credentials` grant type
    * [x] `authorization_code` grant type
      * [x] [PKCE](https://oauth.net/2/pkce/) - [rfc7636](https://tools.ietf.org/html/rfc7636)
      * [x] [Pushed Authorization Request (PAR)](https://oauth.net/2/pushed-authorization-requests/) (PAR) - [draft-ietf-oauth-par-01](https://tools.ietf.org/html/draft-ietf-oauth-par-01)
      * [x] [JWT Encoded Authorization Requests (JAR)](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-30) (JAR)
      * [x] [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/openid-financial-api-jarm-ID1.html)
    * [x] `refresh_token` grant type
    * [x] `device_code` grant type
    * [x] Pairwise subject identifier
    * [x] [Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/rfc8707)
  * Client
    * [ ] OAuth 2.0 Dynamic Client Registration - [rfc7591](https://tools.ietf.org/html/rfc7591)
    * [ ] OAuth 2.0 Dynamic Client Registration Management Protocol - [rfc7591](https://tools.ietf.org/html/rfc7592)
  * Token Management
    * [x] Generic API
    * [x] Introspection - [rfc7662](https://tools.ietf.org/html/rfc7662)
    * [x] Revocation - [rfc7009](tools.ietf.org/html/rfc7009)
  * Token
    * Scheme
      * [x] Bearer - [rfc6750](https://tools.ietf.org/html/rfc6750)
      * [x] DPoP - [draft-fett-oauth-dpop-04](https://tools.ietf.org/html/draft-ietf-oauth-dpop-01)
      * [ ] mTLS constrained tokens - [draft-ietf-oauth-mtls-17](https://tools.ietf.org/id/draft-ietf-oauth-mtls-17.html)
    * Authentication by reference
      * [x] Random string
    * Authentication by value
      * [x] JWT - [rfc7519](https://tools.ietf.org/html/rfc7519)
      * [ ] CWT - [rfc8392](https://tools.ietf.org/html/rfc8392)
* Storage
  * [x] API
    * Client
      * [x] Confidential client
      * [x] Public client
    * Requests
      * [x] Authorization request
    * Tokens
      * [x] Storage
    * Sessions
      * [x] AuthorizationCode
      * [x] DeviceCode
  * [x] in-memory storage
  * [ ] gRPC driven storage
* Privacy
  * [ ] Consent management

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
* [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15)
* [Why you should stop using the OAuth implicit grant!](https://medium.com/@torsten_lodderstedt/why-you-should-stop-using-the-oauth-implicit-grant-2436ced1c926)
* [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.html)
* [Financial-grade API - Part 1: Read-Only API Security Profile](https://openid.net/specs/openid-financial-api-part-1.html)
* [Financial-grade API - Part 2: Read and Write API Security Profile](https://openid.net/specs/openid-financial-api-part-2.html)
* [PKCE vs. Nonce: Equivalent or Not?](https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/)
* [An Extensive Formal Security Analysis of the OpenID Financial-grade API](https://arxiv.org/abs/1901.11520)
* [Mix-Up, Revisited](https://danielfett.de/2020/05/04/mix-up-revisited/)
* [Financial-grade API: JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/openid-financial-api-jarm-ID1.html)
