# SolID

Integrated end-to-end identity provider and authorization server based on OIDC
with security and privacy by design philosophy.

This will not provide a full-featured OIDC Server but a limited and secure
settings according to your use cases.

Many OIDC providers give you a lot of features that you have to understand and
choose to maximize your security posture. So that your security posture is correlated
to your understanding of OAuth and OIDC. I don't like this idea to be honnest.

I'm developing OAuth provider since 8 years now, in multiple languages and
environments, and I saw each time the same thing: `people don't understand
flows`.

I understand the requirements of commercial products to have a wide compatibilty
matrix, but by allowing insecure settings for one client you can compromise the
whole platform, and also lose the customer inside the features fog.

That's the reason why I've started this project as an OSS project, to provide a
simple and solid implementations of 4 OAuth flows :

* online users using `authorization_code` flow with mandatory PKCE via Pushed
  Authorization Request with state enforcement;
* service account using `client_credentials` based on asymetric authentication
  schemes;
* devices and constrained environments, you know for IO(v)T (Internet Of vulnerable Thing);
* offline users using `refresh_token` flow for application that need to act as
  an online user but without its online interaction.

## Objectives

* Enforce OIDC features as a complete suite according to selected use-case;
* Provide a complete toolchain to enforce security and privacy without the
  complete knowledge of all related protocols;
* Enhance security posture based on security objectives not the understand of
  security protocols;
* Provide a battle-tested framework;

## What is not

* A complete OIDC compliant server. By making some **optional** and **recommended**
  parameters as **required**, `solid` can't pass the OIDC compliance tests;

## Features

* Storage
  * Client
    * [x] Confidential client
    * [x] Public client
  * Requests
    * [x] Authorization request
* [ ] Dynamic client registration - [rfc7591](https://tools.ietf.org/html/rfc7591)
* OAuth Grant Types
  * [x] `client_credentials` flow
    * [x] `private_key_jwt` client authentication
    * [ ] `tls_client_auth` client authentication
  * [x] `authorization_code` flow
    * [x] [PKCE](https://oauth.net/2/pkce/) - [rfc7636](https://tools.ietf.org/html/rfc7636)
    * [x] [Pushed Authorization Request](https://oauth.net/2/pushed-authorization-requests/) (PAR) - [draft-ietf-oauth-par-01](https://tools.ietf.org/html/draft-ietf-oauth-par-01)
  * [ ] `device_code` flow
  * [ ] `refresh_token` flow
* Token
  * [ ] Generic key manager
  * [ ] JWT support
  * [ ] mTLS constrained tokens - [draft-ietf-oauth-mtls-17](https://tools.ietf.org/id/draft-ietf-oauth-mtls-17.html)
* Privacy
  * [ ] Pairwise subject identifier
  * [ ] Phantom token flow
  * [ ] Consent

## References

* [OAuth 2.0](https://oauth.net/2/)
* [OAuth 2.0 Client Authentication](https://medium.com/@darutk/oauth-2-0-client-authentication-4b5f929305d4)
* [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15)
* [Why you should stop using the OAuth implicit grant!](https://medium.com/@torsten_lodderstedt/why-you-should-stop-using-the-oauth-implicit-grant-2436ced1c926)
* [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.html)
