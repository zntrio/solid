# CIBA Client (poll mode, DPoP-bound)

Drives the full OpenID CIBA Core 1.0 round trip in poll mode with a signed
request object and a DPoP key binding:

* client authentication with `private_key_jwt` (ES256, fresh assertion per
  request — each `jti` is single-use),
* all authentication request parameters — including the DPoP key
  thumbprint `dpop_jkt` — carried inside the signed request object
  (CIBA §7.1.1),
* end-user approval on the authentication device (the AS `/backchannel`
  endpoint standing in for the user's phone),
* token-endpoint polling with a fresh DPoP proof of the bound key per poll.

Prerequisite: `authorizationserver` running (see [`../README.md`](../README.md)).

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as cibaclient (ES256 fixture key)
    participant BC as AS /bc-authorize
    participant AD as Authentication device
    participant T as AS /token

    C->>C: compute key thumbprint (RFC 7638) → jkt
    C->>C: sign request object: iss=client_id, aud=issuer, exp/iat/nbf/jti, scope, login_hint, binding_message, dpop_jkt
    C->>BC: POST request + client assertion
    BC->>BC: verify signature vs client JWKS, alg allowlist (ES256)
    BC->>BC: resolve login_hint "hello" → subject (HintResolver)
    BC->>BC: bind session to jkt (cnf), status PENDING, interval 5s
    BC-->>C: auth_req_id, expires_in=300, interval=5
    C->>AD: (real deployment: user's phone shows binding_message)
    AD->>BC: POST /backchannel auth_req_id (basic auth "hello")
    BC->>BC: PENDING → VALIDATED (state machine)
    loop every ≥ interval (slow_down: +5s)
        C->>C: fresh assertion + fresh DPoP proof (POST /token)
        C->>T: grant=urn:openid:params:grant-type:ciba + auth_req_id
        T->>T: poll too fast → slow_down, not approved → authorization_pending
        T->>T: approved → check proof jkt == session cnf.jkt (proof-key-swap guard)
    end
    T->>T: consume auth_req_id atomically (one-time)
    T->>T: mint access token (cnf.jkt, token_type=DPoP, no refresh, offline_access stripped)
    T-->>C: access_token (token_type: DPoP)
```

## What it proves

* The solid promotion: `binding_message` is required (the CD/AD
  anti-phishing interlock) and charset-constrained.
* Signed request objects are verified against the client's registered
  JWKS with an EC-only algorithm allowlist; parameters may not appear
  outside the JWT.
* The optional DPoP binding (RFC 9449 §10 analog): polls without a proof or
  with the wrong key are rejected `invalid_grant` **before** the session is
  consumed — a retry with the right key still succeeds.
* The CIBA grant never mints refresh tokens and strips `offline_access`
  (RFC 9700 §4.12.2).
