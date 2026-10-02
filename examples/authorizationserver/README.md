# Authorization Server (example assembly)

Reference assembly of the `solid` SDK as an OAuth 2.1 / OIDC authorization
server. It wires the strict profile (`server/profile`): PAR + JAR + DPoP +
JARM for the authorization-code flow, elliptic-curve and post-quantum
signing only, asymmetric client authentication only, pairwise subjects,
and the device and CIBA grants with their cross-device hardening.

Run it with `go run ./examples/authorizationserver` (see
[`../README.md`](../README.md) for the full demo ecosystem).

## Endpoints

| Route | Purpose |
|---|---|
| `/.well-known/oauth-authorization-server` | AS metadata (RFC 8414) |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/keys` | AS signing JWKS |
| `/spiffe/bundle.json` | example.org trust-domain bundle |
| `/par` | Pushed Authorization Requests (RFC 9126) |
| `/authorize` | authorization endpoint (JAR + JARM) |
| `/token` | token endpoint (all grants) |
| `/token/introspect` · `/token/revoke` | RFC 7662 / RFC 7009 |
| `/device/authorize` · `/device` | RFC 8628 device flow |
| `/bc-authorize` · `/backchannel` | OpenID CIBA (poll mode) |

## Authorization-code flow (PAR + JAR + DPoP + JARM)

The strict profile's front channel: the request is pushed as a signed
request object, the end user authenticates (basic auth, subject becomes the
pairwise subject), the response is JWT-encoded (JARM) and the issued code
carries a DPoP key binding.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant PUSH as /par
    participant A as /authorize
    participant U as End user (basic auth)
    participant T as /token
    participant AS as AS services

    C->>PUSH: POST request object (JAR, ML-DSA-65) + client assertion
    PUSH->>AS: register authorization request
    PUSH-->>C: request_uri
    C->>A: GET /authorize?client_id&request_uri (+ DPoP proof)
    A->>U: authentication + consent (binding_message shown)
    U-->>A: approve
    AS->>AS: store code session (scope, dpop_jkt→cnf, authorization_details)
    A-->>C: JARM response (JWT, code inside)
    C->>T: POST code + PKCE verifier + client assertion + DPoP proof
    T->>AS: verify PKCE, code↔client, cnf.jkt == proof jkt
    AS->>AS: consume code (one-time), mint access token
    T-->>C: access_token (+ refresh when granted)
```

## Device flow (RFC 8628)

```mermaid
sequenceDiagram
    autonumber
    participant D as Device client
    participant DA as /device/authorize
    participant AD as Authentication device
    participant DV as /device
    participant T as /token
    participant AS as AS services

    D->>DA: POST client assertion (private_key_jwt)
    DA->>AS: create session (PENDING, device_code + user_code, 120s)
    DA-->>D: device_code, user_code, interval=5s
    D->>AD: display user_code out-of-band
    AD->>DV: POST user_code (subject from basic auth)
    DV->>AS: PENDING → VALIDATED (state machine, throttled)
    loop every ≥ interval
        D->>T: POST grant=device_code (fresh assertion each poll)
        T->>AS: slow_down / authorization_pending / consume VALIDATED
    end
    AS-->>T: mint access token (offline_access stripped, no refresh)
    T-->>D: access_token
```

## CIBA flow (OpenID CIBA Core 1.0, poll mode)

```mermaid
sequenceDiagram
    autonumber
    participant C as Consumption device (client)
    participant BC as /bc-authorize
    participant AD as Authentication device
    participant BV as /backchannel
    participant T as /token
    participant AS as AS services

    C->>C: sign request object (ES256): scope, login_hint, binding_message, dpop_jkt
    C->>BC: POST request + client assertion
    BC->>AS: verify signature vs client JWKS, resolve hint → subject
    AS->>AS: create session (PENDING, auth_req_id, poll_interval=5s, cnf from dpop_jkt)
    BC-->>C: auth_req_id, expires_in, interval
    AD->>BV: POST auth_req_id (user confirms binding_message)
    BV->>AS: PENDING → VALIDATED (state machine)
    loop every ≥ interval
        C->>T: POST grant=urn:openid:params:grant-type:ciba + DPoP proof
        T->>AS: slow_down / pending / check cnf.jkt == proof jkt / consume
    end
    AS-->>T: mint sender-constrained access token (no refresh, offline_access stripped)
    T-->>C: access_token (token_type: DPoP)
```

## Notes

* Key material: ephemeral ML-DSA-65 signing key and ephemeral P-256
  encryption key at boot unless `SOLID_EXAMPLE_SIGNING_KEY` /
  `SOLID_EXAMPLE_ENCRYPTION_KEY` are set (see [`../README.md`](../README.md)).
* Access and refresh tokens are HPKE-encrypted JWTs (`HPKE-7`,
  draft-ietf-jose-hpke-encrypt-22): sign-then-encrypt, 5-segment JWE
  compact serializations.
* Storage is in-memory: all state is lost on restart.
* The deny paths of the device and CIBA validation services stay
  service-level (exercised by `integration/` tests); the HTML endpoints
  expose approval only.
