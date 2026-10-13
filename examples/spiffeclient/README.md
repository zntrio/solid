# SPIFFE Client (JWT-SVID client authentication)

Demonstrates OAuth SPIFFE client authentication
(draft-ietf-oauth-spiffe-client-auth-02): the client mints a JWT-SVID for
the registered workload `spiffe://example.org/my-oauth-client` with the
example.org trust-domain fixture key and exchanges it at the token endpoint
with the `jwt-spiffe` client assertion type.

Prerequisite: `authorizationserver` running (see [`../README.md`](../README.md)).

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as spiffeclient
    participant T as AS /token
    participant B as AS /spiffe/bundle.json

    Note over C: signing key = example.org trust-domain fixture<br/>(public part also pinned in the AS bundle)
    C->>C: mint JWT-SVID (draft §3.1): iss=sub=spiffe://example.org/my-oauth-client, aud=/token, exp=+5min, jti
    C->>T: POST grant=client_credentials, client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe, client_assertion=SVID
    T->>B: (at boot) fetch trust bundle for example.org
    T->>T: verify SVID signature against the bundle<br/>(no client Jwks registered: keys come from the trust domain)
    T->>T: match SPIFFE ID → registered workload client
    T-->>C: access_token
```

## Sample run (captured live)

```text
JWT-SVID: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvdG9rZW4iLCJleHAiOjE3OTE4ODExNjcsImlhdCI6MTc5MTg4MDg2NywiaXNzIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvbXktb2F1dGgtY2xpZW50IiwianRpIjoiV2RxS2RCemVlZWd6VkttSSIsInN1YiI6InNwaWZmZTovL2V4YW1wbGUub3JnL215LW9hdXRoLWNsaWVudCJ9.4jy8sQFqgz6T4qLBtrsHs2Zg8smSgq1fhU6B6JOe-NsSyCDEehniTLGth27DU0ksDLxY1xslDrU4qAy-haeEhw

→ POST http://127.0.0.1:8080/token
  Content-Type: application/x-www-form-urlencoded
  client_assertion=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ…(+324 bytes)
  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe
  grant_type=client_credentials
  resource=http://127.0.0.1:8085
  scope=timestamp:read
← HTTP 200
  "access_token": "eyJhbGciOiJIUEtFLTciLCJraWQiOiJnLXZSSFdxdHVsb2J…(+6655 bytes)
  "expires_in": 3600
  "scope": "timestamp:read"
  "token_type": "Bearer"
```

## What it proves

* Client identity is the workload identity: no per-client key registration
  on the AS — verification delegates to the trust-domain bundle
  (`spiffe.BundleSource`), proving the SDK's decoupling of client
  authentication from static key registries.
* The SVID is short-lived and single-purpose (`aud` = token endpoint), so a
  leaked SVID is useless elsewhere.
