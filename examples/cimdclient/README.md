# CIMD Client (Client ID Metadata Document)

Demonstrates client authentication with a URL-shaped client identifier
resolved through its Client ID Metadata Document
(draft-ietf-oauth-client-id-metadata-document): the AS resolves
`https://cimd.example.org/client` to the demo fixture document at
authentication time — no static registration exists.

Prerequisite: `authorizationserver` running (see [`../README.md`](../README.md)).

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as cimdclient
    participant AS as Authorization server (CIMD resolver)
    participant D as Client ID Metadata Document (cimddemo fixture)
    participant T as AS /token

    C->>C: rebuild JWK (AKP, ML-DSA-65) from the published fixture seed
    C->>T: POST client_credentials, client_assertion signed with that key, client_id=https://cimd.example.org/client
    T->>AS: no static registration for the URL-shaped identifier
    AS->>D: fetch document (allow-list pinned host, SSRF-hardened fetcher)
    D-->>AS: metadata: token_endpoint_auth_method=private_key_jwt, jwks, grant_types, introspection grant
    AS->>T: verify assertion against the document's JWKS
    T->>T: mint access token
    T-->>C: access_token
    Note over C: nbf (iat+1) settles, then:
    C->>T: introspect (fresh assertion — jti single-use)
    T-->>C: active, client_id=https://cimd.example.org/client
```

## What it proves

* Client registration moves to the document: the AS trust decision is
  reduced to a host allow-list (operator-pinned, never caller-controlled)
  and the SSRF-hardened fetch.
* The document's grants flow through: the introspection call succeeds
  because the *document* declares `authorized_introspection_clients`.
* Assertions stay single-use (`jti` burned per request), so the demo mints
  a fresh one before introspecting.
