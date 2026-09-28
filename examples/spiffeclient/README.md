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

## What it proves

* Client identity is the workload identity: no per-client key registration
  on the AS — verification delegates to the trust-domain bundle
  (`spiffe.BundleSource`), proving the SDK's decoupling of client
  authentication from static key registries.
* The SVID is short-lived and single-purpose (`aud` = token endpoint), so a
  leaked SVID is useless elsewhere.
