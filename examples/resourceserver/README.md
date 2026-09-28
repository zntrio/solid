# Resource Server (signed timestamp)

Protected resource serving a signed timestamp. It is a reference consumer
of the solid stack: discovery of the AS, token introspection under the
`authorized_introspection_clients` grant, Bearer and DPoP access, RFC 8705
certificate binding, and RFC 9470 step-up signals (`max_age`, `acr`).

Prerequisites: `authorizationserver` running (see [`../README.md`](../README.md)).

## Endpoints

* `/.well-known/oauth-protected-resource` — PRM (RFC 9728)
* `/` — the signed-timestamp resource (scope `timestamp:read`)

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (Bearer or DPoP)
    participant R as Resource server :8085
    participant T as AS /token

    Note over R: boot: discovery of AS metadata (panics without the AS)
    C->>R: Authorization: Bearer|DPoP <token> [+ DPoP proof]
    alt Bearer
        R->>T: introspect (private_key_jwt assertion, authorized client)
        T-->>R: active + metadata + cnf
        R->>R: cnf.jkt set? → reject ("requires PoP")
        R->>R: cnf.x5t#S256 set? → require matching mTLS cert (RFC 8705 §3)
    else DPoP
        R->>R: verify proof (htm/htu, ath = token hash) → jkt
        R->>T: introspect
        T-->>R: active + cnf.jkt
        R->>R: secure-compare proof jkt == token cnf.jkt
    end
    R->>R: max_auth_age (30s) / acr (urn:solid:loa:1fa:any) checks → 401 with WWW-Authenticate
    R->>R: scope/permission check (timestamp:read) → 403
    R->>R: sign timestamp (ed25519, nonce)
    R-->>C: SignedTimestamp JSON (issuer, timestamp, signature)
```

## What it proves

* A resource server can authorize on both proof schemes with the same
  middleware (`Bearer` and `DPoP` schemes dispatched on the
  `Authorization` prefix).
* Sender-constrained tokens are enforced, not just introspected: a
  DPoP-bound token fails Bearer access; a certificate-bound token fails
  without the bound mTLS certificate.
* Step-up authentication challenges carry the RFC 9470 fields
  (`max_age`, `acr_values`) and RFC 9728 discovery pointers
  (`resource`, `resource_metadata`).
