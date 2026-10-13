# Resource Server (signed timestamp)

Protected resource serving a signed timestamp. It is a reference consumer
of the solid stack: discovery of the AS, token introspection under the
`authorized_introspection_clients` grant, Bearer and DPoP access, RFC 8705
certificate binding, RFC 9470 step-up signals (`max_age`, `acr`), and
RFC 9396 `authorization_details` evaluation for MCP-style tool access.

The server is a **Client ID Metadata Document** client
(draft-ietf-oauth-client-id-metadata-document) identified by the URL-shaped
`https://rs.example.org/timestamp` (introspection-only: its CIMD document
carries the `private_key_jwt` signing key; the introspection authorization
lives on the token owners' documents, RFC 7662 section 2.1).

Prerequisites: `authorizationserver` running (see [`../README.md`](../README.md)).
The `agentclient` and `mcpserver` demos additionally require this server
(it is the backend target of the delegated re-delegation chain).

## Endpoints

* `/.well-known/oauth-protected-resource` — PRM (RFC 9728)
* `/` — the signed-timestamp resource (scope `timestamp:read`),
  **step-up surface**: end-user tokens only — the RFC 9470 `acr` and
  `max_age` requirements apply, so `client_credentials` tokens fail
  closed
* `/machine` — same resource, client surface: identical audience/scope/
  PoP enforcement, no end-user ACR requirement (the machine credential
  is the client itself, RFC 6749 §4.4; used by the `deviceclient` and
  `attestationclient` demos)

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
    R->>R: / (step-up surface): max_auth_age (30s) / acr (urn:solid:loa:1fa:any) checks → 401 with WWW-Authenticate
    R->>R: /machine (client surface): ACR checks skipped — client_credentials has no login event
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
* RFC 9396 authorization_details arriving through a delegated
  re-delegation (RFC 8693) are evaluated here: the MCP tool server
  (`https://mcp.example.org/server`, see `mcpserver` and `agentclient`)
  only reaches the `timestamp:read` intent when its re-delegated token
  (T5: `act=[mcp, agent]`, `cnf.jkt` = the MCP server's proof key)
  carries the matching `mcp_tools` detail for this resource. The AS
  transports the entries; this resource server is the authorization
  authority for MCP tool access.
