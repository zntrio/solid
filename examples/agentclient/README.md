# AI-Agent Client (STS token exchange + MCP authorization details)

An AI agent acting on behalf of a user against a remote MCP-style resource
server, using OAuth 2.0 Token Exchange (RFC 8693) and `authorization_details`
(RFC 9396).

The agent is a **Client ID Metadata Document** client
(draft-ietf-oauth-client-id-metadata-document) identified by the URL-shaped
`https://agent.example.org/ai-agent`, resolved by the example authorization
server through the CIMD fixture in
[`../authorizationserver/cimddemo`](../authorizationserver/cimddemo).

Prerequisites: both the example authorization server and the example
resource server are running (see [`../README.md`](../README.md)):

```sh
go run ./examples/authorizationserver
go run ./examples/resourceserver
```

Then:

```sh
go run ./examples/agentclient
```

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant A as AI agent (CIMD client)
    participant U as User (Basic hello:world — mocked login)
    participant S as AS :8080
    participant R as Remote MCP resource server :8085

    Note over A: key = ML-DSA-65 fixture (assertions, JAR, DPoP)
    A->>S: POST /par?request=<JAR> (+ client_assertion, DPoP proof)
    S-->>A: request_uri
    U->>S: GET /authorize?client_id&request_uri (Basic hello:world)
    S-->>U: 302 redirect_uri?response=<JARM query.jwt>
    Note over A: captures the 302 Location (no browser)
    A->>A: verify JARM (state, AS keys)
    A->>S: POST /token (code, PKCE verifier, client_assertion, DPoP)
    S-->>A: subject access token (DPoP-bound)<br/>+ id_token (SD id+jwt) + id_token_disclosures
    Note over A: RP verifies the id_token: AS keys, typ id+jwt,<br/>aud = agent, nonce echo; disclosures<br/>processed for the user claims
    A->>S: POST /token (client_credentials: the agent's own identity)
    S-->>A: actor access token
    A->>S: POST /token grant=token-exchange<br/>subject_token=user AT, actor_token=agent AT,<br/>resource=http://127.0.0.1:8085,<br/>authorization_details=[mcp_tools]
    Note over S: mocked processing: details carried verbatim
    S-->>A: scoped access token (60s, act=agent,<br/>authorization_details echoed, cnf.jkt preserved)
    A->>R: POST / (Authorization: DPoP, DPoP proof)
    R->>S: introspect (authorized_introspection_clients)
    S-->>R: active, act chain, authorization_details, cnf.jkt
    Note over R: evaluates the mcp_tools detail —<br/>the RS is the authorization authority
    R-->>A: SignedTimestamp JSON
```

## What it exercises

* PAR (RFC 9126) with a JAR request object (RFC 9101), DPoP-proved
  (RFC 9449) and the `request_uri` consumption at `/authorize`.
* The mocked user approval leg: the demo performs the front-channel
  authorization request with the Basic `hello:world` fixture standing in for
  the resource-owner login (no browser, no consent screen), and captures the
  JARM `query.jwt` response (RFC 9447) from the 302 Location.
* DPoP-bound `authorization_code` redemption with mandatory PKCE and nonce,
  plus retrieval and verification of the opt-in D-12.1 `id_token`: an
  SD-JWT (`id+jwt`, RFC 9901) carrying digests only, its Disclosures in the
  `id_token_disclosures` parameter; the agent verifies the signature against
  the AS keys, the `aud` (its own client id) and the nonce echo, then
  processes the disclosures to recover the demo user claims.
* CIMD client authentication (`private_key_jwt`, ML-DSA-65): the same key
  drives the client assertions, the JAR signature and the DPoP proofs.
* RFC 8693 token exchange with `actor_token` (delegation: the exchanged
  token records the agent in the `act` chain) and the RFC 8707 resource
  indicator of the remote MCP service.
* RFC 9396 `authorization_details` through the exchange. **The AS applies
  mocked processing**: the requested `mcp_tools` entries are carried
  verbatim into the exchanged token (no consent narrowing is enforced);
  the remote resource server evaluates them and makes the authorization
  decision — the demo's concrete authorization check.
* RFC 7662 introspection of the exchanged token: `act` chain, carried
  details, `cnf.jkt` key binding.

## Notes

* The exchanged token lives 60 seconds (RFC 8693 short-lived delegation):
  the demo calls the resource server immediately after the exchange.
* The DPoP key binding survives the exchange: the proof at the resource
  call must use the same key the subject token was bound to (RFC 9449
  section 8 — key swaps are rejected at the exchange).
* The demo prints `sub` as empty in the client-side introspection output:
  the client SDK decodes the `subject` member while the wire carries `sub`
  (pre-existing quirk, intentionally left as is; the resource server's
  permission map accounts for it).
