# Examples

Reference assemblies of the `solid` SDK. Each example is a runnable `main`
package; they compose into a small working ecosystem of an authorization
server, a resource server, and several client demos exercising different
client-authentication mechanisms.

> These are **local demo assemblies**, not production services. Key material
> is published fixtures or generated at boot; do not reuse any of it. The
> pairwise subject salt default is a fixture too — set
> `SOLID_EXAMPLE_PAIRWISE_SALT` for anything beyond the local demo.

## Prerequisites

* Go 1.27+

## Overview

| Example | Kind | Port | Requires |
|---|---|---|---|
| [`authorizationserver`](authorizationserver/README.md) | server | `:8080` (`SOLID_EXAMPLE_LISTEN_ADDR`) | — |
| [`attestationserver`](attestationserver/README.md) | server | `:8087` | — |
| [`resourceserver`](resourceserver/README.md) | server | `:8085` | `authorizationserver` running |
| [`mcpserver`](mcpserver/README.md) | server (MCP tools) | `:8090` | `authorizationserver` + `resourceserver` |
| [`deviceclient`](deviceclient/README.md) | client | — | `authorizationserver` + `resourceserver` |
| [`attestationclient`](attestationclient/README.md) | client | — | `authorizationserver` + `attestationserver` + `resourceserver` |
| [`spiffeclient`](spiffeclient/README.md) | client | — | `authorizationserver` |
| [`cibaclient`](cibaclient/README.md) | client | — | `authorizationserver` |
| [`cimdclient`](cimdclient/README.md) | client | — | `authorizationserver` |
| [`agentclient`](agentclient/README.md) | client | — | `authorizationserver` + `mcpserver` + `resourceserver` |
| [`grpcbackend`](grpcbackend/README.md) | server (gRPC) | `127.0.0.1:9090` | — |
| [`coapace`](coapace/README.md) | server + client (CoAP/DTLS) | `127.0.0.1:5684` (AS), `127.0.0.1:5685` (RS) | — |
| [`sdtoken`](sdtoken/README.md) | client (direct mint) | — | — |

Client demos are one-shot: they run, print the exchanged token (and the
resource response when applicable), then exit.

Every client demo prints its **protocol flow** as it runs: each HTTP request
(method, URL, headers, form parameters) and each response (status, headers,
body) is echoed to stdout, with token, proof, and assertion values truncated
for readability — the output shows the shape of every exchange without
dumping full cryptographic material.

Each example directory carries a `README.md` with a mermaid diagram
describing the exact flow its code implements, plus a **sample run**
section captured from a live execution (truncated token material).

## Running the servers

The `resourceserver` fetches the authorization server's discovery metadata at
boot, so **start the `authorizationserver` first** — otherwise it panics with
a connection-refused error.

```sh
# Terminal 1 — authorization server (must be first)
go run ./examples/authorizationserver

# Terminal 2 — attestation server (only needed by attestationclient)
go run ./examples/attestationserver

# Terminal 3 — resource server
go run ./examples/resourceserver

# Terminal 4 — MCP tool server (only needed by agentclient)
go run ./examples/mcpserver
```

Once up, the authorization server serves:

* `http://127.0.0.1:8080/.well-known/oauth-authorization-server` — AS metadata
* `http://127.0.0.1:8080/.well-known/openid-configuration` — OIDC discovery
* `http://127.0.0.1:8080/keys` — JWKS
* `http://127.0.0.1:8080/spiffe/bundle.json` — SPIFFE trust bundle
* `/par`, `/authorize`, `/token`, `/token/introspect`, `/token/revoke`,
  `/device/authorize`, `/device`, `/bc-authorize`, `/backchannel`

and the resource server serves:

* `http://127.0.0.1:8085/.well-known/oauth-protected-resource` — protected-resource metadata
* `http://127.0.0.1:8085/` — a signed-timestamp endpoint (scope
  `timestamp:read`; step-up surface — end-user tokens with a RFC 9470
  `acr` only, `client_credentials` tokens fail closed)
* `http://127.0.0.1:8085/machine` — the same resource as a client
  surface (same audience/scope/PoP enforcement, no end-user ACR
  requirement — used by `deviceclient` and `attestationclient`)

and the MCP tool server serves:

* `http://127.0.0.1:8090/.well-known/oauth-protected-resource` —
  protected-resource metadata (RFC 9728)
* `http://127.0.0.1:8090/tools/get_signed_timestamp/invoke` — the
  `get_signed_timestamp` tool (DPoP-bound delegated token carrying the
  `mcp_tools(:8090, get_signed_timestamp)` grant)

The attestation server serves `http://127.0.0.1:8087/attestations/sign` and
`/attestations/jwks`.

Running the gRPC backend instead: it exposes the authorization protocol
core (client authentication, PAR, token, introspection, revocation, gated
RFC 7591 registration) as proto-defined gRPC services for a presentation
layer to consume — see `grpcbackend/README.md`:

```sh
go run ./examples/grpcbackend
```

## Running the client demos

Each demo lives in its own directory; run it with `go run`:

```sh
# DPoP-bound client_credentials grant, then calls the timestamp resource
go run ./examples/deviceclient

# Attestation-based client authentication (needs attestationserver)
go run ./examples/attestationclient

# SPIFFE JWT-SVID client authentication (draft-ietf-oauth-spiffe-client-auth)
go run ./examples/spiffeclient

# Client ID Metadata Document client (draft-ietf-oauth-client-id-metadata-document)
go run ./examples/cimdclient

# CIBA poll-mode client (OpenID Client-Initiated Backchannel Authentication)
go run ./examples/cibaclient

# AI agent: PAR + JARM authorization code, then delegated re-delegation
# through the MCP tool server (RFC 8693 ×2) to the backend resource server
go run ./examples/agentclient

# ACE-OAuth over mutual DTLS 1.2 (RFC 9200, self-contained triangle)
go run ./examples/coapace
```

What each demo exercises:

* **`deviceclient`** — `client_credentials` with a `private_key_jwt` assertion
  (ML-DSA-65) plus a DPoP proof; the returned access token is DPoP-bound when
  calling the resource server.
* **`attestationclient`** — generates a fresh client instance key, obtains a
  client attestation JWT from the attestation server, proves possession of
  the attested key, and exchanges it for a token (`attest_jwt_client_auth`).
* **`spiffeclient`** — mints a JWT-SVID for `spiffe://example.org/my-oauth-client`
  with the shared trust-domain fixture key and exchanges it via the
  `jwt-spiffe` client assertion type.
* **`cimdclient`** — authenticates with the URL-shaped client identifier
  `https://cimd.example.org/client`, which the AS resolves through its Client
  ID Metadata Document fixture, then introspects the issued token.
* **`cibaclient`** — CIBA poll mode end to end with DPoP: `private_key_jwt`
  (ES256) authentication, a signed request object posted to `/bc-authorize`
  (CIBA §7.1.1) declaring the DPoP key thumbprint as `dpop_jkt`
  (RFC 9449 §10), end-user approval on the authentication device
  (`/backchannel`, standing in for the user's phone), then token-endpoint
  polling with `urn:openid:params:grant-type:ciba` presenting a fresh DPoP
  proof of the bound key with every poll (honoring the advertised interval
  and `slow_down`); prints the sender-constrained access token
  (`token_type: DPoP`, no refresh token, per RFC 9700 §4.12.2).
* **`agentclient`** — an AI agent acting on behalf of a user through a
  delegation chain: CIMD client identity
  (`https://agent.example.org/ai-agent`, ML-DSA-65 key driving assertions,
  JAR and DPoP), PAR with `request_uri` consumption, mocked user approval
  (Basic login) with a JARM `query.jwt` response, DPoP-bound
  authorization_code redemption, then a first RFC 8693 token exchange
  toward the MCP tool server (`mcpserver`: the AS delegation policy mints
  `may_act=[the MCP server]` on the delegated token) and the
  `get_signed_timestamp` tool invocation. The MCP server re-delegates
  (second RFC 8693 exchange: `cnf` re-bound to its proof key, act chain
  `[mcp, agent]`) to the backend resource server, which evaluates the
  carried `mcp_tools` detail (introspection exposes the `act` chain, the
  details and the `cnf.jkt` binding) and relays the signed timestamp as
  the tool result. A non-consented-detail probe is rejected with
  `invalid_authorization_details` (RFC 9396 §6).

## Configuration

* `SOLID_EXAMPLE_LISTEN_ADDR` — listen address (default `127.0.0.1:8080`;
  loopback only, the example serves plaintext HTTP).
* `SOLID_EXAMPLE_ISSUER` — authorization server issuer identifier
  (default `http://127.0.0.1:8080`). Recognized by the authorization server
  and the client demos (deviceclient, cibaclient, cimdclient, spiffeclient,
  attestationclient, agentclient, resourceserver, mcpserver) — set it on both
  sides when running the AS on a non-default address.
* `SOLID_EXAMPLE_TOKEN_FORMAT` — (coapace) token serialization format:
  `opaque` (default, verifiable UUIDv7 reference tokens) or `cwt`
  (RFC 8392 CBOR Web Tokens signed with an ephemeral ES256 key).
* `SOLID_EXAMPLE_SIGNING_KEY` — signing key as a JWK JSON document. When
  unset, an ephemeral ML-DSA-65 key is generated at boot **with a loud
  warning**: tokens do not survive a restart. Set it for anything beyond
  local testing.
* `SOLID_EXAMPLE_ENCRYPTION_KEY` — token encryption key as a JWK JSON
  document (P-256 EC, `use: enc`). Access and refresh tokens are
  HPKE-encrypted JWTs (`HPKE-7`, draft-ietf-jose-hpke-encrypt-22):
  sign-then-encrypt, 5-segment JWE compact serializations. When unset, an
  ephemeral P-256 key is generated at boot **with a loud warning**: tokens
  do not survive a restart.
* `SOLID_EXAMPLE_XAA_CONFIG` — Cross-App Access (ID-JAG) trust configuration
  as JSON (`trusted_issuers`, `audiences`). When unset, ID-JAG issuance and
  redemption are disabled.
* `SOLID_EXAMPLE_XAA_SALT` — pairwise salt for ID-JAG subject identifiers.

Storage is in-memory; all state is lost on restart.
