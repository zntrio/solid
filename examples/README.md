# Examples

Reference assemblies of the `solid` SDK. Each example is a runnable `main`
package; they compose into a small working ecosystem of an authorization
server, a resource server, and several client demos exercising different
client-authentication mechanisms.

> These are **local demo assemblies**, not production services. Key material
> is published fixtures or generated at boot; do not reuse any of it.

## Prerequisites

* Go 1.27+

## Overview

| Example | Kind | Port | Requires |
|---|---|---|---|
| [`authorizationserver`](authorizationserver/README.md) | server | `:8080` (`SOLID_EXAMPLE_LISTEN_ADDR`) | — |
| [`attestationserver`](attestationserver/README.md) | server | `:8087` | — |
| [`resourceserver`](resourceserver/README.md) | server | `:8085` | `authorizationserver` running |
| [`deviceclient`](deviceclient/README.md) | client | — | `authorizationserver` + `resourceserver` |
| [`attestationclient`](attestationclient/README.md) | client | — | `authorizationserver` + `attestationserver` + `resourceserver` |
| [`spiffeclient`](spiffeclient/README.md) | client | — | `authorizationserver` |
| [`cibaclient`](cibaclient/README.md) | client | — | `authorizationserver` |
| [`cimdclient`](cimdclient/README.md) | client | — | `authorizationserver` |

Client demos are one-shot: they run, print the exchanged token (and the
resource response when applicable), then exit.

Each example directory carries a `README.md` with a mermaid sequence
diagram describing the exact flow its `main.go` implements.

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
* `http://127.0.0.1:8085/` — a signed-timestamp endpoint (requires an access token for the `timestamp:read` scope)

The attestation server serves `http://127.0.0.1:8087/attestations/sign` and
`/attestations/jwks`.

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

## Authorization server configuration

* `SOLID_EXAMPLE_LISTEN_ADDR` — listen address (default `:8080`).
* `SOLID_EXAMPLE_SIGNING_KEY` — signing key as a JWK JSON document. When
  unset, an ephemeral ML-DSA-65 key is generated at boot **with a loud
  warning**: tokens do not survive a restart. Set it for anything beyond
  local testing.
* `SOLID_EXAMPLE_XAA_CONFIG` — Cross-App Access (ID-JAG) trust configuration
  as JSON (`trusted_issuers`, `audiences`). When unset, ID-JAG issuance and
  redemption are disabled.
* `SOLID_EXAMPLE_XAA_SALT` — pairwise salt for ID-JAG subject identifiers.

Storage is in-memory; all state is lost on restart.
