# AGENTS.md

Guidance for AI agents (and humans) working in this repository.

## What this project is

`solid` (module `zntr.io/solid`, Go 1.26) is a set of **modular SDK building blocks
for assembling an OIDC/OAuth authorization server** — not a ready-to-use, final
authorization server.

The idea behind this project is to **decouple OAuth protocols from HTTP** and
build a presentation-agnostic authorization protocol that could be served by
different presentation layers: HTTP, gRPC, CoAP, etc. The standards bind the
authorization protocol to a presentation layer by design, but many standards
are in conflict due to that way of thinking — `solid` deliberately separates
the protocol logic from the wire so the same mechanisms hold regardless of
the transport serving them.

The project must stay **modular and composable**: every mechanism is an
independent building block with a small interface, assembled by the consumer
(see `examples/`) rather than baked into a monolithic server.

1. **Defensive** — optional/recommended protocol parameters are promoted to
   required when they harden security. Insecure configurations are not offered
   as options. This is deliberate: `solid` does not aim to pass full OIDC
   compliance tests (see README "What is not").
2. **Security-minded** — enforced flows and mechanisms: `PAR + DPoP + JARM` for
   the `authorization_code` flow, mandatory `PKCE + nonce`, JWT-secured requests
   (JAR/JWSREQ), asymmetric client authentication only (`private_key_jwt`,
   attestation-based), no `HSxxx`/`RSxxx` JOSE algorithms (elliptic curves
   only), no implicit or hybrid flow, `response_type=code` only.
3. **Privacy-first** — access/refresh tokens are hybrid: protocol-validation
   claims only; the subject is referenced by a `jti`-addressed, AS-only record
   and exposed as a pairwise subject identifier. No `id_token` in the
   authorization code flow; user details come from `user_info` at consent time.
4. **Modular and composable** — small packages, narrow interfaces, dependency
   injection via constructor options; blocks must remain usable in isolation.
   Resist coupling an `sdk/` mechanism to a specific storage, transport, or
   service implementation.

The backbone is **OAuth RFC compliance**: each feature maps to a specific RFC
(see README "Framework" for the checklist). When in doubt, the RFC wins; when
the RFC leaves options open, the most defensive option wins.

## Architecture

The protocol layer is decoupled from HTTP on purpose: **the domain model is
defined in protobuf** (`proto/oidc/**`), which makes domain objects serialisable
and extensible — e.g. to build a gRPC-based (or CoAP-based) OAuth service.
Generated Go code lives in `api/` (regenerated, never hand-edited).

Package map:

| Path | Role |
|---|---|
| `proto/` | Protobuf domain model + `buf` generation config (source of truth for model objects) |
| `api/` | Generated protobuf Go code (do not edit; `make regenerate-api`) |
| `sdk/` | Reusable protocol building blocks: `jwsreq`, `jarm`, `pkce`, `dpop`, `token` (verifiable / jwt / cwt / paseto), `pairwise`, `generator`, `jwk`, `rfcerrors`, `types` |
| `server/` | Server-side SDK: `services` (authorization, token, device contracts), `clientauthentication`, `storage`, `profile` |
| `oidc/` | OIDC constants |
| `client/` | HTTP client helpers |
| `examples/` | Reference assemblies: `authorizationserver`, `deviceclient`, `resourceserver`, `attestationclient`, `attestationserver` |

Interfaces are small, `context.Context`-first, and take/return protobuf types
(e.g. `server/services/api.go`). Look there before inventing a new convention.

## Commands

```sh
make buildall          # go build ./...
go test ./...          # tests
make code-format       # gofumpt + gci (import order: std / default / zntr.io/solid)
make regenerate-api    # buf generate: proto/ → api/ (local protoc plugins via install-tools)
```

Linting: `bin/golangci-lint` with `.golangci.yml`; license header checks via
`wwhrd` (`.wwhrd.yml`) — only Apache-2.0-compatible dependencies. Generated
files (`.pb.go`, mocks) are excluded from lint.

## Conventions for changes

* **Every Go file** starts with the Apache 2.0 SolID license header (see any
  existing file; `doc.go` shows the exact block).
* Import order enforced by `gci`: standard library, third-party, then
  `zntr.io/solid`.
* Domain objects and service contracts use protobuf types from `api/oidc/**`.
  New model fields or messages belong in `proto/oidc/**`, then regenerate.
* Syntactic request validation (required fields, length bounds, URI/pattern
  syntax) is expressed as protovalidate annotations in `proto/oidc/**` and
  enforced by the `protovalidate` first validation level in services; semantic
  checks (cross-field rules, storage state, cryptography) live in business
  logic, never in proto annotations.
* Error responses to protocol callers use `sdk/rfcerrors` builders so that
  RFC-compliant error codes/ descriptions stay consistent.
* Secrets, keys, and random values: use `crypto/rand` (security-sensitive) and
  `math/rand/v2` (deterministic/test PRNGs) from the standard library, plus
  `sdk/jwk` for key handling; never invent ad-hoc randomness.
* Mocks live in per-package `mock/` directories (gomock style, `bin/mockgen`).
* Do not relax a security-enforcing default to make a test or example pass —
  tests adapt to the security posture, not the reverse.
* `examples/` are assemblies of the SDK, not a fork of its logic; keep protocol
  decisions in `sdk/`/`server/`.

## When extending the protocol surface

1. Check the README "Framework" checklist for the relevant RFC and its status.
2. Implement in `sdk/` (mechanism, wire-agnostic) or `server/` (service-side),
   keeping HTTP/CoAP/gRPC concerns out of the core.
3. Wire the strict profile (`server/profile`) so the mechanism is enforced, not
   merely available.
4. Add/adjust tests next to the implementation (unit tests in the same package;
  see existing `*_test.go`).
