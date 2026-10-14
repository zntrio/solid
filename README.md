# SolID — OAuth 2.0 / OpenID Connect Authorization Server SDK in Go
[![CI](https://github.com/zntrio/solid/actions/workflows/ci.yml/badge.svg)](https://github.com/zntrio/solid/actions/workflows/ci.yml)
[![CodeQL](https://github.com/zntrio/solid/actions/workflows/codeql.yml/badge.svg)](https://github.com/zntrio/solid/actions/workflows/codeql.yml)
[![Go Reference](https://pkg.go.dev/badge/zntr.io/solid.svg)](https://pkg.go.dev/zntr.io/solid)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

SolID is an open-source SDK for building an OIDC / OAuth 2.0 authorization server in Go. Security and privacy by design. Protocol logic is decoupled from the wire.

**What this is.** A modular SDK for assembling authorization servers. It covers five use cases out of the box. Every flow ships with a hardened, standards-based configuration. You pick the use case. The security posture comes with it. PAR, JAR, JARM, DPoP, PKCE, and sender-constrained tokens are mandatory, not options.

**Who builds it.** A security engineer specialized in identity, authentication, authorization, and privacy. In active development. Not a certified product.

| Use case | Flow | Enforcement |
|---|---|---|
| Online users | `authorization_code` | Mandatory PKCE (S256) via PAR, JARM responses, `state` |
| Machine-to-machine | `client_credentials` | Asymmetric client authentication only |
| Constrained devices (IoT) | ACE over CoAP | DTLS profile, CBOR tokens, `device_code` grant |
| Offline access | `refresh_token` | Rotation on every use, grant-family revocation |
| Delegation / AI agents | `token_exchange` | `may_act` gating, `act` chain depth cap; AI-agent CIMD clients are metadata-policy-governed (D-21) — see `examples/agentclient` |

## Why this project exists

OAuth and OIDC implementations fail more often than the protocols themselves. The specifications form a maze. Developers read them fast and interpret instead of apply. The result is faulty implementations in production.

These are real-world failures observed in the field:

* Teams skip the `authorization_code` flow because it does not carry user credentials.
* Teams use `client_credentials` as a customer login, with the secret hard-coded in a public UI.
* Applications authorize on token presence, without signature or content validation. "Token is here ⇒ you are admin."
* Authorization decisions read token claims that nobody verified.

Most OIDC providers offer a wide feature matrix. The deployer must understand every option to reach a secure configuration. Security posture becomes a function of OAuth expertise. One insecure client configuration can compromise the whole platform.

SolID takes the opposite position. It removes the insecure options instead of documenting them. The standards offer optional and recommended parameters. SolID promotes them to required. The deployer cannot misconfigure into a weak posture, because the weak posture does not exist in the code.

## Objectives

* Enforce OIDC features as one complete suite, selected by use case.
* Deliver security and privacy without full protocol expertise.
* Base the security posture on security objectives, not on protocol knowledge.
* Provide a battle-tested framework: adversarial tests, RFC conformance suites, and executable formal models (`spec/`).
* Decouple the protocol from the wire. OIDC binds to HTTP by design. SolID keeps protocol logic transport-agnostic, so the same services serve HTTP, gRPC, and CoAP.

## What SolID is not

* A complete, OIDC-compliant server. Optional and recommended parameters are promoted to required. SolID cannot pass the OIDC compliance test suite. This is deliberate.
* A turnkey product. It is an SDK. Assemblies live in `examples/`.

## Getting started

The `examples/` directory contains a reference authorization server and client integrations. See [`examples/README.md`](examples/README.md) for how to run them.

Each example directory carries a `README.md` with a sequence diagram. The diagram describes the exact flow its `main.go` implements.

## Features

### Protocol decisions

Each rule below is a design decision. The full record with evidence lives in [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md). Every entry cites the RFC section, the code anchor, and the test that proves it.

| Rule | Standard position | SolID position |
|---|---|---|
| `PAR + DPoP + JARM` | Optional extensions | Enforced for the `authorization_code` flow |
| Response types | Four registered types | `code` only. No implicit, no hybrid |
| PKCE | Public clients, `plain` allowed | All clients, S256 only, constant-time compare |
| Client authentication | Secrets permitted | Asymmetric only: `private_key_jwt`, mTLS, attestation, SPIFFE |
| Dynamic CIMD clients | Draft: fetched document as-is | Operator metadata policy (Federation 1.0 §6.1.3.1 operators) applied before credential enforcement (D-21) |
| JOSE algorithms | Full registry | Elliptic curves + ML-DSA. No HS, RS, PS, `none` |
| Token content | Implementation choice | No PII. `jti`-addressed subject record, pairwise identifiers |
| `id_token` in code flow | Required by OIDC Core | Opt-in: SD-JWT `id_token` (RFC 9901), digests only, values in `id_token_disclosures`; not issued by default (D-12.1) |
| Refresh tokens | Rotation optional (BCP) or MAY (2.1) | Unconditional rotation, replay revokes the grant family |
| `audience` | Optional | Required whenever `scope` is requested |
| Authorization requests | Front-channel permitted | PAR with signed JWT request objects only |
| Client profiles | Registration metadata | Application-type profiles gate grants, response types, auth methods |
| Token serialization | JWT assumed | Assembler decision: reference token, JWT, HPKE-JWT, or CWT |

Web applications must use a server-side component to negotiate authorization. Client-side JavaScript must not see authorization artifacts before the user is identified.

Syntactic request validation is expressed as protovalidate annotations on the protobuf model (`proto/oidc/**`). Every service runs it as a first level. Semantic rules live in business logic.

### Framework

Conformance detail with executed test proof lives in [`docs/COMPLIANCE_REPORT.md`](docs/COMPLIANCE_REPORT.md). Every RFC and draft below is vendored under `docs/rfcs/` — see `docs/rfcs/index.jsonl` for the checksummed list.

#### Core and security

| Standard | Notes |
|---|---|
| [draft-ietf-oauth-v2-1-16](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — OAuth 2.1 | Core requirements enforced, adversarially tested |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) — Security BCP | Adversarially tested (`integration/`) |
| [draft-ietf-oauth-security-topics-update-03](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-update-03.txt) | AS-side audience hardening (§2.1), issuer-identifier audience (§2.1.2.1) |

#### Discovery, metadata and step-up

| Standard | Notes |
|---|---|
| [RFC 8414](https://tools.ietf.org/html/rfc8414) — AS Metadata | |
| [RFC 9207](https://tools.ietf.org/html/rfc9207.html) — Issuer Identification | `iss` in every response mode |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) — Protected Resource Metadata | |
| [RFC 9470](https://tools.ietf.org/html/rfc9470) — Step-Up Authentication | `acr_values`/`max_age`, `unmet_authentication_requirements` error |
| [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document) | Client ID Metadata Documents resolved at the AS behind the operator allow-list; [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) §6.1.3.1 metadata-policy operators (`value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, `essential`) applied between the identifier match and the credential enforcement (`cimd.NewPolicyResolver`); redirect URIs validated on the final document — the AI-agent examples run policy-governed |

#### Authorization requests and responses

| Standard | Notes |
|---|---|
| [RFC 7636](https://tools.ietf.org/html/rfc7636) — PKCE | S256 only, every client type, constant-time compare |
| [RFC 9126](https://tools.ietf.org/html/rfc9126.html) — PAR | Atomic single-use `request_uri`, client-bound |
| [RFC 9101](https://tools.ietf.org/html/rfc9101) — JAR | Signed request objects only |
| [FAPI JARM](https://openid.net/specs/openid-financial-api-jarm-ID1.html) | JWT response modes only, success and error |
| [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396) — Rich Authorization Requests | Carried in JAR objects, subset narrowing at the token endpoint, fail-closed |
| [RFC 8707](https://tools.ietf.org/html/rfc8707) — Resource Indicators | Registry-resolved URNs, unknown target rejected |

#### Grant types

| Standard | Notes |
|---|---|
| `authorization_code` | `code` only. PKCE, PAR, JAR, JARM all mandatory |
| `refresh_token` | Unconditional rotation, replay revokes the grant family |
| `client_credentials` | Asymmetric client authentication only |
| [RFC 8628](https://tools.ietf.org/html/rfc8628) — Device grant | RFC 10027 hardening: one-time codes, poll throttle, no refresh tokens |
| [CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | Poll mode, `binding_message` required, no refresh tokens (RFC 9700 §4.12.2) |
| [RFC 8693](https://tools.ietf.org/html/rfc8693) — Token Exchange | `may_act` gating, `act` chain depth cap 3 (fail-closed), `cnf` carried over |
| [draft-ietf-oauth-identity-chaining-17](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining) | Identity-chained tokens via token exchange, pairwise subjects |
| [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) — ID-JAG | Issuance at the IdP AS, redemption at the Resource AS (`sdk/idjag`) |
| [RFC 7523 §4](https://tools.ietf.org/html/rfc7523#section-4) — JWT Bearer grant | Redeems ID-JAG assertions at the Resource AS |

#### Client authentication and registration

| Standard | Notes |
|---|---|
| [RFC 7521](https://tools.ietf.org/html/rfc7521.html) / [RFC 7523](https://tools.ietf.org/html/rfc7523) — Assertion framework | |
| `private_key_jwt` | Algorithm allowlist checked before claims |
| [draft-ietf-oauth-attestation-based-client-auth-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) — `attest_jwt_client_auth` | Header transport, registry-pinned attesters, jti-burn replay protection |
| [draft-ietf-oauth-spiffe-client-auth-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) — `spiffe_jwt` / `spiffe_wit` / `spiffe_x509` | All three SVID types, bundle-sourced trust only |
| [RFC 8705 §2.1](https://tools.ietf.org/html/rfc8705) — `tls_client_auth` | Exact-one registered subject binding, fail-closed |
| [RFC 8705 §2.2](https://tools.ietf.org/html/rfc8705) — `self_signed_tls_client_auth` | Registered JWKS `x5c` match, method-confusion guard |
| [RFC 7591](https://tools.ietf.org/html/rfc7591) — Dynamic Client Registration | No client secrets issued, `code` only, operator-gated |
| [RFC 7592](https://tools.ietf.org/html/rfc7592) — Registration Management | Registration access token is the sole credential |

#### Token protection

| Standard | Notes |
|---|---|
| [RFC 6750](https://tools.ietf.org/html/rfc6750) — Bearer usage | Authorization header only. jkt-bound tokens rejected as Bearer |
| [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) — PoP key semantics | |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) — DPoP | Nonce support included, jti burned after full validation |
| [RFC 8705 §3](https://tools.ietf.org/html/rfc8705) — Certificate-bound tokens | `x5t#S256` confirmation, enforced at refresh |

#### Token formats

| Standard | Notes |
|---|---|
| [RFC 7519](https://tools.ietf.org/html/rfc7519) — JWT | EC + ML-DSA allowlist at sign time and check time |
| [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392) — CWT | COSE_Sign1, EC + ML-DSA only |
| [draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/) — HPKE with JWE | Integrated + Key Encryption modes |
| [draft-ietf-cose-hpke-27](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/) — HPKE with COSE | Shared ciphersuite registry with the JWE strategy |
| Reference tokens | Random string, signed UUID (verifiable) |

#### Privacy and selective disclosure

| Standard | Notes |
|---|---|
| [Pairwise subject identifiers](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg) | Per-sector, salted |
| [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.txt) — SD-JWT | Recursive disclosures, decoy digests, key binding mandatory |
| [draft-ietf-spice-sd-cwt-08](https://www.ietf.org/archive/id/draft-ietf-spice-sd-cwt-08.txt) — SD-CWT | COSE_Sign1 SD-CWT/KBT, definite-length and duplicate-key enforcement |

#### Token lifecycle

| Standard | Notes |
|---|---|
| [RFC 7662](https://tools.ietf.org/html/rfc7662) — Introspection | Opt-in disclosure: owner plus declared allowlist only |
| [RFC 7009](https://tools.ietf.org/html/rfc7009) — Revocation | Refresh revocation cascades to the grant family |

#### Constrained environments (ACE)

| Standard | Notes |
|---|---|
| [RFC 9200](https://www.rfc-editor.org/rfc/rfc9200) — ACE-OAuth | `application/ace+cbor` codec (`sdk/ace`), CoAP triangle demo |
| [RFC 9201](https://www.rfc-editor.org/rfc/rfc9201) — COSE profile | COSE_Key `cnf` members for PoP keys |
| [RFC 9202](https://www.rfc-editor.org/rfc/rfc9202) — DTLS profile | Mutual DTLS 1.2, certificate-bound tokens |
| [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747) — CWT PoP semantics | `cnf` by value and by reference |

### Integrations

| Transport | Deployment | Where |
|---|---|---|
| HTTP | Shared building blocks (`server/httpkit`) | Assembled by `examples/authorizationserver` |
| CoAP | Standalone ACE server, mutual DTLS 1.2 (RFC 9202 profile) | `examples/coapace` |
| AWS | Lambda | `examples/` |

## Design decisions

The per-decision design record lives in [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md). For every posture it states the relation to the governing standard (REPRESENTS / NEGATES / ENHANCES / HARDENS) and the override rules that settle standard conflicts. Per-standard conformance with executed test proof is in [`docs/COMPLIANCE_REPORT.md`](docs/COMPLIANCE_REPORT.md).

## Further reading

* [OAuth 2.0](https://oauth.net/2/) — the community site for the framework and its extensions
* [Financial-grade API security profiles](https://openid.net/specs/openid-financial-api-part-1.html) — read-only and read-write parts, the source of the JARM response-mode profile
* [OAuth 2.0 for Browser-Based Apps](https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.html) — current guidance for SPAs and browser apps
* [An Extensive Formal Security Analysis of the OpenID Financial-grade API](https://arxiv.org/abs/1901.11520) — the academic basis for the front-channel hardening decisions
* [PKCE vs. Nonce: Equivalent or Not?](https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/) — why SolID enforces both
