# Attestation Server

Issues client attestation JWTs for the attestation-based client
authentication demo. It signs with a fixed fixture seed so the
authorization server (which pins the corresponding public key in its static
client registry) can verify attestations across processes.

Prerequisite of `attestationclient`; see [`../README.md`](../README.md).

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as attestationclient
    participant S as Attestation server :8087
    participant AS as Authorization server

    Note over S: boot: ML-DSA-65 key from fixture seed
    C->>S: POST /attestations/sign { clientPublicKey, clientId }
    S->>S: build attestation: iss=urn:solid:attestation-server, sub=clientId, cnf.jwk=clientPublicKey
    S->>S: sign with fixture key (typ client-attestation+jwt, jwk header)
    S-->>C: attestation JWT (1h validity)
    AS->>S: GET /attestations/jwks (at first verification)
    S-->>AS: signing public JWKS
    Note over AS: verifies every attestation against this JWKS,<br/>then checks the client's PoP against cnf.jwk
```

## What it proves

* The attestation is a bearer-bindable credential for exactly one client
  public key (`cnf.jwk` echoes the request's key verbatim).
* The signing key is out-of-band pinned: the AS registry fixture
  (`urn:solid:attestation-server` client entry) trusts the JWKS published
  at `/attestations/jwks`.
* A real deployment would derive this key from secure hardware and
  authenticate requesting clients; the example keeps it deliberately
  minimal.
