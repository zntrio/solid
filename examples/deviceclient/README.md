# Device Client (DPoP-bound client_credentials)

Despite the name inherited from the device ecosystem, this demo exercises a
`client_credentials` grant whose access tokens must be DPoP-bound
(`DpopBoundAccessTokens` on the fixture client), then calls the timestamp
resource with a fresh proof carrying the token value.

Prerequisite: `authorizationserver` and `resourceserver` running
(see [`../README.md`](../README.md)).

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as deviceclient (fixture key ML-DSA-65)
    participant T as AS /token
    participant R as Resource server :8085

    C->>C: build private_key_jwt assertion (iss=sub=client_id, aud=issuer)
    C->>C: mint DPoP proof (POST /token, embedded JWK)
    C->>T: POST grant=client_credentials + assertion + DPoP proof
    T->>T: verify assertion (jti burned), verify proof → jkt
    T->>T: mint access token bound to jkt (cnf.jkt, token_type=DPoP)
    T-->>C: access_token
    C->>C: mint resource proof (POST /, ath = access token hash)
    C->>R: Authorization: DPoP <token> + DPoP proof
    R->>T: introspect (as authorized introspection client)
    T-->>R: active, cnf.jkt set
    R->>R: verify proof jkt == token cnf.jkt, scope timestamp:read
    R-->>C: signed timestamp response
```

## What it proves

* Client authentication is asymmetric only (`private_key_jwt`,
  ML-DSA-65): no secrets over the wire.
* DPoP sender-constrains both the minted token (proof at the token
  endpoint) and its use (fresh proof with `ath` at the resource).
* The resource server refuses bearer use of a DPoP-bound token
  (`cnf.jkt` set → proof required).
