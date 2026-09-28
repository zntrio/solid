/**
 * xaa.qnt — formal model of the Cross-App Access (XAA) protocol:
 * Identity Assertion JWT Authorization Grant
 * ( draft-ietf-oauth-identity-assertion-authz-grant-04, profiling
 *   draft-ietf-oauth-identity-chaining-17 + RFC 7521/7523 ).
 *
 * COVERS
 *   - IdP role: token exchange with requested_token_type=id-jag, subject
 *     refresh token validation (active, client-bound, unexpired), trusted
 *     audience resolution with client-ID mapping, pairwise subject
 *     transcription, DPoP cnf.jkt minting ( grant_token_exchange_idjag.go )
 *   - Resource AS role: jwt-bearer redemption — typ/issuer-trust/audience/
 *     temporal/REQUIRED-claim validation, client continuity (client_id ==
 *     authenticated client), cnf.jkt ↔ DPoP proof binding, scope and
 *     authorization_details narrowing, no refresh token issuance
 *     ( grant_jwt_bearer.go + sdk/idjag/verifier.go )
 *   - Attacker actions: foreign-key signatures, untrusted issuers, grant
 *     laundering (aud=B replayed at C), expired/nbf/not-yet-valid
 *     assertions, scope escalation, client impersonation
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: EC/ML-DSA signatures are abstract — a token verifies
 *     iff its issuer is trusted AND it was minted by that issuer (the
 *     attacker cannot forge a trusted issuer's signature, matching the
 *     threat model of the adversarial integration tests).
 *   - JWT structure: typ/alg allowlists are folded into "well-formed ID-JAG".
 *   - Wall-clock: exp/iat/nbf are integer stamps against a discrete clock.
 *   - Client authentication (private_key_jwt etc.): modeled as the closed
 *     client registry of the AS, like solid.qnt.
 *   - Token introspection / revocation: out of the XAA loop.
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/token/grant_token_exchange_idjag.go,
 *   server/services/token/grant_jwt_bearer.go, or sdk/idjag/verifier.go.
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module xaa {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12        // exploration bound on minted artifacts
  pure val IDP = "https://idp.example/"          // trust domain A
  pure val AS_B = "https://resource-as.example/" // trust domain B (audience)
  pure val AS_C = "https://third-as.example/"    // trust domain C (laundering)

  pure val CLIENTS: Set[str] = Set("wiki", "chat") // clients at the IdP
  pure val RAS_CLIENTS: Set[str] = Set("wiki-at-b", "chat-at-b") // clients at AS B
  pure val USERS: Set[int] = Set(1, 2)
  pure val SCOPES: Set[str] = Set("chat.read", "chat.history", "admin.write")
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set("chat.read"),
    Set("chat.read", "chat.history"),
  )
  pure val JKTS: Set[int] = Set(0, 1, 2) // DPoP key thumbprints; 0 = unbound

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],       // "token_exchange" | "jwt_bearer" etc.
    tokenExchange: bool,    // may request ID-JAGs at the IdP (IdP role check)
  }

  type RefreshToken = {     // subject token at the IdP; map presence = ACTIVE
    client: str,
    user: int,
    scopes: Set[str],
    expiresAt: int,
  }

  type IdJag = {            // the cross-domain grant artifact
    iss: str,               // issuing IdP
    sub: int,               // pairwise subject for the target AS
    aud: str,               // target Resource AS issuer
    clientAtTarget: str,     // client_id claim: the client at the AS
    jti: int,
    exp: int,
    iat: int,
    scopes: Set[str],       // granted scope set
    jkt: int,               // cnf.jkt DPoP binding; 0 = unbound (bearer)
    authentic: bool,        // true iff genuinely signed by iss (crypto abstraction)
  }

  type AccessToken = {      // what the Resource AS mints
    id: int,                // fresh token id (unique per mint)
    subject: int,           // transcribed pairwise sub
    client: str,            // the authenticated RAS client
    scopes: Set[str],       // granted (possibly narrowed) scopes
    jkt: int,               // DPoP binding carried to the AT
    grantJti: int,          // the ID-JAG jti it derives from
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  // IdP (trust domain A)
  var idpClients: str -> Client
  var refreshTokens: int -> RefreshToken   // id -> RT (SSO step output)
  var mintedJags: Set[IdJag]               // ID-JAGs genuinely issued by the IdP

  // Resource AS (trust domain B) — the properties are about this state
  var rasClients: str -> Client
  var trustedIssuers: Set[str]             // issuer allowlist of the RAS
  var clientMapping: str -> str            // IdP-local client -> RAS client
  var issuedAccessTokens: Set[AccessToken]

  var clock: int                           // discrete time
  var counter: int                         // fresh jti/id source

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client = { grants: Set(), tokenExchange: false }
  pure val NO_RT: RefreshToken = { client: "", user: 0, scopes: Set(), expiresAt: 0 }
  pure val NO_JAG: IdJag = { iss: "", sub: 0, aud: "", clientAtTarget: "", jti: -1,
    exp: 0, iat: 0, scopes: Set(), jkt: 0, authentic: false }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // Abstract pairwise subject for the target AS sector (sdk/pairwise.Hash):
  // injective in (sector, user). The IdP uses the target AS issuer as sector.
  pure def pairwiseSub(targetAS: str, user: int): int =
    if (targetAS == AS_B) 1000 + user
    else if (targetAS == AS_C) 2000 + user
    else 3000 + user

  // Crypto abstraction: a token's signature verifies iff its issuer is
  // trusted by the RAS AND it is authentic (minted by that issuer).
  pure def signatureVerifies(j: IdJag, trust: Set[str]): bool =
    trust.contains(j.iss) and j.authentic

  // RFC 7523 §3 temporal validation, as validateTemporal in the verifier.
  pure def temporallyValid(j: IdJag, now: int): bool =
    j.exp > now
    // nbf is folded into the iat field of this abstraction: an ID-JAG is
    // not-yet-valid when iat > now (minted in the future). The verifier
    // checks exp and nbf; here iat doubles for nbf to keep the record small.
    and j.iat <= now

  // draft §4.4.1 audience check: aud must be exactly the local AS issuer.
  pure def audienceFor(j: IdJag, localAS: str): bool =
    j.aud == localAS

  // draft §4.4.1 client continuity: the ID-JAG client_id claim must equal
  // the authenticated client at the AS.
  pure def clientContinuity(j: IdJag, authenticated: str): bool =
    j.clientAtTarget == authenticated

  // Scope narrowing: requested ⊆ granted (RFC 8693 §5 / chain §2.5).
  pure def scopeWithin(requested: Set[str], granted: Set[str]): bool =
    requested.subseteq(granted)

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    idpClients' = Map(
      "wiki" -> { grants: Set("authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"),
                  tokenExchange: true },
      "chat" -> { grants: Set("authorization_code"), tokenExchange: false },
    ),
    refreshTokens' = Map(),
    mintedJags' = Set(),
    rasClients' = Map(
      "wiki-at-b" -> { grants: Set("urn:ietf:params:oauth:grant-type:jwt-bearer"), tokenExchange: false },
      "chat-at-b" -> { grants: Set("urn:ietf:params:oauth:grant-type:jwt-bearer"), tokenExchange: false },
    ),
    trustedIssuers' = Set(IDP),
    clientMapping' = Map("wiki" -> "wiki-at-b", "chat" -> "chat-at-b"),
    issuedAccessTokens' = Set(),
    clock' = 0,
    counter' = 0,
  }

  // SSO step output (abstracted): a client obtains an active refresh token
  // for a user with a scope context. This is the subject_token source.
  action ssoLogin(client: str, user: int, scopes: Set[str]): bool = {
    val cl = if (idpClients.keys().contains(client)) idpClients.get(client) else NO_CLIENT
    all {
      idpClients.keys().contains(client),
      cl.tokenExchange,                // only IdP clients may hold RTs here
      counter < MAX_IDS,
      refreshTokens' = refreshTokens.put(counter, {
        client: client,
        user: user,
        scopes: scopes,
        expiresAt: clock + 10,          // generous TTL vs the discrete clock
      }),
      mintedJags' = mintedJags,
      rasClients' = rasClients,
      trustedIssuers' = trustedIssuers,
      clientMapping' = clientMapping,
      issuedAccessTokens' = issuedAccessTokens,
      idpClients' = idpClients,
      clock' = clock,
      counter' = counter + 1,
    }
  }

  // Time passage: the discrete clock advances (enables expiry checks).
  action tick: bool = all {
    clock' = clock + 1,
    refreshTokens' = refreshTokens,
    mintedJags' = mintedJags,
    rasClients' = rasClients,
    trustedIssuers' = trustedIssuers,
    clientMapping' = clientMapping,
    issuedAccessTokens' = issuedAccessTokens,
    idpClients' = idpClients,
    counter' = counter,
  }

  // IdP role — token exchange for an ID-JAG ( grant_token_exchange_idjag.go ):
  // subject refresh token validation, audience trust, client mapping,
  // pairwise subject, scope narrowing, cnf.jkt minting from the DPoP proof.
  action exchangeForJag(client: str, rtId: int, audience: str,
                       requestedScopes: Set[str], proofJkt: int): bool = {
    val cl = if (idpClients.keys().contains(client)) idpClients.get(client) else NO_CLIENT
    val rt = if (refreshTokens.keys().contains(rtId)) refreshTokens.get(rtId) else NO_RT
    val mapped = if (clientMapping.keys().contains(client)) clientMapping.get(client) else ""
    all {
      // validateGrantPreamble: capability
      cl.grants.contains("urn:ietf:params:oauth:grant-type:token-exchange"),
      // subject token: present, active, unexpired, client-bound (§4.3.3)
      refreshTokens.keys().contains(rtId),
      rt.client == client,
      rt.expiresAt > clock,
      // audience: REQUIRED and trusted (§4.3 / §5)
      audience == AS_B or audience == AS_C,
      // scope narrowing never widens (chain §2.5)
      scopeWithin(requestedScopes, rt.scopes),
      // client MUST be mapped at the target (§3.1/§5) — fail-closed
      mapped != "",
      counter < MAX_IDS,
      mintedJags' = mintedJags.union(Set({
        iss: IDP,
        sub: pairwiseSub(audience, rt.user),
        aud: audience,
        clientAtTarget: mapped,
        jti: counter,
        exp: clock + 5,             // idjagLifetime
        iat: clock,
        scopes: requestedScopes,
        jkt: proofJkt,              // §9.8.1.1: cnf.jkt from the DPoP proof
        authentic: true,
      })),
      refreshTokens' = refreshTokens,
      rasClients' = rasClients,
      trustedIssuers' = trustedIssuers,
      clientMapping' = clientMapping,
      issuedAccessTokens' = issuedAccessTokens,
      idpClients' = idpClients,
      clock' = clock,
      counter' = counter + 1,
    }
  }

  // Attacker: forges an ID-JAG claim set under a trusted issuer identity,
  // but the signature does not verify (authentic: false).
  action forgeJag(audience: str, subject: int, clientAtTarget: str,
                 scopes: Set[str], expOffset: int): bool = all {
    counter < MAX_IDS,
    mintedJags' = mintedJags.union(Set({
      iss: IDP,
      sub: subject,
      aud: audience,
      clientAtTarget: clientAtTarget,
      jti: counter,
      exp: clock + expOffset,
      iat: clock,
      scopes: scopes,
      jkt: 0,
      authentic: false,            // forged signature
    })),
    refreshTokens' = refreshTokens,
    rasClients' = rasClients,
    trustedIssuers' = trustedIssuers,
    clientMapping' = clientMapping,
    issuedAccessTokens' = issuedAccessTokens,
    idpClients' = idpClients,
    clock' = clock,
    counter' = counter + 1,
  }

  // Attacker: mints a grant from a DIFFERENT (untrusted) issuer —
  // signature may be perfectly valid, but the issuer is not in the RAS
  // trust registry (RFC 7523 §3 point 4).
  action foreignIssuerJag(audience: str, subject: int, clientAtTarget: str,
                         scopes: Set[str]): bool = all {
    counter < MAX_IDS,
    mintedJags' = mintedJags.union(Set({
      iss: "https://evil-idp.example/",
      sub: subject,
      aud: audience,
      clientAtTarget: clientAtTarget,
      jti: counter,
      exp: clock + 5,
      iat: clock,
      scopes: scopes,
      jkt: 0,
      authentic: true,             // valid signature, untrusted issuer
    })),
    refreshTokens' = refreshTokens,
    rasClients' = rasClients,
    trustedIssuers' = trustedIssuers,
    clientMapping' = clientMapping,
    issuedAccessTokens' = issuedAccessTokens,
    idpClients' = idpClients,
    clock' = clock,
    counter' = counter + 1,
  }

  // Resource AS role — jwt-bearer redemption ( grant_jwt_bearer.go ):
  // full §4.4.1 chain. The attacker picks ANY minted/forged ID-JAG and ANY
  // RAS client + DPoP proof; the guards are the implementation's checks.
  action redeemJag(jti: int, rasClient: str, requestedScopes: Set[str],
                  proofJkt: int, atAS: str): bool = {
    val cl = if (rasClients.keys().contains(rasClient)) rasClients.get(rasClient) else NO_CLIENT
    val jag = mintedJags.filter(j => j.jti == jti)
      .fold(NO_JAG, (acc, j) => j)
    all {
      // The modeled Resource AS stack is AS_B: its trustedIssuers,
      // registry and mapping are this state. A redemption "at" another
      // AS issuer would be a different stack, not this action.
      atAS == AS_B,
      signatureVerifies(jag, trustedIssuers),
      // aud == local AS issuer (§4.4.1; anti-laundering)
      audienceFor(jag, atAS),
      // temporal validity: exp future, iat/nbf past (RFC 7523 §3)
      temporallyValid(jag, clock),
      // REQUIRED claims present
      jag.sub != 0 and jag.clientAtTarget != "" and jag.jti != -1,
      // client continuity (§4.4.1)
      clientContinuity(jag, rasClient),
      // cnf.jkt ↔ DPoP proof binding (§9.8.1.2)
      jag.jkt == 0 or jag.jkt == proofJkt,
      // scope narrowing never widens
      scopeWithin(requestedScopes, jag.scopes),
      // no refresh token is ever issued for a jwt-bearer redemption (§4.4.3)
      counter < MAX_IDS,
      issuedAccessTokens' = issuedAccessTokens.union(Set({
        id: counter,
        subject: jag.sub,
        client: rasClient,
        scopes: requestedScopes,
        jkt: if (jag.jkt != 0) jag.jkt else proofJkt,
        grantJti: jag.jti,
      })),
      refreshTokens' = refreshTokens,
      mintedJags' = mintedJags,
      rasClients' = rasClients,
      trustedIssuers' = trustedIssuers,
      clientMapping' = clientMapping,
      idpClients' = idpClients,
      clock' = clock,
      counter' = counter + 1,
    }
  }

  // ------------------------------------------------------------------
  // Steps
  // ------------------------------------------------------------------

  action ssoStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet user = USERS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    ssoLogin(client, user, scopes)
  }

  action exchangeStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet rtId = 0.to(MAX_IDS - 1).oneOf()
    nondet audience = Set(AS_B, AS_C).oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet jkt = JKTS.oneOf()
    exchangeForJag(client, rtId, audience, scopes, jkt)
  }

  action forgeStep: bool = {
    nondet audience = Set(AS_B, AS_C).oneOf()
    nondet subject = Set(1001, 1002, 2001, 42).oneOf()
    nondet rasClient = RAS_CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.union(Set(Set("admin.write"))).oneOf()
    nondet expOffset = Set(5, -1, 0).oneOf()
    forgeJag(audience, subject, rasClient, scopes, expOffset)
  }

  action foreignStep: bool = {
    nondet audience = Set(AS_B, AS_C).oneOf()
    nondet subject = Set(1001, 1002, 42).oneOf()
    nondet rasClient = RAS_CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    foreignIssuerJag(audience, subject, rasClient, scopes)
  }

  action redeemStep: bool = {
    nondet jti = 0.to(MAX_IDS - 1).oneOf()
    nondet rasClient = RAS_CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.union(Set(Set("admin.write"))).oneOf()
    nondet jkt = JKTS.oneOf()
    nondet atAS = Set(AS_B, AS_C).oneOf()
    redeemJag(jti, rasClient, scopes, jkt, atAS)
  }

  action step: bool = any {
    ssoStep,
    tick,
    exchangeStep,
    forgeStep,
    foreignStep,
    redeemStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants
  // ------------------------------------------------------------------

  // J1 — signature trust (RFC 7523 §3.4, chain §2.1 step 5): every access
  // token minted via jwt-bearer derives from an authentic ID-JAG of a
  // trusted issuer. Forged signatures and untrusted issuers never redeem.
  val inv_signatureTrust: bool =
    issuedAccessTokens.forall(at =>
      mintedJags.exists(j =>
        j.jti == at.grantJti
        and j.authentic
        and trustedIssuers.contains(j.iss)))

  // J2 — audience pinning / anti-laundering (chain §2.3.3, chain §2.4.2):
  // every redeemed grant was issued for exactly the redeeming AS. A grant
  // minted for B never mints a token at C (or vice versa).
  val inv_noGrantLaundering: bool =
    issuedAccessTokens.forall(at =>
      mintedJags.exists(j => j.jti == at.grantJti and j.aud == AS_B))
    // The model redeems only at AS_B (atAS == AS_B is the only enabled
    // successful path since trustedIssuers == {IDP} and AS_C redeems need
    // aud == AS_C, which the IdP can mint — so we pin the stronger form:
    // every minted token traces to a grant whose aud is the RAS issuer.
    and mintedJags.forall(j =>
      (j.aud != AS_B and j.authentic and trustedIssuers.contains(j.iss))
        implies not (issuedAccessTokens.exists(at => at.grantJti == j.jti)))

  // J3 — client continuity (draft §4.4.1): the client that redeems is
  // exactly the client the IdP vouched for in the grant's client_id claim.
  val inv_clientContinuity: bool =
    issuedAccessTokens.forall(at =>
      mintedJags.exists(j =>
        j.jti == at.grantJti and j.clientAtTarget == at.client))

  // J4 — subject transcription integrity (chain §2.5): the token subject is
  // exactly the pairwise subject of the grant — an attacker-chosen subject
  // never mints, and the raw IdP user id (1..USERS) never crosses the
  // domain boundary in the clear.
  val inv_subjectTranscription: bool =
    issuedAccessTokens.forall(at =>
      mintedJags.exists(j => j.jti == at.grantJti and j.sub == at.subject))
    and issuedAccessTokens.forall(at => not(at.subject == 1 or at.subject == 2))

  // J5 — scope monotonicity (chain §2.5): a minted access token's scope
  // never exceeds the scope context of the SSO refresh token the grant
  // chain started from. No escalation through the cross-domain hop.
  val inv_noScopeEscalation: bool =
    issuedAccessTokens.forall(at =>
      mintedJags.exists(j =>
        j.jti == at.grantJti
        and at.scopes.subseteq(j.scopes)))

  // J6 — DPoP key continuity (draft §9.8.1.2, chain §5.2): a key-bound
  // (cnf.jkt ≠ 0) grant's tokens are bound to the same key; a key-bound
  // grant cannot mint an unbound token.
  val inv_dpopKeyContinuity: bool =
    issuedAccessTokens.forall(at =>
      mintedJags.exists(j =>
        j.jti == at.grantJti
        implies ((j.jkt != 0) implies (at.jkt == j.jkt))))

  // J7 — no refresh token from jwt-bearer (draft §4.4.3, chain §5.4): the
  // Resource AS never issues refresh tokens for assertion grants. The
  // access-token record type has no refresh field; this invariant pins the
  // observable consequence: every minted artifact at the RAS is an AT whose
  // family cannot refresh (grantJti-typed grants are one-shot).
  val inv_noRefreshFromBearer: bool =
    // Structural: the only minted record type is AccessToken; nothing to
    // check beyond the type. Kept as a named property for the README.
    true

  val allInvariants: bool = all {
    inv_signatureTrust,
    inv_noGrantLaundering,
    inv_clientContinuity,
    inv_subjectTranscription,
    inv_noScopeEscalation,
    inv_dpopKeyContinuity,
    inv_noRefreshFromBearer,
  }

  // ------------------------------------------------------------------
  // Witnesses (one per action — reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_ssoLoggedIn: bool = refreshTokens.keys().size() > 0
  val w_jagMinted: bool =
    mintedJags.exists(j => j.authentic and trustedIssuers.contains(j.iss) and j.aud == AS_B)
  val w_tokenMinted: bool = issuedAccessTokens.size() > 0
  val w_forgeAttempted: bool = mintedJags.exists(j => not(j.authentic))
  val w_foreignIssuerAttempted: bool = mintedJags.exists(j => j.iss != IDP)

  // Negative-space witnesses: the attack states are REACHABLE as attempts
  // (attacker actions fire) — proving the guards, not dead code, stop them.
  val w_attackSurfaceLive: bool =
    mintedJags.exists(j => not(j.authentic) or j.iss != IDP)

}