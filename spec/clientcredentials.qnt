/**
 * clientcredentials.qnt — formal model of the solid client_credentials
 * (machine-to-machine, RFC 6749 §4.4) grant lifecycle ( zntr.io/solid,
 * module `clientcredentials` ).
 *
 * COVERS
 *   - Shared grant preamble: client existence, grant capability check
 *     ( server/services/token/service.go: validateGrantPreamble )
 *   - Sender-constrained token policy: DPoP key binding
 *     ( server/services/token/grant_client_credentials.go: enforceSenderBinding )
 *   - Client type gating: only CONFIDENTIAL / CREDENTIALED clients may mint
 *     ( grant_client_credentials.go:73-82, invalid_client for public clients )
 *   - RFC 9396 fail-closed: authorization_details are rejected outright —
 *     the grant has no end-user consent authority
 *     ( grant_client_credentials.go:85-90 )
 *   - AT-only minting: NO refresh token is ever issued (no user, no
 *     consent); subject == client_id (RFC 9068 §4 — the client is the
 *     resource owner); GrantId = fresh random16 per mint, so every mint
 *     is its own grant family ( grant_client_credentials.go:99-125 )
 *   - Scope containment: minted scope ⊆ client's allowed scope set
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: JWT/DPoP signatures, key thumbprints are assumed
 *     correct; jkt is an abstract key id.
 *   - TLS client-certificate sender binding ( X5TS256 ) is not modeled;
 *     only the DPoP branch of enforceSenderBinding is.
 *   - Expiry / wall-clock: the 1h AT lifetime manifests as "minted" and
 *     never changes state (no clock in the model).
 *   - Client authentication — modeled as a closed client registry.
 *   - Audience validation (taken from the request verbatim, abstract).
 *   - Issuer syntax check (RFC 6749 §5.2 invalid_request) — abstract.
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/token/grant_client_credentials.go,
 *   server/services/token/service.go ( validateGrantPreamble /
 *   enforceSenderBinding ), or server/services/token/token.go.
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module clientcredentials {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12          // exploration bound on minted artifacts
  pure val CLIENTS: Set[str] = Set("pub", "conf", "cred")
  pure val CLIENT_TYPES: Set[str] = Set("public", "confidential", "credentialed")
  pure val M2M_TYPES: Set[str] = Set("confidential", "credentialed")
  pure val JKTS: Set[int] = Set(0, 1, 2) // abstract DPoP key ids; 0 = no proof

  // Scope universe: subsets of allowed scopes plus smuggling attempts.
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set(),
    Set("read"),
    Set("write"),
    Set("read", "write"),
    Set("admin"),            // never registered: smuggling attempt
    Set("read", "admin"),    // mixed smuggling attempt
  )

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // "client_credentials" capability
    clientType: str,         // public | confidential | credentialed
    dpopBound: bool,         // DpopBoundAccessTokens policy (RFC 10027 §6.1.12)
    allowedScopes: Set[str], // registered/default scope authority
  }

  type Token = {              // map presence = minted (ACTIVE)
    id: int,                  // jti; token value == id (abstract lookup key)
    kind: str,                // "access" | "refresh" (refresh is unreachable)
    client: str,              // authenticated client id
    subject: str,             // == client_id (RFC 9068 §4)
    grantId: int,             // fresh random16 per mint: own grant family
    scopes: Set[str],
    jkt: int,                 // DPoP key confirmation; 0 = unbound
    authzDetails: bool,            // authorization_details (RFC 9396) smuggled in
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  var clients: str -> Client  // registry (static after init)
  var tokens: int -> Token     // token id -> record
  var counter: int             // fresh id source (jtis, grant ids)

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client =
    { grants: Set(), clientType: "public", dpopBound: false, allowedScopes: Set() }
  pure val NO_TOKEN: Token =
    { id: -1, kind: "access", client: "", subject: "", grantId: -1,
      scopes: Set(), jkt: 0, authzDetails: false }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  pure def mkToken(id: int, client: str, grantId: int,
                   scopes: Set[str], jkt: int): Token =
    { id: id, kind: "access", client: client, subject: client,
      grantId: grantId, scopes: scopes, jkt: jkt, authzDetails: false }

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      // public client WITHOUT the client_credentials capability:
      // exercises both the type gate and the capability gate.
      "pub" -> { grants: Set(),
                 clientType: "public",
                 dpopBound: false,
                 allowedScopes: Set("read") },
      // confidential, DPoP-bound, with the capability.
      "conf" -> { grants: Set("client_credentials"),
                  clientType: "confidential",
                  dpopBound: true,
                  allowedScopes: Set("read", "write") },
      // credentialed, not DPoP-bound, with the capability.
      "cred" -> { grants: Set("client_credentials"),
                  clientType: "credentialed",
                  dpopBound: false,
                  allowedScopes: Set("read") },
    ),
    tokens' = Map(),
    counter' = 0,
  }

  // Token endpoint, client_credentials grant (grant_client_credentials.go).
  // FAITHFUL ORDERING, all guards BEFORE any effect (this grant has no
  // burn-before-check hazard — nothing is consumed):
  //   1. client exists (validateGrantPreamble)
  //   2. sender binding (enforceSenderBinding): a DPoP-bound client MUST
  //      present a proof; an unbound client MUST NOT carry one
  //   3. client type ∈ {confidential, credentialed} (else invalid_client)
  //   4. authorization_details == ∅ (RFC 9396 fail-closed: no consent
  //      authority exists at this grant → invalid_authorization_details)
  //   5. capability client_credentials (else unauthorized_client)
  //   6. requested scope ⊆ registered/default scope (CC1)
  //   7. fresh ids available
  // Effect: mint exactly ONE access token. Subject == client_id, GrantId
  // is fresh (own family), no refresh token can ever appear.
  action mint(client: str, scopes: Set[str], proofJkt: int, authzDetails: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    all {
      clients.keys().contains(client),
      // enforceSenderBinding (DPoP branch): jkt ≠ 0 iff client is bound.
      cl.dpopBound == (proofJkt != 0),
      M2M_TYPES.contains(cl.clientType),
      not (authzDetails),
      cl.grants.contains("client_credentials"),
      scopes.forall(s => cl.allowedScopes.contains(s)),
      counter < MAX_IDS,
      tokens' = tokens.put(counter,
        mkToken(counter, client, counter, scopes, proofJkt)),
      clients' = clients,
      counter' = counter + 1,
    }
  }

  // Adversarial variant (integration/rfc9396_adversarial_test.go):
  // a request that smuggles authorization_details. Its guard requires
  // authzDetails ∅, so this action is DISABLED in every reachable state —
  // the fail-closed policy made structural.
  action attemptWithDetails(client: str, scopes: Set[str], proofJkt: int): bool =
    mint(client, scopes, proofJkt, true)

  // ------------------------------------------------------------------
  // Step (random protocol walks)
  // ------------------------------------------------------------------

  action mintStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    nondet authzDetails = Set(true, false).oneOf()
    mint(client, scopes, proofJkt, authzDetails)
  }

  action attemptWithDetailsStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    attemptWithDetails(client, scopes, proofJkt)
  }

  action step: bool = any {
    mintStep,
    attemptWithDetailsStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants
  // ------------------------------------------------------------------

  val allTokens: Set[Token] = tokens.keys().map(k => tokens.get(k))

  // CC1 — RFC 9396 fail-closed + scope authority: a client_credentials
  // mint NEVER carries authorization_details, and its scope is within
  // the client's registered/default scope set.
  val inv_cc1_noDetailsAndScopeContained: bool =
    allTokens.forall(t =>
      not (t.authzDetails)
      and t.scopes.forall(s => clients.get(t.client).allowedScopes.contains(s)))

  // CC2 — no refresh token: structurally, every token ever minted by this
  // grant is an access token; no RT can exist in any reachable state.
  val inv_cc2_noRefreshToken: bool =
    allTokens.forall(t => t.kind == "access")

  // CC3 — subject == client: the client IS the resource owner
  // (RFC 9068 §4); impersonation of another principal is impossible.
  val inv_cc3_subjectIsClient: bool =
    allTokens.forall(t => t.subject == t.client)

  // CC4 — client type & capability gating: tokens are only ever minted
  // for clients with type ∈ {confidential, credentialed} that hold the
  // client_credentials grant capability.
  val inv_cc4_m2mCapableOnly: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      M2M_TYPES.contains(cl.clientType)
      and cl.grants.contains("client_credentials")
    })

  // CC5 — sender binding respected: a DPoP-bound client's tokens always
  // carry a non-empty jkt; an unbound client's tokens carry jkt = 0 only.
  val inv_cc5_senderBinding: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      cl.dpopBound == (t.jkt != 0)
    })

  // CC6 — fresh grant families: GrantId = random16 per mint, so distinct
  // tokens never share a grant family.
  val inv_cc6_uniqueGrantFamilies: bool =
    not (allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id
      and t1.grantId == t2.grantId)))

  val allInvariants: bool = all {
    inv_cc1_noDetailsAndScopeContained,
    inv_cc2_noRefreshToken,
    inv_cc3_subjectIsClient,
    inv_cc4_m2mCapableOnly,
    inv_cc5_senderBinding,
    inv_cc6_uniqueGrantFamilies,
  }

  // ------------------------------------------------------------------
  // Witnesses (one per action — reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_minted: bool = allTokens.size() > 0
  val w_confDpopBoundMinted: bool =
    allTokens.exists(t => t.client == "conf" and t.jkt != 0)
  val w_credUnboundMinted: bool =
    allTokens.exists(t => t.client == "cred" and t.jkt == 0)
  val w_twoGrantsDistinctFamilies: bool =
    allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id and t1.grantId != t2.grantId))

}
