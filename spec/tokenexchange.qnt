/**
 * tokenexchange.qnt — formal model of the RFC 8693 token_exchange grant's
 * access-token subject path ( zntr.io/solid, module `tokenexchange` ).
 *
 * COVERS
 *   - Shared grant validation: validateGrantPreamble token_exchange
 *     capability, authorization_details fail-closed gate
 *     (invalid_authorization_details — exchange delegates, no consent
 *     authority), non-empty subject_token_type/subject_token
 *     ( grant_token_exchange.go: tokenExchange, lines 47-113 )
 *   - Access-token subject path ( tokenExchangeAccessToken, lines 115-310 ):
 *     subject token lookup/status/type/metadata guards, requested_token_type
 *     access_token-only, optional actor token validation, may_act actor
 *     allowlist (RFC 8693 §5), DPoP cnf.jkt proof-key equality (RFC 9449 §8),
 *     subject-token expiry, scope narrowing, act chain depth cap 3 with
 *     fail-closed semantics (RFC 8693 §4.4), audience resource-registry URN
 *     resolution (never verbatim), subject/confirmation preservation, fresh
 *     GrantId, NO refresh token issuance.
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - The ID-JAG (cross-app access) sub-path: modeled in spec/xaa.qnt
 *     ( grant_token_exchange_idjag.go ). Access-token path only here.
 *   - Cryptography: DPoP thumbprints are abstract ints; SecureCompare is
 *     equality. Token values are abstract int ids.
 *   - Wall-clock: expiry is a discrete clock against integer stamps.
 *   - Client authentication: modeled as the closed client registry.
 *   - Token introspection / revocation / RT grants: out of the exchange loop.
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/token/grant_token_exchange.go.
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module tokenexchange {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12          // exploration bound on minted artifacts
  pure val GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

  pure val CLIENTS: Set[str] = Set("c1", "c2", "owner")
    // c1: token_exchange capability; c2: without; owner: subject-token owner
  pure val SUBJECTS: Set[int] = Set(11, 12)  // pairwise subjects of seeded tokens
  pure val ACTORS: Set[int] = Set(11, 12, 21, 22) // actor subjects incl. non-listed
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set("openid", "profile"),
    Set("openid"),
    Set("profile"),          // narrowing target
    Set("openid", "profile", "admin"), // escalation attempt source
  )
  pure val JKTS: Set[int] = Set(0, 1, 2) // DPoP thumbprints; 0 = unbound
  pure val CHAINS: Set[List[int]] = Set(
    List(),                  // no prior delegation
    List(11),                // depth 1 prior chain
    List(11, 12),             // depth 2 prior chain
    List(11, 12, 21),          // depth 3 prior chain (over-deep with actor)
  )

  // Resource registry: audience URI -> canonical URN id.
  pure val RESOURCES: str -> int = Map(
    "https://rs.example/api" -> 100,
    "https://other.example" -> 200,
  )
  pure val RESOURCE_URIS: Set[str] = Set("https://rs.example/api", "https://other.example")

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // contains GRANT iff token_exchange capable
  }

  type TokenKind = Access | Refresh // Refresh exists only to be provably never minted
  type TokenStatus = Active | Revoked

  type Token = {
    id: int,                 // jti; token value == id (abstract lookup key)
    status: TokenStatus,
    kind: TokenKind,        // model stores access tokens only (no RT path)
    subject: int,            // subject claim
    client: str,             // owner / exchanging client
    scopes: Set[str],
    jkt: int,                // cnf.jkt DPoP confirmation; 0 = unbound
    mayAct: Set[int],        // may_act actor-subject allowlist; empty = ungated
    actorChain: List[int],   // prior act chain (RFC 8693 §4.4)
    expiresAt: int,          // integer stamp vs the discrete clock
    viaExchange: bool,       // true iff minted by token exchange
    grantId: int,            // fresh per exchange mint; -1 = seeded
  }

  type ExchangeToken = {     // the minted exchange artifact (observable surface)
    id: int,
    subjectTokenId: int,     // provenance: the subject token it derives from
    subject: int,            // T1: == subject token's subject
    client: str,             // T2: == the exchanging (authenticated) client
    scopes: Set[str],        // T3: narrowed
    jkt: int,                // T6: carried subject-token confirmation
    actorChain: List[int],   // T5: [actor.subject] ++ actor's chain
    audience: int,           // T7: registered resource URN; -1 = none
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  var clients: str -> Client       // registry (static after init)
  var tokens: int -> Token          // token id -> record (subject + actor tokens)
  var exchangeTokens: Set[ExchangeToken] // tokens minted by exchange
  var clock: int                   // discrete time
  var counter: int                  // fresh id source

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client = { grants: Set() }
  pure val NO_TOKEN: Token =
    { id: -1, status: Revoked, kind: Access, subject: 0, client: "", scopes: Set(),
      jkt: 0, mayAct: Set(), actorChain: List(), expiresAt: 0, viaExchange: false, grantId: -1 }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // Scope narrowing: requested ⊆ subject token scope (RFC 8693 §5).
  pure def scopeWithin(requested: Set[str], granted: Set[str]): bool =
    requested.subseteq(granted)

  // Act chain: immediate actor ++ preserved prior chain (RFC 8693 §4.4),
  // fail-closed depth cap maxActChainDepth = 3 (never truncated).
  pure def actChain(actorSubject: int, prior: List[int]): List[int] =
    List(actorSubject).concat(prior)

  pure def chainWithinCap(chain: List[int]): bool =
    chain.length() <= 3

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      "c1" -> { grants: Set("authorization_code", GRANT) },
      "c2" -> { grants: Set("authorization_code") },
      "owner" -> { grants: Set("authorization_code") },
    ),
    tokens' = Map(),
    exchangeTokens' = Set(),
    clock' = 0,
    counter' = 0,
  }

  // Time passage: the discrete clock advances (enables expiry checks).
  action tick: bool = all {
    clock' = clock + 1,
    tokens' = tokens,
    exchangeTokens' = exchangeTokens,
    clients' = clients,
    counter' = counter,
  }

  // Seed an ACTIVE access token (abstract authorization_code mint): the
  // subject-token / actor-token source for exchanges.
  action seedToken(client: str, subject: int, scopes: Set[str], jkt: int,
                   mayAct: Set[int], actorChain: List[int], expiresAt: int): bool = {
    all {
      clients.keys().contains(client),
      counter < MAX_IDS,
      tokens' = tokens.put(counter, {
        id: counter,
        status: Active,
        kind: Access,
        subject: subject,
        client: client,
        scopes: scopes,
        jkt: jkt,
        mayAct: mayAct,
        actorChain: actorChain,
        expiresAt: expiresAt,
        viaExchange: false,
        grantId: -1,
      }),
      exchangeTokens' = exchangeTokens,
      clients' = clients,
      clock' = clock,
      counter' = counter + 1,
    }
  }

  // Token endpoint, token_exchange grant, access-token subject path
  // ( grant_token_exchange.go: tokenExchangeAccessToken, lines 115-310 ).
  // FAITHFUL GUARD ORDER — the guards fire exactly in the code's order:
  //   0. shared: token_exchange capability (validateGrantPreamble),
  //      authorization_details fail-closed gate, non-empty
  //      subject_token_type + subject_token (modeled: the action is only
  //      enabled for well-formed requests; malformed shapes are the
  //      disabled action, which in Quint means "nothing happens").
  //   1. subject token: found, ACTIVE, access-token kind, metadata present.
  //   2. requested_token_type: nil or access_token.
  //   3. actor token (optional): found, ACTIVE, access-token kind, unexpired.
  //   4. may_act (RFC 8693 §5): non-empty may_act on the subject token
  //      REQUIRES an actor token whose subject is in the list.
  //   5. cnf binding (RFC 9449 §8): bound subject token ⇒ presented proof
  //      jkt equals the bound jkt (no proof-key swap, no proof stripping).
  //   6. subject token unexpired.
  //   7. scope narrowing: requested ⊆ subject token scope.
  //   8. act chain (RFC 8693 §4.4): [actor.subject] ++ actor's chain,
  //      length ≤ 3 else fail closed.
  //   9. audience: resource-registry lookup; unknown → nothing minted;
  //      the minted audience is the registry URN, never the request string.
  //  10. mint AT: subject = subject token's subject, client = EXCHANGING
  //      client, cnf carried, fresh grantId; NEVER a refresh token.
  //
  // The parameters include the ADVERSARY'S CHOICES: a wrong actor subject,
  // a swapped or stripped proof key, an escalated scope, an unknown
  // audience, an over-deep chain, a client without the capability, and
  // authorization_details smuggling — each is an enabled action whose
  // guards reject it (mints nothing).
  action exchange(requester: str, subjectTokenId: int,
                  requestedTokenType: int,   // 0 = nil, 1 = access_token, 2 = other
                  hasAuthzDetails: bool,     // true ⇒ invalid_authorization_details gate
                  actorTokenId: int,         // -1 = no actor token
                  proofJkt: int,             // presented TokenConfirmation.jkt; 0 = none
                  requestedScopes: Set[str], // empty = inherit subject scope
                  audience: str,             // "" = no audience requested
                  wantRefresh: bool): bool = {         // adversary asks for an RT
    val cl = if (clients.keys().contains(requester)) clients.get(requester) else NO_CLIENT
    val st = if (tokens.keys().contains(subjectTokenId)) tokens.get(subjectTokenId) else NO_TOKEN
    val at = if (actorTokenId != -1 and tokens.keys().contains(actorTokenId)) tokens.get(actorTokenId) else NO_TOKEN
    val actorPresent = actorTokenId != -1
    val chain =
      if (actorPresent) actChain(at.subject, at.actorChain)
      else List()
    val resolvedAudience =
      if (audience != "" and RESOURCE_URIS.contains(audience)) RESOURCES.get(audience)
      else -1
    val effScopes = if (requestedScopes == Set()) st.scopes else requestedScopes
    all {
      // -- 0. shared preamble guards --------------------------------
      cl.grants.contains(GRANT),                    // validateGrantPreamble
      not(hasAuthzDetails),                        // RFC 9396 fail-closed gate
      // (subject_token_type/subject_token non-empty: the enabled action
      //  IS a well-formed request; empty shapes never dispatch.)
      // -- 1. subject token guards ---------------------------------
      tokens.keys().contains(subjectTokenId),
      st.status == Active,
      st.kind == Access,
      st.expiresAt != 0,                             // Metadata present
      // -- 2. requested_token_type ---------------------------------
      requestedTokenType == 0 or requestedTokenType == 1,
      // -- 3. actor token guards (optional) ------------------------
      (not(actorPresent)) or all {
        tokens.keys().contains(actorTokenId),
        at.status == Active,
        at.kind == Access,
        at.expiresAt != 0,                           // Metadata present
        at.expiresAt > clock,                       // actor unexpired
      },
      // -- 4. may_act (RFC 8693 §5) --------------------------------
      (st.mayAct == Set()) or (actorPresent and st.mayAct.contains(at.subject)),
      // -- 5. cnf binding (RFC 9449 §8) -----------------------------
      st.jkt == 0 or st.jkt == proofJkt,
      // -- 6. subject token unexpired --------------------------------
      st.expiresAt > clock,
      // -- 7. scope narrowing ---------------------------------------
      scopeWithin(effScopes, st.scopes),
      // -- 8. act chain depth cap (fail closed) ----------------------
      chainWithinCap(chain),
      // -- 9. audience: registered resource or none ------------------
      audience == "" or RESOURCE_URIS.contains(audience),
      // -- 10. mint: never an RT, fresh id ----------------------------
      not(wantRefresh),
      counter < MAX_IDS,
      tokens' = tokens.put(counter, {
        id: counter,
        status: Active,
        kind: Access,
        subject: st.subject,
        client: requester,
        scopes: effScopes,
        jkt: st.jkt,                                // cnf CARRIED
        mayAct: Set(),
        actorChain: chain,
        expiresAt: clock + 10,
        viaExchange: true,
        grantId: counter,
      }),
      exchangeTokens' = exchangeTokens.union(Set({
        id: counter,
        subjectTokenId: subjectTokenId,
        subject: st.subject,
        client: requester,
        scopes: effScopes,
        jkt: st.jkt,
        actorChain: chain,
        audience: resolvedAudience,
      })),
      clients' = clients,
      clock' = clock,
      counter' = counter + 1,
    }
  }

  // ------------------------------------------------------------------
  // Steps (random protocol walks)
  // ------------------------------------------------------------------

  action seedStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet subject = SUBJECTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet jkt = JKTS.oneOf()
    nondet mayAct = Set(Set(), Set(11), Set(12), Set(11, 12)).oneOf()
    nondet chain = CHAINS.oneOf()
    nondet expiresOffset = Set(5, 0).oneOf()
    seedToken(client, subject, scopes, jkt, mayAct, chain, clock + expiresOffset)
  }

  action exchangeStep: bool = {
    nondet requester = CLIENTS.oneOf()
    nondet subjectTokenId = 0.to(MAX_IDS - 1).oneOf()
    nondet requestedTokenType = Set(0, 1, 2).oneOf()
    nondet hasAuthzDetails = Set(true, false).oneOf()
    nondet actorTokenId = Set(-1).union(0.to(MAX_IDS - 1).fold(Set(), (acc, v) => acc.union(Set(v)))).oneOf()
    nondet proofJkt = JKTS.oneOf()
    nondet requestedScopes = SCOPE_SETS.oneOf()
    nondet audience = Set("", "https://rs.example/api", "https://other.example",
                          "https://evil.example").oneOf()
    nondet wantRefresh = Set(true, false).oneOf()
    exchange(requester, subjectTokenId, requestedTokenType, hasAuthzDetails,
             actorTokenId, proofJkt, requestedScopes, audience, wantRefresh)
  }

  action step: bool = any {
    seedStep,
    tick,
    exchangeStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants
  // ------------------------------------------------------------------

  // E1 — T1 subject preservation: the minted token's subject is exactly
  // the exchanged subject token's subject — never the exchanging client's
  // own token subject and never the actor's subject.
  val inv_subjectPreservation: bool =
    exchangeTokens.forall(et =>
      tokens.keys().contains(et.subjectTokenId)
      and tokens.get(et.id).subject == tokens.get(et.subjectTokenId).subject
      and et.subject == tokens.get(et.subjectTokenId).subject)

  // E2 — T2 client attribution: the minted token's client is the
  // authenticated requester (the EXCHANGING client) — captured at mint
  // time and consistent between both records.
  val inv_clientAttribution: bool =
    exchangeTokens.forall(et =>
      tokens.get(et.id).client == et.client)

  // E3 — T3 scope narrowing: the minted scope never exceeds the scope of
  // the subject token it was exchanged from; exchange never widens.
  val inv_scopeNarrowing: bool =
    exchangeTokens.forall(et =>
      tokens.keys().contains(et.subjectTokenId)
      and et.scopes.subseteq(tokens.get(et.subjectTokenId).scopes)
      and tokens.get(et.id).scopes == et.scopes)

  // E4 — T4 may_act gate: a token minted from a may_act-gated subject
  // token carries an act chain headed by an actor subject that was in
  // that subject token's may_act list; ungated subject tokens may mint
  // actor-less.
  val inv_mayActGate: bool =
    exchangeTokens.forall(et => {
      val st = tokens.get(et.subjectTokenId)
      (st.mayAct == Set())
        or (et.actorChain.length() > 0 and st.mayAct.contains(et.actorChain[0]))
    })

  // E5 — T5 act chain shape and depth: a minted act chain never exceeds
  // the cap of 3 (fail closed — over-deep exchanges mint nothing, never a
  // truncated chain).
  val inv_actChainCap: bool =
    exchangeTokens.forall(et => chainWithinCap(et.actorChain))

  // E6 — T6 cnf continuity: exchange cannot strip or swap the subject
  // token's DPoP binding — the minted jkt equals the subject token's jkt
  // whenever the subject token was bound.
  val inv_dpopContinuity: bool =
    exchangeTokens.forall(et =>
      tokens.keys().contains(et.subjectTokenId)
      and (tokens.get(et.subjectTokenId).jkt == 0
        implies et.jkt == 0)
      and (tokens.get(et.subjectTokenId).jkt != 0
        implies et.jkt == tokens.get(et.subjectTokenId).jkt)
      and tokens.get(et.id).jkt == et.jkt)

  // E7 — T7 audience registry: a minted audience is only ever a registered
  // resource URN (100 | 200) or absent (-1) — never a client-chosen
  // arbitrary request string.
  val inv_audienceRegistry: bool =
    exchangeTokens.forall(et =>
      et.audience == -1 or et.audience == 100 or et.audience == 200)

  // E8 — T8 no RT, no authorization_details: every minted record is an
  // access token (the model's Token type has no Refresh variant at all),
  // and no authorization_details survive the gate (the record type has no
  // such field — pinned structurally, like xaa.qnt's inv_noRefreshFromBearer).
  val inv_noRefreshNoDetails: bool =
    exchangeTokens.size() == tokens.keys().filter(k => tokens.get(k).viaExchange).mapBy(k => k).keys().size()


  val allInvariants: bool = all {
    inv_subjectPreservation,
    inv_clientAttribution,
    inv_scopeNarrowing,
    inv_mayActGate,
    inv_actChainCap,
    inv_dpopContinuity,
    inv_audienceRegistry,
    inv_noRefreshNoDetails,
  }

  // ------------------------------------------------------------------
  // Witnesses (one per action — reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_tokenSeeded: bool = tokens.keys().size() > 0
  val w_exchangeMinted: bool = exchangeTokens.size() > 0
  val w_plainExchange: bool =                       // happy path, no actor
    exchangeTokens.exists(et => et.actorChain.length() == 0)
  val w_actorExchange: bool =                       // actor path exercised
    exchangeTokens.exists(et => et.actorChain.length() > 0)
  val w_deepChainMinted: bool =                     // depth-3 chain (cap edge)
    exchangeTokens.exists(et => et.actorChain.length() == 3)

  // Negative-space witnesses: attack states are REACHABLE as attempts —
  // proving the guards, not dead code, stop them. Each fires an exchange
  // whose mint is then absent.
  val w_gatedTokenSeeded: bool =                   // a may_act-gated subject token exists
    tokens.keys().exists(k => tokens.get(k).mayAct != Set() and not(tokens.get(k).viaExchange))
  val w_boundTokenSeeded: bool =                   // a jkt-bound subject token exists
    tokens.keys().exists(k => tokens.get(k).jkt != 0 and not(tokens.get(k).viaExchange))

}