/**
 * solid.qnt — formal model of the solid authorization-code + refresh-token
 * lifecycle ( zntr.io/solid, module `solid` ).
 *
 * COVERS
 *   - PAR registration and burn-after-read consumption of request_uri
 *     ( server/services/authorization/service.go: Register, Authorize )
 *   - Authorization-code session minting with fresh GrantId, pairwise subject
 *     ( grant_authorization_code.go / authorization.go HTTP layer )
 *   - Code redemption: burn-BEFORE-check ordering, client binding,
 *     redirect_uri binding, abstract PKCE S256, openid-gated minting,
 *     offline_access-gated refresh token ( grant_authorization_code.go:46-205 )
 *   - Refresh grant: unconditional rotation, single-use RT, replay of a
 *     revoked RT revokes the whole GrantId family ( grant_refresh_token.go )
 *   - Token revocation: single token, owner-client only ( revoke.go )
 *   - Pairwise subjects: injective per (sector, user), no cross-client linkage
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: PKCE S256 is an injective abstract function; JWT/DPoP/
 *     JARM signatures, key thumbprints are assumed correct.
 *   - Expiry / wall-clock: code TTL (60s) and RT expiry manifest as
 *     "absent from storage" and are conflated with single-use, as in the code.
 *   - DPoP proof validation & jti replay store (separate mechanism).
 *   - Client authentication ( private_key_jwt / attestation ) — modeled as a
 *     closed client registry.
 *   - The PAR Get+Delete non-atomicity (see README: known finding F1).
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/token/grant_authorization_code.go,
 *   server/services/token/grant_refresh_token.go, or
 *   server/services/authorization/service.go.
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module solid {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12          // exploration bound on minted artifacts
  pure val CLIENTS: Set[str] = Set("c1", "c2")
  pure val USERS: Set[int] = Set(1, 2)
  pure val VERIFIERS: Set[int] = Set(1, 2) // well-formed code_verifiers
  pure val REDIRECTS: Set[str] =
    Set("https://c1.example/cb", "https://c2.example/cb")
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set("openid"),
    Set("openid", "offline_access"),
    Set("openid", "profile"),
    Set("openid", "offline_access", "profile"),
    Set("profile"), // no openid: exercises the mint-nothing path
  )

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // "authorization_code" | "refresh_token"
    redirectUris: Set[str],
    sector: int,             // pairwise sector identifier
  }

  type AuthzRequest = {      // PAR-registered request
    client: str,
    user: int,
    redirect: str,
    challenge: int,          // abstract S256(code_verifier)
    scopes: Set[str],
    jkt: int,                // DPoP key thumbprint bound at PAR (RFC 9449 §5); 0 = unbound
  }

  type CodeSession = {       // authorization code session; map presence = ACTIVE
    client: str,
    user: int,
    subject: int,             // pairwise pseudonym
    redirect: str,
    challenge: int,
    scopes: Set[str],
    grantId: int,
    jkt: int,                 // DPoP key the code is bound to (RFC 9449 §10); 0 = unbound
  }

  type TokenKind = Access | Refresh
  type TokenVia = FromCode | FromRefresh
  type TokenStatus = Active | Revoked

  type Token = {
    id: int,                 // jti; token value == id (abstract lookup key)
    kind: TokenKind,
    via: TokenVia,
    status: TokenStatus,
    client: str,
    user: int,               // model-only annotation for pairwise checks
    subject: int,
    grantId: int,
    scopes: Set[str],
    jkt: int,                 // DPoP confirmation carried into the token; 0 = unbound
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  var clients: str -> Client       // registry (static after init)
  var requests: int -> AuthzRequest // PAR store: request_uri -> request
  var sessions: int -> CodeSession  // code -> session; absent = consumed/expired
  var tokens: int -> Token          // token id -> record
  var replayDetected: Set[int]      // grant families flagged by RT replay
  var counter: int                  // fresh id source (codes, uris, grant ids, jtis)

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client =
    { grants: Set(), redirectUris: Set(), sector: 0 }
  pure val NO_REQUEST: AuthzRequest =
    { client: "", user: 0, redirect: "", challenge: 0, scopes: Set(), jkt: 0 }
  pure val NO_SESSION: CodeSession =
    { client: "", user: 0, subject: 0, redirect: "", challenge: 0, scopes: Set(), grantId: -1, jkt: 0 }
  pure val NO_TOKEN: Token =
    { id: -1, kind: Access, via: FromCode, status: Active, client: "", user: 0, subject: 0, grantId: -1, scopes: Set(), jkt: 0 }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // Abstract S256: injective challenge derivation from a verifier.
  // Only a matching verifier passes the redeem check.
  pure def challengeOf(v: int): int = 10 * v + 1

  // Abstract pairwise pseudonym (sdk/pairwise: keyed blake2b over sector ++ subject).
  // Injective in (sector, user): distinct sectors never collide.
  pure def pairwiseSub(sector: int, user: int): int = 100 * sector + user

  pure def mkToken(id: int, kind: TokenKind, via: TokenVia, client: str,
                   user: int, subject: int, grantId: int, scopes: Set[str], jkt: int): Token =
    { id: id, kind: kind, via: via, status: Active, client: client,
      user: user, subject: subject, grantId: grantId, scopes: scopes, jkt: jkt }

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      "c1" -> { grants: Set("authorization_code", "refresh_token"),
                redirectUris: Set("https://c1.example/cb"), sector: 1 },
      "c2" -> { grants: Set("authorization_code"),
                redirectUris: Set("https://c2.example/cb"), sector: 2 },
    ),
    requests' = Map(),
    sessions' = Map(),
    tokens' = Map(),
    replayDetected' = Set(),
    counter' = 0,
  }

  // PAR endpoint (service.Register): client registers a validated request,
  // gets a single-use request_uri. offline_access is silently stripped
  // unless consent was given (service.go validate).
  action registerPAR(client: str, user: int, verifier: int, redirect: str,
                     scopes: Set[str], consent: bool, jkt: int): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effScopes = if (consent) scopes else scopes.exclude(Set("offline_access"))
    all {
      cl.grants.contains("authorization_code"),
      cl.redirectUris.contains(redirect),
      counter < MAX_IDS,
      requests' = requests.put(counter, {
        client: client,
        user: user,
        redirect: redirect,
        challenge: challengeOf(verifier),
        scopes: effScopes,
        jkt: jkt,
      }),
      sessions' = sessions,
      tokens' = tokens,
      replayDetected' = replayDetected,
      clients' = clients,
      counter' = counter + 1,
    }
  }

  // Authorization endpoint, PAR flavor (service.Authorize): consume the
  // request_uri (burn-after-read) and mint an ACTIVE code session with a
  // fresh GrantId and the pairwise-encoded subject.
  action authorizePAR(uri: int): bool = {
    val req = if (requests.keys().contains(uri)) requests.get(uri) else NO_REQUEST
    val cl = if (clients.keys().contains(req.client)) clients.get(req.client) else NO_CLIENT
    all {
      requests.keys().contains(uri),
      counter < MAX_IDS,
      sessions' = sessions.put(counter, {
        client: req.client,
        user: req.user,
        subject: pairwiseSub(cl.sector, req.user),
        redirect: req.redirect,
        challenge: req.challenge,
        scopes: req.scopes,
        grantId: counter,
        jkt: req.jkt,
      }),
      requests' = requests.keys().filter(u => u != uri).mapBy(u => requests.get(u)),
      tokens' = tokens,
      replayDetected' = replayDetected,
      clients' = clients,
      counter' = counter + 1,
    }
  }

  // Authorization endpoint, direct request-object flavor: same validation,
  // session minted without a stored request_uri.
  action authorizeDirect(client: str, user: int, verifier: int, redirect: str,
                         scopes: Set[str], consent: bool, jkt: int): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effScopes = if (consent) scopes else scopes.exclude(Set("offline_access"))
    all {
      cl.grants.contains("authorization_code"),
      cl.redirectUris.contains(redirect),
      counter < MAX_IDS,
      sessions' = sessions.put(counter, {
        client: client,
        user: user,
        subject: pairwiseSub(cl.sector, user),
        redirect: redirect,
        challenge: challengeOf(verifier),
        scopes: effScopes,
        grantId: counter,
        jkt: jkt,
      }),
      requests' = requests,
      tokens' = tokens,
      replayDetected' = replayDetected,
      clients' = clients,
      counter' = counter + 1,
    }
  }

  // Token endpoint, authorization_code grant (grant_authorization_code.go).
  // FAITHFUL ORDERING: syntactic guards (verifier shape, client grant
  // capability) run BEFORE the burn; then the code is consumed
  // ATOMICALLY and UNCONDITIONALLY (DeleteAndGet, line 86) — client_id,
  // redirect_uri, and PKCE are checked on the already-burned session, so a
  // failed check still spends the code. Minting is gated on ALL checks plus
  // openid ∈ scopes; refresh token additionally on offline_access. The
  // DPoP key binding (RFC 9449 §10) is enforced on the burned session: a
  // bound code redeems only with a proof from the same key.
  action redeem(code: int, client: str, verifier: int, redirect: str, proofJkt: int): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val s = if (sessions.keys().contains(code)) sessions.get(code) else NO_SESSION
    // RFC 9449 §10: a code bound to a DPoP key can only be redeemed with a
    // proof from that same key (grant_authorization_code.go:123-138).
    val dpopOk = s.jkt == 0 or s.jkt == proofJkt
    val checksOk =
      client == s.client
      and redirect == s.redirect
      and cl.redirectUris.contains(redirect)
      and challengeOf(verifier) == s.challenge
      and s.scopes.contains("openid")
      and dpopOk
    val mintRt = s.scopes.contains("offline_access")
    all {
      sessions.keys().contains(code),
      cl.grants.contains("authorization_code"),
      VERIFIERS.contains(verifier),
      REDIRECTS.contains(redirect),
      if (checksOk and mintRt) counter + 2 <= MAX_IDS
      else if (checksOk) counter + 1 <= MAX_IDS
      else true,
      // Burn FIRST (RFC 9700 §4.5 single-use, atomic consume).
      sessions' = sessions.keys().filter(c => c != code).mapBy(c => sessions.get(c)),
      tokens' =
        if (checksOk and mintRt)
          tokens.put(counter, mkToken(counter, Access, FromCode, s.client, s.user, s.subject, s.grantId, s.scopes, proofJkt))
                .put(counter + 1, mkToken(counter + 1, Refresh, FromCode, s.client, s.user, s.subject, s.grantId, s.scopes, proofJkt))
        else if (checksOk)
          tokens.put(counter, mkToken(counter, Access, FromCode, s.client, s.user, s.subject, s.grantId, s.scopes, proofJkt))
        else
          tokens,
      counter' = if (checksOk and mintRt) counter + 2
                else if (checksOk) counter + 1
                else counter,
      requests' = requests,
      replayDetected' = replayDetected,
      clients' = clients,
    }
  }

  // Token endpoint, refresh_token grant (grant_refresh_token.go).
  // Guard order: client refresh capability (validateGrantPreamble) BEFORE
  // lookup. Then: REVOKED status ⇒ replay ⇒ revoke the ENTIRE GrantId family
  // (lines 66-77, fires regardless of token kind, before the ownership
  // check); ACTIVE + Refresh kind + owner client ⇒ mint new AT + RT
  // (via FromRefresh, same family metadata), revoke the presented RT.
  action refresh(rtId: int, client: str): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val t = if (tokens.keys().contains(rtId)) tokens.get(rtId) else NO_TOKEN
    val replay = t.status == Revoked
    val valid = t.status == Active and t.kind == Refresh and t.client == client
    all {
      tokens.keys().contains(rtId),
      cl.grants.contains("refresh_token"),
      if (valid) counter + 2 <= MAX_IDS else true,
      replayDetected' = if (replay) replayDetected.union(Set(t.grantId)) else replayDetected,
      tokens' =
        if (replay)
          tokens.keys().mapBy(k =>
            if (tokens.get(k).grantId == t.grantId)
              { ...tokens.get(k), status: Revoked }
            else
              tokens.get(k))
        else if (valid)
          tokens.put(rtId, { ...t, status: Revoked })
                .put(counter, mkToken(counter, Access, FromRefresh, t.client, t.user, t.subject, t.grantId, t.scopes, t.jkt))
                .put(counter + 1, mkToken(counter + 1, Refresh, FromRefresh, t.client, t.user, t.subject, t.grantId, t.scopes, t.jkt))
        else
          tokens,
      counter' = if (valid) counter + 2 else counter,
      sessions' = sessions,
      requests' = requests,
      clients' = clients,
    }
  }

  // Revocation endpoint (revoke.go): single token, owner client only;
  // unknown tokens are silent no-ops (modeled as a disabled action).
  action revoke(tokenId: int, client: str): bool = {
    val t = if (tokens.keys().contains(tokenId)) tokens.get(tokenId) else NO_TOKEN
    all {
      tokens.keys().contains(tokenId),
      tokens' = if (t.client == client) tokens.put(tokenId, { ...t, status: Revoked }) else tokens,
      sessions' = sessions,
      requests' = requests,
      replayDetected' = replayDetected,
      clients' = clients,
      counter' = counter,
    }
  }

  // ------------------------------------------------------------------
  // Step (random protocol walks)
  // ------------------------------------------------------------------

  // DPoP keys used by honest clients; attacker keys are modeled by the
  // distance between the key a code is bound to and the proof key used.
  pure val JKTS: Set[int] = Set(0, 1, 2) // 0 = no DPoP proof presented

  action parStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet user = USERS.oneOf()
    nondet verifier = VERIFIERS.oneOf()
    nondet redirect = REDIRECTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet consent = Set(true, false).oneOf()
    nondet jkt = JKTS.oneOf()
    registerPAR(client, user, verifier, redirect, scopes, consent, jkt)
  }

  action authorizeStep: bool = any {
    {
      nondet uri = 0.to(MAX_IDS - 1).oneOf()
      authorizePAR(uri)
    },
    {
      nondet client = CLIENTS.oneOf()
      nondet user = USERS.oneOf()
      nondet verifier = VERIFIERS.oneOf()
      nondet redirect = REDIRECTS.oneOf()
      nondet scopes = SCOPE_SETS.oneOf()
      nondet consent = Set(true, false).oneOf()
      nondet jkt = JKTS.oneOf()
      authorizeDirect(client, user, verifier, redirect, scopes, consent, jkt)
    },
  }

  action redeemStep: bool = {
    nondet code = 0.to(MAX_IDS - 1).oneOf()
    nondet client = CLIENTS.oneOf()
    nondet verifier = VERIFIERS.oneOf()
    nondet redirect = REDIRECTS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    redeem(code, client, verifier, redirect, proofJkt)
  }

  action refreshStep: bool = {
    nondet rtId = 0.to(MAX_IDS - 1).oneOf()
    nondet client = CLIENTS.oneOf()
    refresh(rtId, client)
  }

  action revokeStep: bool = {
    nondet tokenId = 0.to(MAX_IDS - 1).oneOf()
    nondet client = CLIENTS.oneOf()
    revoke(tokenId, client)
  }

  action step: bool = any {
    parStep,
    authorizeStep,
    redeemStep,
    refreshStep,
    revokeStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants
  // ------------------------------------------------------------------

  val allTokens: Set[Token] = tokens.keys().map(k => tokens.get(k))

  // I1 — RFC 9700 §4.5: single-use codes; a grant family receives at most
  // one code-minted AT and one code-minted RT.
  val inv_codeSingleUse: bool =
    not (allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id
      and t1.via == FromCode and t2.via == FromCode
      and t1.kind == t2.kind
      and t1.grantId == t2.grantId)))

  // I2 — grant family purity: one client, one subject, one user per GrantId.
  val inv_grantPurity: bool =
    allTokens.forall(t1 => allTokens.forall(t2 =>
      (t1.grantId == t2.grantId) implies
        (t1.client == t2.client and t1.subject == t2.subject and t1.user == t2.user)))

  // I3 — RFC 9700 §4.14.2 rotation: at most one ACTIVE refresh token per
  // grant family in any reachable state.
  val inv_singleActiveRT: bool =
    not (allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id
      and t1.kind == Refresh and t2.kind == Refresh
      and t1.status == Active and t2.status == Active
      and t1.grantId == t2.grantId)))

  // I4 — replay detection (theft response): a grant family flagged by RT
  // replay is fully revoked.
  val inv_replayRevokesFamily: bool =
    replayDetected.forall(g =>
      allTokens.forall(t => (t.grantId == g) implies (t.status == Revoked)))

  // I5 — pairwise pseudonymity: subjects issued to different clients never
  // collide, so tokens cannot be linked across clients.
  val inv_pairwiseNoCrossClientLinkage: bool =
    allTokens.forall(t1 => allTokens.forall(t2 =>
      (t1.client != t2.client) implies (t1.subject != t2.subject)))

  // I6 — pairwise injectivity per client: same subject ⇒ same underlying user.
  val inv_pairwiseSubjectInjective: bool =
    allTokens.forall(t1 => allTokens.forall(t2 =>
      (t1.client == t2.client and t1.subject == t2.subject) implies (t1.user == t2.user)))

  // I7 — RFC 9449 §10 DPoP key continuity: every token of a grant family
  // carries the same key confirmation — the key the code was bound to at
  // authorization time. A proof-key swap at redemption or refresh cannot
  // mint tokens under a different key.
  val inv_dpopKeyContinuity: bool =
    allTokens.forall(t1 => allTokens.forall(t2 =>
      (t1.grantId == t2.grantId) implies (t1.jkt == t2.jkt)))

  val allInvariants: bool = all {
    inv_codeSingleUse,
    inv_grantPurity,
    inv_singleActiveRT,
    inv_replayRevokesFamily,
    inv_pairwiseNoCrossClientLinkage,
    inv_pairwiseSubjectInjective,
    inv_dpopKeyContinuity,
  }

  // ------------------------------------------------------------------
  // Witnesses (one per action — reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_parRegistered: bool = requests.keys().size() > 0
  val w_codeIssued: bool = sessions.keys().size() > 0
  val w_redeemed: bool = allTokens.exists(t => t.via == FromCode and t.kind == Access)
  val w_redeemedWithRT: bool = allTokens.exists(t => t.via == FromCode and t.kind == Refresh)
  val w_dpopBoundGrantMinted: bool = allTokens.exists(t => t.jkt != 0)
  val w_refreshed: bool = allTokens.exists(t => t.via == FromRefresh)
  val w_replayDetected: bool = replayDetected.size() > 0
  val w_revoked: bool = allTokens.exists(t => t.status == Revoked)

}
