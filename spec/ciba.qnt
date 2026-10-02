/**
 * ciba.qnt — formal model of the CIBA flow (OpenID Client-Initiated
 * Backchannel Authentication Core 1.0 + RFC 9700 §4.12) of zntr.io/solid,
 * module `ciba`.
 *
 * COVERS
 *   - bc-authorize: hint cardinality (exactly one of login_hint /
 *     login_hint_token / id_token_hint), REQUIRED binding_message
 *     (solid promotion, anti-phishing interlock), openid-gated scope,
 *     fail-closed authorization_details registry validation, subject
 *     resolvability, requested_expiry honoring, offline_access stripping
 *     (RFC 9700 §4.12.2), optional dpop_jkt session binding (RFC 9449 §10),
 *     signed request object §7.1.1 discriminator (no unsigned parameter
 *     alongside the signed object; iss == client_id)
 *     ( server/services/backchannel/service.go )
 *   - Approval state machine: PENDING → VALIDATED (subject set) is the only
 *     legal forward edge; PENDING → DENIED is terminal; both consume the
 *     user-facing hint while auth_req_id stays pollable
 *   - Token poll guard chain in Go order: ciba capability
 *     (validateGrantPreamble), no authorization_details on the token request
 *     (fail closed), auth_req_id lookup (CIBA-strict: unknown ⇒
 *     invalid_grant), client binding, DPoP jkt SecureCompare binding,
 *     expiry, then status dispatch: Pending → enforcePollInterval
 *     (slow_down: Interval += 5 persisted, LastPolledAt unchanged;
 *     admissible: LastPolledAt = now, authorization_pending),
 *     Denied → access_denied, Validated → mint
 *     ( server/services/token/grant_ciba.go )
 *   - Minting: AT ONLY (never an RT — RFC 9700 §4.12.2), offline_access
 *     stripped, Audience = session audience, fresh GrantId, atomic
 *     single-use consume (DeleteAndGetByAuthReqID; replay is
 *     indistinguishable from unknown ⇒ invalid_grant)
 *   - Adversarial invariants B1–B8 ( integration/ciba_adversarial_test.go )
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: JWT/request-object signatures, alg allowlists (EC-only),
 *     JWKS lookup, DPoP proof verification and jti replay are assumed
 *     correct; the signed request object is a signed/unsigned discriminator
 *     plus the iss==client_id binding, not a signature check.
 *   - Wall-clock granularity: abstract int clock advanced by a nondet `tick`.
 *   - Client authentication — modeled as a closed client registry.
 *   - Refresh tokens: RFC 9700 §4.12.2 forbids them in CIBA; the module has
 *     no refresh machinery at all, so "no RT ever" is structural (B2).
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/backchannel/service.go,
 *   or server/services/token/grant_ciba.go.
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module ciba {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12          // exploration bound on minted artifacts
  pure val CLIENTS: Set[str] = Set("c1", "c2", "c3")
  pure val USERS: Set[int] = Set(1, 2)
  pure val SUBJECTS: Set[int] = Set(1, 2) // subjects settable at Validate
  pure val HINT_COUNTS: Set[int] = Set(0, 1, 2) // hints present in bc-authorize
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set("openid"),
    Set("openid", "offline_access"),
    Set("openid", "profile"),
    Set("openid", "offline_access", "profile"),
    Set("profile"),          // no openid: rejected at bc-authorize
    Set("offline_access"),   // no openid: rejected at bc-authorize
  )
  pure val DETAIL_SETS: Set[str] = Set("d1", "d2") // registry-valid details
  pure val AUDIENCES: Set[str] = Set("a1", "a2")
  pure val JKTS: Set[int] = Set(0, 1, 2) // 0 = unbound / no proof
  pure val REQUESTED_EXPIRY: Set[int] = Set(0, 4, 8) // 0 → server default
  pure val DEFAULT_EXPIRY: int = 6
  pure val BASE_POLL_INTERVAL: int = 5
  pure val SLOW_DOWN_INCREMENT: int = 5
  pure val MAX_REQUESTED_EXPIRY: int = 3600
  pure val TICKS: Set[int] = Set(1, 2, 3, 4, 5, 6) // abstract clock advances

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // "ciba" | "refresh_token" | "authorization_code"
  }

  type CibaStatus = Pending | Validated | Denied

  type CibaSession = {       // keyed by auth_req_id; presence = pollable
    client: str,
    user: int,               // hint-resolved end user (model annotation)
    subject: int,            // subject set at Validate; 0 = unset
    scopes: Set[str],        // offline_access already stripped
    details: str,            // authorization_details fixed at bc-authorize
    audience: str,
    status: CibaStatus,
    expiresAt: int,          // abstract clock units
    pollInterval: int,       // starts at BASE_POLL_INTERVAL, +5 on slow_down
    lastPolledAt: int,
    jkt: int,                // DPoP thumbprint bound at bc-authorize; 0 = unbound
    signed: bool,            // request came via a signed request object (§7.1.1)
  }

  type CibaToken = {         // access token ONLY — no refresh kind exists (B2)
    id: int,                 // jti; token value == id (abstract lookup key)
    authReqId: int,          // model annotation: minting session key (B1)
    client: str,
    subject: int,
    grantId: int,            // fresh per mint
    scopes: Set[str],
    jkt: int,                // DPoP confirmation carried into the token
    audience: str,
    details: str,            // session-consented, fixed at bc-authorize (B6)
  }

  // Ghost audit of the session a token was minted from (model annotation).
  type MintedRecord = {
    sess: CibaSession,       // session snapshot AT MINT TIME (already consumed)
    at: int,                 // clock value at mint
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  var clients: str -> Client            // registry (static after init)
  var sessions: int -> CibaSession      // auth_req_id -> session
  var tokens: int -> CibaToken          // token id -> record
  var mintedFrom: int -> MintedRecord   // auth_req_id -> mint audit (ghost)
  var counter: int                      // fresh id source (auth_req_ids, jtis, grant ids)
  var now: int                          // abstract clock

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client = { grants: Set() }
  pure val NO_SESSION: CibaSession =
    { client: "", user: 0, subject: 0, scopes: Set(), details: "",
      audience: "", status: Pending, expiresAt: -1, pollInterval: 0,
      lastPolledAt: -1, jkt: 0, signed: false }
  pure val NO_TOKEN: CibaToken =
    { id: -1, authReqId: -1, client: "", subject: 0, grantId: -1,
      scopes: Set(), jkt: 0, audience: "", details: "" }
  pure val NO_MINTED: MintedRecord = { sess: NO_SESSION, at: -1 }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // requested_expiry honored when 0 < v <= 3600, else server default 300
  // (service.go). Abstract units.
  pure def effectiveExpiry(requested: int): int =
    if (requested > 0 and requested <= MAX_REQUESTED_EXPIRY) requested
    else DEFAULT_EXPIRY

  pure def mkToken(id: int, authReqId: int, client: str, subject: int,
                   grantId: int, scopes: Set[str], jkt: int,
                   audience: str, details: str): CibaToken =
    { id: id, authReqId: authReqId, client: client, subject: subject,
      grantId: grantId, scopes: scopes, jkt: jkt, audience: audience,
      details: details }

  pure def dropSession(sessions: int -> CibaSession, key: int): int -> CibaSession =
    sessions.keys().filter(k => k != key).mapBy(k => sessions.get(k))

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      "c1" -> { grants: Set("ciba", "refresh_token") },
      "c2" -> { grants: Set("ciba") },
      "c3" -> { grants: Set("authorization_code") }, // no ciba: unauthorized_client
    ),
    sessions' = Map(),
    tokens' = Map(),
    mintedFrom' = Map(),
    counter' = 0,
    now' = 0,
  }

  // bc-authorize (backchannel/service.go). FAITHFUL GUARD SET, order as in
  // the code: client registered + ciba grant type (unauthorized_client);
  // EXACTLY ONE hint among login_hint / login_hint_token / id_token_hint
  // (invalid_request) — modeled as hintCount; binding_message REQUIRED and
  // matching ^[A-Za-z0-9._-]{4,64}$ (invalid_binding_message, solid
  // anti-phishing promotion) — modeled as bindingMessageOk; openid ∈ scope
  // (invalid_scope); authorization_details registry validation, fail closed
  // (invalid_authorization_details) — detailsOk; subject resolvable from the
  // single hint (unknown_user_id) — subjectResolvable. Signed request
  // object (§7.1.1): all params must live inside the signed object (no
  // unsigned param alongside it) and iss == client_id. Crypto (signature,
  // alg allowlist, exp/iat/nbf/jti) abstracted away as assumed correct.
  // EFFECT: offline_access STRIPPED (RFC 9700 §4.12.2), requested_expiry
  // honored else default, optional dpop_jkt binds the session (RFC 9449 §10);
  // session keyed by a fresh auth_req_id, PENDING, PollInterval = 5.
  action bcAuthorize(client: str, user: int, hintCount: int,
                     bindingMessageOk: bool, scopes: Set[str],
                     detailsOk: bool, subjectResolvable: bool,
                     requestedExpiry: int, details: str, audience: str,
                     jkt: int, signed: bool, unsignedParams: bool,
                     issMatches: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effScopes = scopes.exclude(Set("offline_access"))
    all {
      cl.grants.contains("ciba"),
      hintCount == 1,
      bindingMessageOk,
      scopes.contains("openid"),
      detailsOk,
      subjectResolvable,
      // §7.1.1: signed object carries ALL params; iss must be the client.
      (not(signed)) or (issMatches and not(unsignedParams)),
      counter < MAX_IDS,
      sessions' = sessions.put(counter, {
        client: client,
        user: user,
        subject: 0,
        scopes: effScopes,
        details: details,
        audience: audience,
        status: Pending,
        expiresAt: now + effectiveExpiry(requestedExpiry),
        pollInterval: BASE_POLL_INTERVAL,
        lastPolledAt: now,
        jkt: jkt,
        signed: signed,
      }),
      tokens' = tokens,
      mintedFrom' = mintedFrom,
      clients' = clients,
      counter' = counter + 1,
      now' = now,
    }
  }

  // Backchannel approval (service.go Validate / Deny): PENDING → VALIDATED
  // (with the resolved Subject) is the ONLY legal forward edge;
  // PENDING → DENIED is terminal. Both consume the user-facing hint
  // consumption; auth_req_id remains pollable. Expire-aware: an expired
  // session can no longer transition (both endpoints check expiry).
  action attemptValidate(authReqId: int, subject: int, approve: bool): bool = {
    val s = if (sessions.keys().contains(authReqId)) sessions.get(authReqId) else NO_SESSION
    all {
      sessions.keys().contains(authReqId),
      s.status == Pending,
      now < s.expiresAt,
      sessions' = sessions.put(authReqId, {
        client: s.client,
        user: s.user,
        subject: if (approve) subject else 0,
        scopes: s.scopes,
        details: s.details,
        audience: s.audience,
        status: if (approve) Validated else Denied,
        expiresAt: s.expiresAt,
        pollInterval: s.pollInterval,
        lastPolledAt: s.lastPolledAt,
        jkt: s.jkt,
        signed: s.signed,
      }),
      tokens' = tokens,
      mintedFrom' = mintedFrom,
      clients' = clients,
      counter' = counter,
      now' = now,
    }
  }

  // Token endpoint, CIBA poll (grant_ciba.go). FAITHFUL GUARD ORDER:
  //   1. validateGrantPreamble: client ciba capability (unauthorized_client)
  //   2. authorization_details len == 0 REQUIRED on the token request —
  //      fail closed (invalid_request): carriesDetails must be false
  //   3. auth_req_id != "" — structural (int key)
  //   4. lookup: unknown auth_req_id ⇒ invalid_grant (CIBA is stricter
  //      than device, where unknown yields a synthetic pending) — action
  //      disabled, no state change, replay indistinguishable from unknown
  //   5. client == session client (invalid_grant)
  //   6. session DPoP binding: session.jkt != 0 ⇒ presented proofJkt
  //      SecureCompare-equals it (invalid_grant)
  //   7. expiry: now < expiresAt else expired_token
  //   8. status dispatch: PENDING → enforcePollInterval (slow_down:
  //      Interval += 5 persisted, LastPolledAt unchanged; admissible:
  //      LastPolledAt = now, authorization_pending — session STAYS);
  //      DENIED → access_denied (session stays, nothing minted);
  //      VALIDATED → mint + ATOMIC consume (DeleteAndGetByAuthReqID).
  // Minting: AT ONLY (never RT, §4.12.2), offline already stripped,
  // Audience = session audience, fresh GrantId, Details = session details
  // (fixed at bc-authorize), jkt = proof key (== session key when bound).
  action poll(authReqId: int, client: str, proofJkt: int, carriesDetails: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val s = if (sessions.keys().contains(authReqId)) sessions.get(authReqId) else NO_SESSION
    // RFC 9449 §10: a session bound to a DPoP key polls only with a proof
    // from that same key (grant_ciba.go session binding check).
    val dpopOk = s.jkt == 0 or s.jkt == proofJkt
    // enforcePollInterval: has enough time passed since the last
    // admissible poll?
    val admissible = now - s.lastPolledAt >= s.pollInterval
    val minting = s.status == Validated
    all {
      // 1. ciba capability                        (unauthorized_client)
      cl.grants.contains("ciba"),
      // 2. no authorization_details on the poll  (invalid_request)
      not(carriesDetails),
      // 4. known auth_req_id                      (invalid_grant)
      sessions.keys().contains(authReqId),
      // 5. client binding                         (invalid_grant)
      client == s.client,
      // 6. DPoP session binding                   (invalid_grant)
      dpopOk,
      // 7. expiry                                 (expired_token)
      now < s.expiresAt,
      if (minting) counter < MAX_IDS else true,
      // 8. status dispatch + atomic consume
      sessions' =
        if (minting)
          dropSession(sessions, authReqId)
        else if (s.status == Denied)
          sessions
        else if (admissible)
          sessions.put(authReqId, { ...s, lastPolledAt: now })
        else
          sessions.put(authReqId, { ...s, pollInterval: s.pollInterval + SLOW_DOWN_INCREMENT }),
      tokens' =
        if (minting)
          tokens.put(counter, mkToken(counter, authReqId, s.client, s.subject,
                                      counter, s.scopes, proofJkt, s.audience, s.details))
        else
          tokens,
      mintedFrom' =
        if (minting) mintedFrom.put(authReqId, { sess: s, at: now })
        else mintedFrom,
      counter' = if (minting) counter + 1 else counter,
      clients' = clients,
      now' = now,
    }
  }

  // Abstract clock: nondet forward tick. Expiry / poll-interval arithmetic
  // live in the same units.
  action tick(d: int): bool = all {
    d > 0,
    now' = now + d,
    clients' = clients,
    sessions' = sessions,
    tokens' = tokens,
    mintedFrom' = mintedFrom,
    counter' = counter,
  }

  // ------------------------------------------------------------------
  // Step (random protocol walks)
  // ------------------------------------------------------------------

  action authorizeStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet user = USERS.oneOf()
    nondet hintCount = HINT_COUNTS.oneOf()
    nondet bindingMessageOk = Set(true, false).oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet detailsOk = Set(true, false).oneOf()
    nondet subjectResolvable = Set(true, false).oneOf()
    nondet requestedExpiry = REQUESTED_EXPIRY.oneOf()
    nondet details = DETAIL_SETS.oneOf()
    nondet audience = AUDIENCES.oneOf()
    nondet jkt = JKTS.oneOf()
    nondet signed = Set(true, false).oneOf()
    nondet unsignedParams = Set(true, false).oneOf()
    nondet issMatches = Set(true, false).oneOf()
    bcAuthorize(client, user, hintCount, bindingMessageOk, scopes, detailsOk,
                subjectResolvable, requestedExpiry, details, audience, jkt,
                signed, unsignedParams, issMatches)
  }

  action validateStep: bool = {
    nondet authReqId = 0.to(MAX_IDS - 1).oneOf()
    nondet subject = SUBJECTS.oneOf()
    nondet approve = Set(true, false).oneOf()
    attemptValidate(authReqId, subject, approve)
  }

  action pollStep: bool = {
    nondet authReqId = 0.to(MAX_IDS - 1).oneOf()
    nondet client = CLIENTS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    nondet carriesDetails = Set(true, false).oneOf()
    poll(authReqId, client, proofJkt, carriesDetails)
  }

  action tickStep: bool = {
    nondet d = TICKS.oneOf()
    tick(d)
  }

  action step: bool = any {
    authorizeStep,
    validateStep,
    pollStep,
    tickStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants (B1–B8, integration/ciba_adversarial_test.go)
  // ------------------------------------------------------------------

  val allTokens: Set[CibaToken] = tokens.keys().map(k => tokens.get(k))
  val allSessions: Set[CibaSession] = sessions.keys().map(k => sessions.get(k))

  // B1 — single use: a CIBA session mints at most ONE token (atomic
  // consume; replay of a consumed auth_req_id is indistinguishable from
  // unknown ⇒ invalid_grant).
  val inv_singleUsePerSession: bool =
    not (allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id and t1.authReqId == t2.authReqId)))

  // B2 — no refresh token EVER (RFC 9700 §4.12.2: CIBA mints access tokens
  // only; there is no refresh machinery in this module), and offline_access
  // never survives onto a minted token (stripped at bc-authorize).
  val inv_noOfflineEver: bool =
    allTokens.forall(t => not(t.scopes.contains("offline_access")))

  // B3 — subject binding: minted subject == subject set at Validate time
  // (never 0), and tokens mint only from VALIDATED sessions.
  val inv_subjectBound: bool =
    allTokens.forall(t =>
      mintedFrom.keys().contains(t.authReqId)
      and t.subject != 0
      and mintedFrom.get(t.authReqId).sess.status == Validated
      and t.subject == mintedFrom.get(t.authReqId).sess.subject)

  // B4 — client binding: minted token client == session client (a
  // wrong-client poll mints nothing).
  val inv_clientBound: bool =
    allTokens.forall(t =>
      mintedFrom.keys().contains(t.authReqId)
      and t.client == mintedFrom.get(t.authReqId).sess.client)

  // B5 — DPoP continuity: a session bound at bc-authorize with jkt K mints
  // only under a matching proof, and K carries into the minted token.
  val inv_dpopContinuity: bool =
    allTokens.forall(t =>
      mintedFrom.keys().contains(t.authReqId)
      and ((mintedFrom.get(t.authReqId).sess.jkt != 0)
           implies (t.jkt == mintedFrom.get(t.authReqId).sess.jkt)))

  // B6 — details (and scopes / audience) fixed at bc-authorize: the minted
  // token carries exactly the session-consented values.
  val inv_detailsFixed: bool =
    allTokens.forall(t =>
      mintedFrom.keys().contains(t.authReqId)
      and t.details == mintedFrom.get(t.authReqId).sess.details
      and t.scopes == mintedFrom.get(t.authReqId).sess.scopes
      and t.audience == mintedFrom.get(t.authReqId).sess.audience)

  // B7 — poll throttle shape: interval never below the 5s base and only
  // ever grows by +5 (slow_down), LastPolledAt only moves forward in time
  // and never past the clock. Monotonicity itself is transition-local
  // (only two writes exist: +5 on slow_down, unchanged otherwise) and is
  // exercised deterministically in ciba_test.qnt.
  val inv_pollThrottle: bool =
    allSessions.forall(s =>
      s.pollInterval >= BASE_POLL_INTERVAL
      and (s.pollInterval - BASE_POLL_INTERVAL) % SLOW_DOWN_INCREMENT == 0
      and s.lastPolledAt >= 0
      and s.lastPolledAt <= now)

  // B8 — session lifetime: no token minted from an expired, pending, or
  // denied session (the guard chain makes this structural; recorded in the
  // ghost audit at mint time).
  val inv_mintPreconditions: bool =
    mintedFrom.keys().forall(k =>
      mintedFrom.get(k).sess.status == Validated
      and mintedFrom.get(k).at < mintedFrom.get(k).sess.expiresAt)

  val allInvariants: bool = all {
    inv_singleUsePerSession,
    inv_noOfflineEver,
    inv_subjectBound,
    inv_clientBound,
    inv_dpopContinuity,
    inv_detailsFixed,
    inv_pollThrottle,
    inv_mintPreconditions,
  }

  // ------------------------------------------------------------------
  // Witnesses (reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_sessionPending: bool =
    allSessions.exists(s => s.status == Pending)
  val w_sessionValidated: bool =
    allSessions.exists(s => s.status == Validated)
  val w_sessionDenied: bool =
    allSessions.exists(s => s.status == Denied)
  val w_tokenMinted: bool = allTokens.size() > 0
  val w_slowDown: bool =
    allSessions.exists(s => s.pollInterval > BASE_POLL_INTERVAL)
  val w_dpopBoundTokenMinted: bool = allTokens.exists(t => t.jkt != 0)
  val w_expiredSessionPending: bool =
    allSessions.exists(s => now >= s.expiresAt)
  val w_signedRequestAccepted: bool =
    allSessions.exists(s => s.signed)
    or mintedFrom.keys().exists(k => mintedFrom.get(k).sess.signed)

}
