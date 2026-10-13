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
 *     resolvability (MANDATORY — the resolved subject is STORED on the
 *     session and the approval device must later confirm that same
 *     subject), requested_expiry honoring, offline_access stripping
 *     (RFC 9700 §4.12.2), optional dpop_jkt session binding (RFC 9449
 *     §10), signed request object §7.1.1 discriminator (no unsigned
 *     parameter alongside the signed object; iss == client_id; aud
 *     contains the issuer)
 *     ( server/services/backchannel/service.go )
 *   - Approval state machine: PENDING → VALIDATED is the only legal
 *     forward edge (expiry checked — LENIENT at equality; the
 *     confirming subject MUST equal the hint-resolved session subject:
 *     an approver substitution is rejected); PENDING → DENIED is
 *     terminal and checks nothing beyond the transition (service.go
 *     Deny never reads the clock or the subject). The auth_req_id stays
 *     pollable in both cases (the post-Validate storage Delete is a
 *     no-op in the in-memory backend).
 *   - Token poll guard chain in Go order: ciba capability
 *     (validateGrantPreamble), no authorization_details on the token
 *     request (fail closed), sender-constrained policy
 *     (enforceSenderBinding, ONE-SIDED as enforced: a DPoP-bound client
 *     MUST present a jkt; a TLS-bound client MUST present an x5t#S256;
 *     an unbound client presenting a proof anyway is accepted and the
 *     confirmation carried verbatim), auth_req_id lookup (CIBA-strict:
 *     unknown ⇒ invalid_grant), client binding, DPoP jkt SecureCompare
 *     binding, expiry (only expiresAt < now is rejected — a poll at
 *     now == expiresAt still succeeds), then status dispatch:
 *     Pending → enforcePollInterval (the FIRST poll of a fresh session
 *     is ALWAYS admissible — Go's zero-value LastPolledAt sentinel;
 *     slow_down: Interval += 5 persisted, LastPolledAt unchanged;
 *     admissible: LastPolledAt = now, authorization_pending), Denied →
 *     access_denied, Validated → atomic single-use consume
 *     (DeleteAndGetByAuthReqID) THEN audience registry validation
 *     (RFC 8707 §2: an unregistered audience burns the already-consumed
 *     session with invalid_target and mints NOTHING; the replay is then
 *     indistinguishable from unknown ⇒ invalid_grant) and mint
 *     ( server/services/token/grant_ciba.go, grants.go )
 *   - Minting: AT ONLY (never an RT — RFC 9700 §4.12.2), offline_access
 *     stripped, Audience = session audience (registry-validated), fresh
 *     GrantId, presented confirmations (jkt / x5t#S256) carried into the
 *     minted token, authorization_details fixed at bc-authorize
 *   - Adversarial invariants B1–B10 ( integration/ciba_adversarial_test.go )
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: JWT/request-object signatures, alg allowlists (EC-only),
 *     JWKS lookup, DPoP proof verification and jti replay are assumed
 *     correct; the signed request object is a signed/unsigned discriminator
 *     plus the iss==client_id and aud-contains-issuer bindings, not a
 *     signature check; the exp/iat/nbf/jti claim windows are abstracted
 *     away as assumed correct.
 *   - Wall-clock granularity: abstract int clock advanced by a nondet `tick`.
 *   - Client authentication — modeled as a closed client registry.
 *   - Refresh tokens: RFC 9700 §4.12.2 forbids them in CIBA; the module has
 *     no refresh machinery at all, so "no RT ever" is structural (B2).
 *   - Token lifetimes: the minted AT 1h TTL / NotBefore+1s (generator.go)
 *     has no token-expiry domain here.
 *
 * KNOWN SPEC/CODE DIVERGENCES (flagged 2026-10-13, spec-as-documented —
 * the code as implemented is what the model encodes; hardening any of
 * these would be a code change, not a model change):
 *   - Expiry is LENIENT at the boundary: the code rejects only
 *     `ExpiresAt < now` (grant_ciba.go:130, service.go:315), so a poll
 *     or an approval at now == expiresAt still succeeds. The previous
 *     spec pin ("expiry is strict, now < expiresAt") no longer matches
 *     the code.
 *   - Deny ignores the session clock entirely (service.go Deny never
 *     reads ExpiresAt): an expired PENDING session can still be denied.
 *   - The audience registry check runs AFTER the atomic consume, so an
 *     unregistered audience burns the session without minting anything.
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
  pure val CLIENTS: Set[str] = Set("c1", "c2", "c3", "c4")
  pure val USERS: Set[int] = Set(1, 2)
  pure val SUBJECTS: Set[int] = Set(1, 2) // subjects confirmable at Validate
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
  // RFC 8707 §2: the session audience is validated against the resource
  // registry at mint time (grant_ciba.go, after the atomic consume);
  // "a2" models an attacker-chosen unregistered indicator.
  pure val RESOURCES: Set[str] = Set("a1")
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
    dpopBound: bool,         // DpopBoundAccessTokens policy (RFC 10027 §6.1.12)
    tlsBound: bool,          // TlsClientCertificateBoundAccessTokens (RFC 8705 §3)
  }

  type CibaStatus = Pending | Validated | Denied

  type CibaSession = {       // keyed by auth_req_id; presence = pollable
    client: str,
    user: int,               // hint-resolved end user (model annotation)
    subject: int,            // hint-resolved subject, stored at bc-authorize;
                             // confirmed equal by the approver at Validate
    scopes: Set[str],        // offline_access already stripped
    details: str,            // authorization_details fixed at bc-authorize
    audience: str,
    status: CibaStatus,
    expiresAt: int,          // abstract clock units
    pollInterval: int,       // starts at BASE_POLL_INTERVAL, +5 on slow_down
    lastPolledAt: int,       // last admissible poll instant; -1 = never polled
                             // (Go zero-value LastPolledAt sentinel)
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
    x5t: bool,               // TLS certificate confirmation (x5t#S256) carried
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
  pure val NO_CLIENT: Client =
    { grants: Set(), dpopBound: false, tlsBound: false }
  pure val NO_SESSION: CibaSession =
    { client: "", user: 0, subject: 0, scopes: Set(), details: "",
      audience: "", status: Pending, expiresAt: -1, pollInterval: 0,
      lastPolledAt: -1, jkt: 0, signed: false }
  pure val NO_TOKEN: CibaToken =
    { id: -1, authReqId: -1, client: "", subject: 0, grantId: -1,
      scopes: Set(), jkt: 0, x5t: false, audience: "", details: "" }
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
                   grantId: int, scopes: Set[str], jkt: int, x5t: bool,
                   audience: str, details: str): CibaToken =
    { id: id, authReqId: authReqId, client: client, subject: subject,
      grantId: grantId, scopes: scopes, jkt: jkt, x5t: x5t,
      audience: audience, details: details }

  pure def dropSession(sessions: int -> CibaSession, key: int): int -> CibaSession =
    sessions.keys().filter(k => k != key).mapBy(k => sessions.get(k))

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      "c1" -> { grants: Set("ciba", "refresh_token"),
                dpopBound: false, tlsBound: false },
      // DPoP-bound client (RFC 10027 §6.1.12): every poll MUST present a jkt.
      "c2" -> { grants: Set("ciba"), dpopBound: true, tlsBound: false },
      // no ciba: unauthorized_client
      "c3" -> { grants: Set("authorization_code"),
                dpopBound: false, tlsBound: false },
      // TLS-bound client (RFC 8705 §3): every poll MUST present an x5t#S256.
      "c4" -> { grants: Set("ciba"), dpopBound: false, tlsBound: true },
    ),
    sessions' = Map(),
    tokens' = Map(),
    mintedFrom' = Map(),
    counter' = 0,
    now' = 0,
  }

  // bc-authorize (backchannel/service.go Authorize). FAITHFUL GUARD SET,
  // order as in the code: client registered + ciba grant type
  // (unauthorized_client); signed request object (§7.1.1) — when present,
  // no authentication parameter may appear outside it, and (with the
  // signature/alg/JWKS/claim-window verification assumed correct) iss
  // MUST equal client_id and aud MUST contain the issuer; EXACTLY ONE
  // hint among login_hint / login_hint_token / id_token_hint
  // (invalid_request) — modeled as hintCount; binding_message REQUIRED
  // and matching ^[A-Za-z0-9._-]{4,64}$ (invalid_binding_message, solid
  // anti-phishing promotion) — modeled as bindingMessageOk; openid ∈
  // scope (invalid_scope); authorization_details registry validation,
  // fail closed (invalid_authorization_details) — detailsOk; subject
  // resolvable from the single hint (unknown_user_id) — subjectResolvable.
  // EFFECT: the resolved subject is STORED on the session (service.go:220;
  // the approver must later confirm the same subject), offline_access
  // STRIPPED (RFC 9700 §4.12.2), requested_expiry honored else default,
  // optional dpop_jkt binds the session (RFC 9449 §10); session keyed by
  // a fresh auth_req_id, PENDING, PollInterval = 5, LastPolledAt unset
  // (never-polled sentinel: the first poll is always admissible).
  action bcAuthorize(client: str, user: int, hintCount: int,
                     bindingMessageOk: bool, scopes: Set[str],
                     detailsOk: bool, subjectResolvable: bool,
                     requestedExpiry: int, details: str, audience: str,
                     jkt: int, signed: bool, unsignedParams: bool,
                     issMatches: bool, audMatches: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effScopes = scopes.exclude(Set("offline_access"))
    all {
      cl.grants.contains("ciba"),
      // §7.1.1: signed object carries ALL params; iss must be the client
      // and aud must contain the issuer.
      (not(signed)) or (issMatches and audMatches and not(unsignedParams)),
      hintCount == 1,
      bindingMessageOk,
      scopes.contains("openid"),
      detailsOk,
      subjectResolvable,
      counter < MAX_IDS,
      sessions' = sessions.put(counter, {
        client: client,
        user: user,
        subject: user,          // hint-resolved, stored at bc-authorize
        scopes: effScopes,
        details: details,
        audience: audience,
        status: Pending,
        expiresAt: now + effectiveExpiry(requestedExpiry),
        pollInterval: BASE_POLL_INTERVAL,
        lastPolledAt: -1,        // never polled (Go zero-value sentinel)
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

  // Backchannel approval (service.go Validate / Deny): PENDING →
  // VALIDATED is the ONLY legal forward edge; PENDING → DENIED is
  // terminal. Validate checks the clock (lenient at equality: only
  // expiresAt < now is expired) and requires the confirming subject to
  // equal the hint-resolved session subject (CIBA Core §8/11: an
  // approver substitution would hand the client a token for the wrong
  // user); Deny checks neither — an expired PENDING session can still
  // be denied. The auth_req_id stays pollable in both cases.
  action attemptValidate(authReqId: int, subject: int, approve: bool): bool = {
    val s = if (sessions.keys().contains(authReqId)) sessions.get(authReqId) else NO_SESSION
    all {
      sessions.keys().contains(authReqId),
      s.status == Pending,
      // expiry, Validate side only (service.go Deny never reads ExpiresAt)
      not(approve) or now <= s.expiresAt,
      // subject confirmation (service.go:334): the approving user MUST be
      // the hint-resolved subject; Deny carries no subject check.
      not(approve) or subject == s.subject,
      sessions' = sessions.put(authReqId, {
        client: s.client,
        user: s.user,
        // service.go overwrites Subject with the (guard-equal) req.Subject
        subject: s.subject,
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
  //      fail closed (invalid_authorization_details): carriesDetails
  //      must be false
  //   3. enforceSenderBinding (grants.go, ONE-SIDED as enforced): a
  //      DpopBoundAccessTokens client MUST present a jkt proof and a
  //      TlsClientCertificateBoundAccessTokens client an x5t#S256
  //      (invalid_request) — an unbound client presenting a proof anyway
  //      is ACCEPTED and the confirmation carried verbatim into the
  //      minted token (no converse branch exists in the code)
  //   4. auth_req_id != "" — structural (int key)
  //   5. lookup: unknown auth_req_id ⇒ invalid_grant (CIBA is stricter
  //      than device, where unknown yields a synthetic pending) —
  //      action disabled, no state change, replay indistinguishable
  //      from unknown
  //   6. client == session client (invalid_grant)
  //   7. session DPoP binding: session.jkt != 0 ⇒ presented proofJkt
  //      SecureCompare-equals it (invalid_grant)
  //   8. expiry: only expiresAt < now is rejected (expired_token) —
  //      LENIENT at equality: a poll at now == expiresAt still succeeds
  //      (grant_ciba.go:130)
  //   9. status dispatch: PENDING → enforcePollInterval (the FIRST poll
  //      of a fresh session is ALWAYS admissible — Go's zero-value
  //      LastPolledAt sentinel, modeled as -1; slow_down: Interval += 5
  //      persisted, LastPolledAt unchanged; admissible: LastPolledAt =
  //      now, authorization_pending — session STAYS); DENIED →
  //      access_denied (session stays, nothing minted); VALIDATED →
  //      ATOMIC consume (DeleteAndGetByAuthReqID) THEN the RFC 8707 §2
  //      audience registry check: an unregistered session audience burns
  //      the already-consumed session with invalid_target and mints
  //      NOTHING (a replay then answers invalid_grant, unknown).
  // Minting: AT ONLY (never RT, §4.12.2), offline already stripped,
  // Audience = session audience (registry-validated), fresh GrantId,
  // Details = session details (fixed at bc-authorize), confirmations =
  // presented proof (jkt == session key when the session is bound).
  action poll(authReqId: int, client: str, proofJkt: int, proofX5t: bool,
              carriesDetails: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val s = if (sessions.keys().contains(authReqId)) sessions.get(authReqId) else NO_SESSION
    // RFC 9449 §10: a session bound to a DPoP key polls only with a proof
    // from that same key (grant_ciba.go session binding check).
    val dpopOk = s.jkt == 0 or s.jkt == proofJkt
    // enforcePollInterval: has enough time passed since the last
    // admissible poll? A never-polled session (lastPolledAt -1, Go's
    // zero-value LastPolledAt sentinel) is always admissible.
    val admissible = s.lastPolledAt < 0 or now - s.lastPolledAt >= s.pollInterval
    val minting = s.status == Validated
    // RFC 8707 §2: the session audience must resolve against the resource
    // registry before it reaches the minted token (grant_ciba.go, AFTER
    // the atomic consume — an unknown audience burns the session).
    val mintable = RESOURCES.contains(s.audience)
    all {
      // 1. ciba capability                        (unauthorized_client)
      cl.grants.contains("ciba"),
      // 2. no authorization_details on the poll (invalid_authorization_details)
      not(carriesDetails),
      // 3. sender binding, one-sided as enforced   (invalid_request)
      not(cl.dpopBound and proofJkt == 0),
      not(cl.tlsBound and not(proofX5t)),
      // 5. known auth_req_id                      (invalid_grant)
      sessions.keys().contains(authReqId),
      // 6. client binding                         (invalid_grant)
      client == s.client,
      // 7. DPoP session binding                   (invalid_grant)
      dpopOk,
      // 8. expiry, lenient at equality            (expired_token)
      now <= s.expiresAt,
      if (minting and mintable) counter < MAX_IDS else true,
      // 9. status dispatch + atomic consume (a VALIDATED session is
      //    consumed even when the audience turns out unregistered)
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
        if (minting and mintable)
          tokens.put(counter, mkToken(counter, authReqId, s.client, s.subject,
                                      counter, s.scopes, proofJkt, proofX5t,
                                      s.audience, s.details))
        else
          tokens,
      mintedFrom' =
        if (minting and mintable) mintedFrom.put(authReqId, { sess: s, at: now })
        else mintedFrom,
      counter' = if (minting and mintable) counter + 1 else counter,
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
    nondet audMatches = Set(true, false).oneOf()
    bcAuthorize(client, user, hintCount, bindingMessageOk, scopes, detailsOk,
                subjectResolvable, requestedExpiry, details, audience, jkt,
                signed, unsignedParams, issMatches, audMatches)
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
    nondet proofX5t = Set(true, false).oneOf()
    nondet carriesDetails = Set(true, false).oneOf()
    poll(authReqId, client, proofJkt, proofX5t, carriesDetails)
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
  // Safety invariants (B1–B10, integration/ciba_adversarial_test.go)
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

  // B3 — subject binding: the minted subject is the hint-resolved subject
  // (stored at bc-authorize, confirmed equal by the approving user at
  // Validate — service.go:330-338 rejects a substitution), never 0, and
  // tokens mint only from VALIDATED sessions.
  val inv_subjectBound: bool =
    allTokens.forall(t =>
      mintedFrom.keys().contains(t.authReqId)
      and t.subject != 0
      and mintedFrom.get(t.authReqId).sess.status == Validated
      and t.subject == mintedFrom.get(t.authReqId).sess.subject
      and t.subject == mintedFrom.get(t.authReqId).sess.user)

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
  // ever grows by +5 (slow_down); LastPolledAt is either the never-polled
  // sentinel -1 (Go's zero-value LastPolledAt: the first poll of a fresh
  // session is always admissible) or a poll instant never ahead of the
  // clock. Monotonicity itself is transition-local (only two writes
  // exist: +5 on slow_down, unchanged otherwise) and is exercised
  // deterministically in ciba_test.qnt.
  val inv_pollThrottle: bool =
    allSessions.forall(s =>
      s.pollInterval >= BASE_POLL_INTERVAL
      and (s.pollInterval - BASE_POLL_INTERVAL) % SLOW_DOWN_INCREMENT == 0
      and s.lastPolledAt <= now)

  // B8 — session lifetime: no token minted from an expired, pending, or
  // denied session (the guard chain makes this structural; recorded in
  // the ghost audit at mint time). Expiry is lenient at equality: a mint
  // at now == expiresAt is admissible (grant_ciba.go:130).
  val inv_mintPreconditions: bool =
    mintedFrom.keys().forall(k =>
      mintedFrom.get(k).sess.status == Validated
      and mintedFrom.get(k).at <= mintedFrom.get(k).sess.expiresAt)

  // B9 — RFC 8707 §2 audience authority: the minted audience is a
  // registry-resolved session audience — an unregistered
  // (attacker-chosen at bc-authorize) value never lands in aud; it burns
  // the consumed session with invalid_target instead.
  val inv_registeredAudience: bool =
    allTokens.forall(t => RESOURCES.contains(t.audience))

  // B10 — sender-constrained policy (grants.go enforceSenderBinding,
  // ONE-SIDED as enforced): a DPoP-bound client's minted tokens always
  // carry a presented jkt; a TLS-bound client's minted tokens always
  // carry an x5t#S256. No converse is enforced — an unbound client MAY
  // present a proof, which is then carried verbatim.
  val inv_senderBinding: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      (not(cl.dpopBound) or t.jkt != 0)
    })
  val inv_senderBindingTls: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      (not(cl.tlsBound) or t.x5t)
    })

  val allInvariants: bool = all {
    inv_singleUsePerSession,
    inv_noOfflineEver,
    inv_subjectBound,
    inv_clientBound,
    inv_dpopContinuity,
    inv_detailsFixed,
    inv_pollThrottle,
    inv_mintPreconditions,
    inv_registeredAudience,
    inv_senderBinding,
    inv_senderBindingTls,
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
  val w_dpopBoundClientMinted: bool =
    allTokens.exists(t => t.client == "c2")
  val w_tlsBoundClientMinted: bool =
    allTokens.exists(t => t.client == "c4")
  val w_unregisteredAudienceSession: bool =
    allSessions.exists(s => not(RESOURCES.contains(s.audience)))
  val w_expiredSessionPending: bool =
    allSessions.exists(s => now >= s.expiresAt)
  val w_signedRequestAccepted: bool =
    allSessions.exists(s => s.signed)
    or mintedFrom.keys().exists(k => mintedFrom.get(k).sess.signed)

}
