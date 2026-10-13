/**
 * devicecode.qnt — formal model of the solid device authorization grant
 * ( RFC 8628 + RFC 10027, zntr.io/solid, module `devicecode` ).
 *
 * COVERS
 *   - Device authorization endpoint issue: client capability
 *     ( grants ∋ device_code ), PENDING session with fixed expiry
 *     ( 120s ), poll interval 5s, offline_access stripped, details
 *     frozen at issue time, issue-time authorization_details registry
 *     validation ( RFC 9396 — unregistered types fail closed ), audience
 *     frozen at issue time ( RFC 8707 ) ( server/services/device/service.go )
 *   - User approval via user_code: PENDING→VALIDATED (with Subject) is
 *     the only legal transition, PENDING→DENIED terminal; brute-force
 *     throttle on unknown user_codes ( ≥5 failures/subject in a sliding
 *     5-minute window latches access_denied; the latch DECAYS once the
 *     window passes ); expiry does NOT count a failure; the failure
 *     counter resets on successful approval; DENY is deliberately
 *     NOT throttled and NOT expiry-checked
 *   - Token endpoint poll ( server/services/token/grant_device_code.go ):
 *     grant preamble capability ( unauthorized_client ),
 *     authorization_details MUST be empty ( invalid_authorization_details ),
 *     DPoP sender binding by CLIENT REGISTRATION POLICY — a client
 *     registered dpop_bound MUST present a proof jkt ( enforceSenderBinding,
 *     RFC 9449 / RFC 10027 §6.1.12; one-directional, NOT a session-key
 *     equality check ), device_code lookup, client binding, expiry
 *     ( expired_token; live while now ≤ expiresAt ), slow_down
 *     ( interval += 5s, LastPolledAt NOT advanced ) vs
 *     authorization_pending ( LastPolledAt = now ), access_denied on
 *     DENIED, and the ATOMIC one-time consume ( DeleteAndGetByDeviceCode )
 *     that mints a single access token — never a refresh token
 *     ( RFC 10027 §6.1.9/6.1.10 )
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: user_code/device_code values are fresh integers;
 *     DPoP key thumbprints assumed well-formed.
 *   - Wall-clock: time is an abstract integer `clock` advanced by a `tick`
 *     action; 120s TTL / 5s poll interval / 300-unit attempt window live
 *     in the same abstract units.
 *   - Client authentication — modeled as a closed client registry.
 *   - The verification URI browse / user login page behind the approval.
 *   - The TLS-client-certificate branch of enforceSenderBinding
 *     ( x5t#S256, RFC 8705 §3 ) — the dpopBound branch below is the
 *     modeled analog; adding tlsBound would double the client registry.
 *   - Unknown client at ISSUE ( invalid_client ) is conflated with the
 *     capability check ( both disable the issue ).
 *
 * DIVERGENCES ( spec previously stricter than the code — resolved 2026-10
 *   by encoding the code's actual behavior per the DcDrift report ):
 *   - DPoP binding is client-policy at the token endpoint, not a
 *     session-bound key fixed at issue; the session carries no key.
 *   - Expiry boundary: expired iff now > expiresAt ( live at equality ).
 *   - Deny is unthrottled and not expiry-checked ( deliberate, RFC 8628
 *     §5.1 comment in service.go: brute-forcing deny only griefs the
 *     attacker's own code discovery ).
 *   - The brute-force latch decays after the 5-minute sliding window.
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/device/service.go,
 *   server/services/token/grant_device_code.go, or
 *   server/services/token/grants.go ( validateGrantPreamble,
 *   enforceSenderBinding, enforcePollInterval ).
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module devicecode {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12          // exploration bound on minted artifacts
  pure val CLIENTS: Set[str] = Set("c1", "c2", "c3")
  pure val USERS: Set[int] = Set(1, 2) // approver subjects
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set("openid"),
    Set("openid", "offline_access"),   // offline_access must be stripped
    Set("profile"),
  )
  pure val DETAIL_SETS: Set[Set[str]] = Set(
    Set(),                            // the only value the token endpoint accepts
    Set("tx:pay1"),
    Set("tx:pay1", "tx:pay2"),
  )
  pure val AUDIENCES: Set[str] = Set("", "https://api.example/") // "" = none requested
  pure val JKTS: Set[int] = Set(0, 1, 2) // DPoP key thumbprints; 0 = unbound
  pure val TICKS: Set[int] = Set(1, 5, 30, 60, 300) // abstract time deltas
                                         // (300 = the attempt window span)
  pure val DEVICE_TTL: int = 120      // abstract units (RFC 8628: 120s)
  pure val POLL_BASE: int = 5         // RFC 8628: 5s default interval
  pure val THROTTLE_LIMIT: int = 5    // brute-force failures before latch
  pure val ATTEMPT_WINDOW: int = 300  // sliding failure window (5 min)

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // "device_code" | "authorization_code"
    dpopBound: bool,         // registration policy: DPoP-bound access tokens
                             // (RFC 9449 / RFC 10027 §6.1.12) — such a client
                             // MUST present a proof jkt at the token endpoint
  }

  type SessionStatus = Pending | Validated | Denied

  type DeviceSession = {     // device authorization session
    client: str,
    scopes: Set[str],
    details: Set[str],       // authorization_details, frozen at issue
    audience: str,           // RFC 8707 audience, frozen at issue
    status: SessionStatus,
    subject: int,            // approver subject; 0 = unset (PENDING)
    deviceCode: int,
    expiresAt: int,          // abstract clock units
    pollInterval: int,       // seconds; only ever grows by +5
    lastPolledAt: int,       // advanced ONLY on authorization_pending
  }

  type TokenKind = Access | Refresh  // Refresh is never minted (RFC 10027)

  type Token = {
    id: int,                 // jti; token value == id (abstract lookup key)
    kind: TokenKind,
    client: str,
    subject: int,
    deviceCode: int,         // the consumed device session
    grantId: int,            // fresh random16 at mint
    scopes: Set[str],
    details: Set[str],       // == session details (no endpoint narrowing)
    audience: str,           // == session audience (RFC 8707, frozen at issue)
    jkt: int,                // DPoP confirmation carried into the token
  }

  // Per-subject brute-force failure record: a COUNT inside a sliding
  // window that is re-armed on every failure ( user_code_attempts.go:
  // each Fail() stamps expiresAt = now + window; Failures() lazily
  // purges once now > expiresAt ). The latch therefore DECAYS —
  // it is not absorbing.
  type AttemptRecord = {
    count: int,             // failures within the current window
    failExpiresAt: int,     // window deadline; effective count 0 at
                            // clock >= failExpiresAt
  }

  // Ghost ledger keyed by deviceCode: freezes the issue-time contract
  // (client, details, audience) and the approval-time facts (subject,
  // effective failure count), plus the interval history used to prove
  // monotonicity after the session itself has been consumed.
  type Ledger = {
    client: str,
    details: Set[str],
    audience: str,
    subject: int,
    valFailures: int,        // approver's effective failure count at VALIDATE time
    interval: int,           // current poll interval (high water)
    intervalLog: Set[int],   // every interval value ever assigned
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  var clients: str -> Client             // registry (static after init)
  var sessions: int -> DeviceSession     // userCode -> session; map keyed by
                                         // user_code; device_code lookup by scan
  var tokens: int -> Token                // token id -> record
  var ledger: int -> Ledger               // deviceCode -> frozen facts
  var failures: int -> AttemptRecord      // subject -> failure window record
  var clock: int                          // abstract time
  var counter: int                        // fresh id source

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client = { grants: Set(), dpopBound: false }
  pure val NO_SESSION: DeviceSession =
    { client: "", scopes: Set(), details: Set(), audience: "", status: Pending,
      subject: 0, deviceCode: -1, expiresAt: 0, pollInterval: POLL_BASE,
      lastPolledAt: 0 }
  pure val NO_TOKEN: Token =
    { id: -1, kind: Access, client: "", subject: 0, deviceCode: -1,
      grantId: -1, scopes: Set(), details: Set(), audience: "", jkt: 0 }
  pure val NO_LEDGER: Ledger =
    { client: "", details: Set(), audience: "", subject: 0, valFailures: -1,
      interval: POLL_BASE, intervalLog: Set(POLL_BASE) }
  pure val NO_ATTEMPTS: AttemptRecord = { count: 0, failExpiresAt: 0 }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // Reverse lookup: the userCode whose session carries this deviceCode,
  // or -1 when no such session exists (deterministic fold, no nondet).
  pure def userCodeOf(m: int -> DeviceSession, dc: int): int =
    m.keys().fold(-1, (acc, k) => if (m.get(k).deviceCode == dc) k else acc)

  // Effective failure count ( user_code_attempts.go Failures ): 0 once
  // the sliding window has passed — the lazily-purged record counts
  // nothing. A record still inside its window contributes its count.
  pure def effFailures(rec: AttemptRecord, now: int): int =
    if (now >= rec.failExpiresAt) 0 else rec.count

  pure def mkToken(id: int, client: str, subject: int, deviceCode: int,
                   grantId: int, scopes: Set[str], details: Set[str],
                   audience: str, jkt: int): Token =
    { id: id, kind: Access, client: client, subject: subject,
      deviceCode: deviceCode, grantId: grantId, scopes: scopes,
      details: details, audience: audience, jkt: jkt }

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      "c1" -> { grants: Set("device_code", "authorization_code"), dpopBound: false },
      "c2" -> { grants: Set("device_code"), dpopBound: true },  // DPoP-bound policy
      "c3" -> { grants: Set("authorization_code"), dpopBound: false },  // no device_code
    ),
    sessions' = Map(),
    tokens' = Map(),
    ledger' = Map(),
    failures' = Map(),
    clock' = 1,                           // > 0 so 0 can mean "never polled"
    counter' = 0,
  }

  // Device authorization endpoint (service.Authorize): capability check
  // (unsupported_grant_type), RFC 9396 issue-time registry validation of
  // authorization_details (unregistered types fail closed,
  // invalid_authorization_details — no session), fresh user_code
  // (2*counter) and device_code (2*counter+1), PENDING session with fixed
  // expiry, poll interval 5, offline_access STRIPPED from scopes, details
  // and audience frozen as requested.
  action issueDeviceAuth(client: str, scopes: Set[str], details: Set[str],
                         audience: str, detailsRegistered: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effScopes = scopes.exclude(Set("offline_access"))
    all {
      cl.grants.contains("device_code"),
      details == Set() or detailsRegistered,   // registry gate (RFC 9396)
      counter < MAX_IDS,
      sessions' = sessions.put(2 * counter, {
        client: client,
        scopes: effScopes,
        details: details,
        audience: audience,
        status: Pending,
        subject: 0,
        deviceCode: 2 * counter + 1,
        expiresAt: clock + DEVICE_TTL,
        pollInterval: POLL_BASE,
        lastPolledAt: 0,
      }),
      ledger' = ledger.put(2 * counter + 1, {
        client: client,
        details: details,
        audience: audience,
        subject: 0,
        valFailures: -1,
        interval: POLL_BASE,
        intervalLog: Set(POLL_BASE),
      }),
      clients' = clients,
      tokens' = tokens,
      failures' = failures,
      clock' = clock,
      counter' = counter + 1,
    }
  }

  // User approval via user_code (device/service.go Approve):
  //   - throttle first: a subject with ≥5 in-window failures is latched
  //     out (access_denied for ALL further attempts)
  //   - expiry does NOT count a failure and blocks the transition
  //     ( live while clock ≤ expiresAt — expired iff clock > expiresAt )
  //   - PENDING→VALIDATED (Subject set) is the ONLY legal transition
  //   - the failure counter resets on a successful approval
  action attemptUserApprove(userCode: int, subject: int): bool = {
    val rec = if (failures.keys().contains(subject)) failures.get(subject) else NO_ATTEMPTS
    val fc = effFailures(rec, clock)
    val s = if (sessions.keys().contains(userCode)) sessions.get(userCode) else NO_SESSION
    val led = if (ledger.keys().contains(s.deviceCode)) ledger.get(s.deviceCode) else NO_LEDGER
    all {
      sessions.keys().contains(userCode),
      ledger.keys().contains(s.deviceCode),
      clock <= s.expiresAt,             // expired: no failure counted, no transition
      s.status == Pending,              // only legal transition source
      fc < THROTTLE_LIMIT,              // brute-force latch (within window)
      clients' = clients,
      tokens' = tokens,
      clock' = clock,
      counter' = counter,
      failures' =
        failures.keys().filter(k => k != subject).mapBy(k => failures.get(k)),
      sessions' = sessions.put(userCode, { ...s, status: Validated, subject: subject }),
      ledger' = ledger.put(s.deviceCode, { ...led, subject: subject, valFailures: fc }),
    }
  }

  // User denial via user_code (device/service.go Deny): PENDING→DENIED
  // only. Deliberately NOT throttled and NOT expiry-checked — the code
  // comment (service.go:348) states brute-forcing deny only griefs the
  // attacker's own code discovery (RFC 8628 §5.1); an expired PENDING
  // session can still be denied and a latched subject can still deny.
  // Deny records NO failure side effect.
  action attemptUserDeny(userCode: int): bool = {
    val s = if (sessions.keys().contains(userCode)) sessions.get(userCode) else NO_SESSION
    all {
      sessions.keys().contains(userCode),
      s.status == Pending,              // only legal transition source
      clients' = clients,
      tokens' = tokens,
      ledger' = ledger,
      failures' = failures,
      clock' = clock,
      counter' = counter,
      sessions' = sessions.put(userCode, { ...s, status: Denied }),
    }
  }

  // Brute-force attempt on the user_code namespace: an UNKNOWN user_code
  // counts one failure for the subject inside the sliding window — each
  // failure re-arms the window ( failExpiresAt = clock + 300 ), so ≥5
  // in-window failures latch access_denied until the window passes.
  // Guessing a KNOWN code is not this action — it is attemptUserApprove.
  action attemptUserCodeBrute(subject: int, guessedCode: int): bool = {
    val rec = if (failures.keys().contains(subject)) failures.get(subject) else NO_ATTEMPTS
    val fc = effFailures(rec, clock)
    all {
      not(sessions.keys().contains(guessedCode)),
      clients' = clients,
      sessions' = sessions,
      tokens' = tokens,
      ledger' = ledger,
      clock' = clock,
      counter' = counter,
      failures' = failures.put(subject, {
        count: fc + 1,
        failExpiresAt: clock + ATTEMPT_WINDOW,
      }),
    }
  }

  // Token endpoint, device_code grant (grant_device_code.go).
  // FAITHFUL GUARD ORDER:
  //   1. validateGrantPreamble: client grants ∋ device_code
  //      ( unauthorized_client — the ISSUE path is the one that answers
  //      unsupported_grant_type, service.go:124 )
  //   2. authorization_details len == 0 REQUIRED
  //      (invalid_authorization_details) — smuggling is rejected closed
  //   3. enforceSenderBinding ( grants.go:91-94 ) runs BEFORE the session
  //      lookup ( grant_device_code.go:64 precedes :75 ): a client
  //      REGISTERED dpop_bound MUST present a proof jkt
  //      ( invalid_request ). One-directional policy — a NON-bound
  //      client mints an unkeyed token even with no proof at all.
  //   4. lookup by device_code; unknown → invalid_request
  //   5. client match session.client (invalid_request)
  //   6. expiry → expired_token (no state change; live while
  //      clock ≤ expiresAt; expiry never counted as an approval failure)
  //   7. status: PENDING → enforcePollInterval (grants.go):
  //        too fast ⇒ slow_down: interval += 5 persisted,
  //                    LastPolledAt NOT advanced
  //        timely  ⇒ authorization_pending: LastPolledAt = now
  //      DENIED → access_denied (no change)
  //      VALIDATED → ATOMIC consume (DeleteAndGetByDeviceCode):
  //                    session removed; second/concurrent poll finds
  //                    nothing (invalid_grant); exactly one AT minted
  //                    with subject, client, scopes, details, audience
  //                    from the session — NEVER a refresh token
  //                    (RFC 10027 §6.1.9/6.1.10); fresh random16 GrantId;
  //                    the MINTING poll bypasses enforcePollInterval
  //                    (the interval check lives only in the PENDING
  //                    branch, grant_device_code.go:112-123).
  action poll(deviceCode: int, client: str, details: Set[str], proofJkt: int): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val uk = userCodeOf(sessions, deviceCode)
    val known = uk != -1
    val s = if (known) sessions.get(uk) else NO_SESSION
    val led = if (ledger.keys().contains(s.deviceCode)) ledger.get(s.deviceCode) else NO_LEDGER
    // enforceSenderBinding precedes the session lookup in the code.
    val dpopOk = not(cl.dpopBound) or proofJkt != 0
    val clientOk = client == s.client
    val live = known and clock <= s.expiresAt
    val slow = live and s.status == Pending and s.lastPolledAt != 0 and clock < s.lastPolledAt + s.pollInterval
    val pending = live and s.status == Pending and not(slow)
    val mint = live and s.status == Validated and clientOk and dpopOk and s.subject != 0
    all {
      cl.grants.contains("device_code"),
      details == Set(),
      dpopOk,
      known,
      clientOk,
      ledger.keys().contains(s.deviceCode),
      if (mint) counter + 1 <= MAX_IDS else true,
      clients' = clients,
      failures' = failures,
      clock' = clock,
      counter' = if (mint) counter + 1 else counter,
      tokens' =
        if (mint)
          tokens.put(counter, mkToken(counter, s.client, s.subject, s.deviceCode,
                                      counter, s.scopes, s.details, s.audience, proofJkt))
        else
          tokens,
      sessions' =
        if (mint)
          sessions.keys().filter(k => k != uk).mapBy(k => sessions.get(k))
        else if (slow)
          sessions.put(uk, { ...s, pollInterval: s.pollInterval + 5 })
        else if (pending)
          sessions.put(uk, { ...s, lastPolledAt: clock })
        else
          sessions,                        // expired_token | access_denied
      ledger' =
        if (slow)
          ledger.put(s.deviceCode, {
            ...led,
            interval: s.pollInterval + 5,
            intervalLog: led.intervalLog.union(Set(s.pollInterval + 5)),
          })
        else
          ledger,
    }
  }

  // Abstract clock: the only way time passes.
  action tick(d: int): bool = all {
    d > 0,
    clock' = clock + d,
    clients' = clients,
    sessions' = sessions,
    tokens' = tokens,
    ledger' = ledger,
    failures' = failures,
    counter' = counter,
  }

  // ------------------------------------------------------------------
  // Step (random protocol walks)
  // ------------------------------------------------------------------

  action issueStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet details = DETAIL_SETS.oneOf()
    nondet audience = AUDIENCES.oneOf()
    nondet detailsRegistered = Set(true, false).oneOf()
    issueDeviceAuth(client, scopes, details, audience, detailsRegistered)
  }

  action approveStep: bool = {
    nondet userCode = 0.to(2 * MAX_IDS).oneOf()
    nondet subject = USERS.oneOf()
    attemptUserApprove(userCode, subject)
  }

  action denyStep: bool = {
    nondet userCode = 0.to(2 * MAX_IDS).oneOf()
    attemptUserDeny(userCode)
  }

  action bruteStep: bool = {
    nondet subject = USERS.oneOf()
    nondet guessedCode = 0.to(2 * MAX_IDS + 1).oneOf()
    attemptUserCodeBrute(subject, guessedCode)
  }

  action pollStep: bool = {
    nondet deviceCode = 0.to(2 * MAX_IDS).oneOf()
    nondet client = CLIENTS.oneOf()
    nondet details = DETAIL_SETS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    poll(deviceCode, client, details, proofJkt)
  }

  action tickStep: bool = {
    nondet d = TICKS.oneOf()
    tick(d)
  }

  action step: bool = any {
    issueStep,
    approveStep,
    denyStep,
    bruteStep,
    pollStep,
    tickStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants
  // ------------------------------------------------------------------

  val allTokens: Set[Token] = tokens.keys().map(k => tokens.get(k))
  val allSessions: Set[DeviceSession] = sessions.keys().map(k => sessions.get(k))

  // D1 — RFC 8628 §3.5 / RFC 10027: a device session mints at most ONE
  // token ever (atomic consume), and no consumed session lingers in the
  // store, so a replay/concurrent poll can never mint again.
  val inv_deviceSingleUse: bool =
    not (allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id and t1.deviceCode == t2.deviceCode)))
    and allTokens.forall(t =>
      sessions.keys().forall(k => sessions.get(k).deviceCode != t.deviceCode))

  // D2 — RFC 10027 §6.1.9/6.1.10: no refresh token can exist in any
  // reachable state.
  val inv_noRefreshToken: bool =
    allTokens.forall(t => t.kind == Access)

  // D3 — approver binding: a minted token carries exactly the subject
  // fixed at VALIDATE time; tokens only exist for approved sessions.
  val inv_subjectBinding: bool =
    allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and t.subject == ledger.get(t.deviceCode).subject
      and t.subject != 0)

  // D4 — client binding: the token belongs to the session's requesting
  // client; a wrong-client poll mints nothing.
  val inv_clientBinding: bool =
    allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and t.client == ledger.get(t.deviceCode).client)

  // D5 — poll throttle: PollInterval is monotone non-decreasing (only
  // ever issued at 5 and bumped by exactly +5 — the ledger log records
  // every value ever assigned, and none exceeds the current one);
  // LastPolledAt never runs ahead of the clock.
  val inv_pollThrottle: bool =
    allSessions.forall(s =>
      ledger.keys().contains(s.deviceCode)
      and s.pollInterval == ledger.get(s.deviceCode).interval
      and s.pollInterval >= POLL_BASE
      and ledger.get(s.deviceCode).intervalLog.contains(POLL_BASE)
      and ledger.get(s.deviceCode).intervalLog.forall(v => v <= s.pollInterval)
      and s.lastPolledAt <= clock)
    and allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and ledger.get(t.deviceCode).intervalLog.forall(v =>
        v <= ledger.get(t.deviceCode).interval))

  // D6 — details and audience are fixed at device-auth time (RFC 9396
  // §3, RFC 8707): minted details/audience equal the session's
  // issue-time values; no token-endpoint narrowing or widening.
  val inv_detailsFixed: bool =
    allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and t.details == ledger.get(t.deviceCode).details
      and t.audience == ledger.get(t.deviceCode).audience)

  // D7 — brute-force latch (sliding window): the approver behind every
  // minted token had fewer than 5 IN-WINDOW failures at VALIDATE time
  // (a latched subject cannot validate until the window passes).
  val inv_bruteForceLatch: bool =
    allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and ledger.get(t.deviceCode).valFailures < THROTTLE_LIMIT)

  // Session-status hygiene: subjects are set only by VALIDATE.
  val inv_statusHygiene: bool =
    allSessions.forall(s =>
      (s.status == Pending implies s.subject == 0)
      and (s.status == Validated implies s.subject != 0))

  // Window hygiene: a failure record always carries a non-negative count
  // and a non-negative window deadline ( stamped clock + 300 > 0 since
  // the clock starts at 1 ). The effective ( in-window ) count is what
  // the approve guard consults — effFailures zeroes it once the window
  // passes.
  val inv_attemptWindow: bool =
    failures.keys().forall(k =>
      failures.get(k).count >= 0
      and failures.get(k).failExpiresAt >= 0)

  val allInvariants: bool = all {
    inv_deviceSingleUse,
    inv_noRefreshToken,
    inv_subjectBinding,
    inv_clientBinding,
    inv_pollThrottle,
    inv_detailsFixed,
    inv_bruteForceLatch,
    inv_statusHygiene,
    inv_attemptWindow,
  }

  // ------------------------------------------------------------------
  // Witnesses (reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_deviceIssued: bool = sessions.keys().size() > 0
  val w_validated: bool = allSessions.exists(s => s.status == Validated)
  val w_denied: bool = allSessions.exists(s => s.status == Denied)
  val w_tokenMinted: bool = allTokens.size() > 0
  val w_slowDown: bool = allSessions.exists(s => s.pollInterval > POLL_BASE)
  val w_pendingAdvanced: bool = allSessions.exists(s => s.lastPolledAt > 0)
  val w_bruteCounted: bool = failures.keys().exists(k =>
    effFailures(failures.get(k), clock) > 0)
  val w_throttleLatched: bool = failures.keys().exists(k =>
    effFailures(failures.get(k), clock) >= THROTTLE_LIMIT)
  val w_latchDecayed: bool = failures.keys().exists(k =>
    failures.get(k).count >= THROTTLE_LIMIT
    and effFailures(failures.get(k), clock) == 0)
  val w_expiredObserved: bool = allSessions.exists(s => clock > s.expiresAt)
  val w_offlineStripped: bool = allSessions.exists(s =>
    not(s.scopes.contains("offline_access")))

}
