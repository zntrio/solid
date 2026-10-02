/**
 * devicecode.qnt — formal model of the solid device authorization grant
 * ( RFC 8628 + RFC 10027, zntr.io/solid, module `devicecode` ).
 *
 * COVERS
 *   - Device authorization endpoint issue: client capability
 *     ( grants ∋ device_code ), PENDING session with fixed expiry
 *     ( 120s ), poll interval 5s, offline_access stripped, details
 *     frozen at issue time ( server/services/device/service.go )
 *   - User approval via user_code: PENDING→VALIDATED (with Subject) is
 *     the only legal transition, PENDING→DENIED terminal; brute-force
 *     throttle on unknown user_codes ( ≥5 failures/subject/5min window
 *     latches access_denied ); expiry does NOT count a failure; the
 *     failure counter resets on successful approval
 *   - Token endpoint poll ( server/services/token/grant_device_code.go ):
 *     grant preamble capability, authorization_details MUST be empty
 *     ( invalid_authorization_details ), DPoP sender binding (RFC 9449 §10
 *     jkt pattern), device_code lookup, client binding, expiry
 *     ( expired_token ), slow_down ( interval += 5s, LastPolledAt NOT
 *     advanced ) vs authorization_pending ( LastPolledAt = now ),
 *     access_denied on DENIED, and the ATOMIC one-time consume
 *     ( DeleteAndGetByDeviceCode ) that mints a single access token —
 *     never a refresh token ( RFC 10027 §6.1.9/6.1.10 )
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: user_code/device_code values are fresh integers;
 *     DPoP key thumbprints assumed well-formed.
 *   - Wall-clock: time is an abstract integer `clock` advanced by a `tick`
 *     action; 120s TTL / 5s poll interval live in the same abstract units.
 *   - Client authentication — modeled as a closed client registry.
 *   - The verification URI browse / user login page behind the approval.
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/device/service.go,
 *   server/services/token/grant_device_code.go, or
 *   server/services/token/grants.go ( enforcePollInterval ).
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
  pure val JKTS: Set[int] = Set(0, 1, 2) // DPoP key thumbprints; 0 = unbound
  pure val TICKS: Set[int] = Set(1, 5, 30, 60) // abstract time deltas
  pure val DEVICE_TTL: int = 120      // abstract units (RFC 8628: 120s)
  pure val POLL_BASE: int = 5         // RFC 8628: 5s default interval
  pure val THROTTLE_LIMIT: int = 5    // brute-force failures before latch

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // "device_code" | "authorization_code"
  }

  type SessionStatus = Pending | Validated | Denied

  type DeviceSession = {     // device authorization session
    client: str,
    scopes: Set[str],
    details: Set[str],       // authorization_details, frozen at issue
    status: SessionStatus,
    subject: int,            // approver subject; 0 = unset (PENDING)
    deviceCode: int,
    expiresAt: int,          // abstract clock units
    pollInterval: int,       // seconds; only ever grows by +5
    lastPolledAt: int,       // advanced ONLY on authorization_pending
    jkt: int,                // DPoP key bound at issue; 0 = unbound
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
    jkt: int,                // DPoP confirmation carried into the token
  }

  // Ghost ledger keyed by deviceCode: freezes the issue-time contract
  // (client, details) and the approval-time facts (subject, failure count),
  // plus the interval history used to prove monotonicity after the
  // session itself has been consumed.
  type Ledger = {
    client: str,
    details: Set[str],
    subject: int,
    valFailures: int,        // approver's failure count at VALIDATE time
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
  var failures: int -> int                // subject -> unknown-user_code failures
  var clock: int                          // abstract time
  var counter: int                        // fresh id source

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client = { grants: Set() }
  pure val NO_SESSION: DeviceSession =
    { client: "", scopes: Set(), details: Set(), status: Pending, subject: 0,
      deviceCode: -1, expiresAt: 0, pollInterval: POLL_BASE, lastPolledAt: 0, jkt: 0 }
  pure val NO_TOKEN: Token =
    { id: -1, kind: Access, client: "", subject: 0, deviceCode: -1,
      grantId: -1, scopes: Set(), details: Set(), jkt: 0 }
  pure val NO_LEDGER: Ledger =
    { client: "", details: Set(), subject: 0, valFailures: -1,
      interval: POLL_BASE, intervalLog: Set(POLL_BASE) }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // Reverse lookup: the userCode whose session carries this deviceCode,
  // or -1 when no such session exists (deterministic fold, no nondet).
  pure def userCodeOf(m: int -> DeviceSession, dc: int): int =
    m.keys().fold(-1, (acc, k) => if (m.get(k).deviceCode == dc) k else acc)

  pure def mkToken(id: int, client: str, subject: int, deviceCode: int,
                   grantId: int, scopes: Set[str], details: Set[str], jkt: int): Token =
    { id: id, kind: Access, client: client, subject: subject,
      deviceCode: deviceCode, grantId: grantId, scopes: scopes,
      details: details, jkt: jkt }

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      "c1" -> { grants: Set("device_code", "authorization_code") },
      "c2" -> { grants: Set("device_code") },
      "c3" -> { grants: Set("authorization_code") },   // no device_code
    ),
    sessions' = Map(),
    tokens' = Map(),
    ledger' = Map(),
    failures' = Map(),
    clock' = 1,                           // > 0 so 0 can mean "never polled"
    counter' = 0,
  }

  // Device authorization endpoint (service.Issue): capability check
  // (unsupported_grant_type), fresh user_code (2*counter) and device_code
  // (2*counter+1), PENDING session with fixed expiry, poll interval 5,
  // offline_access STRIPPED from scopes, details frozen as requested.
  action issueDeviceAuth(client: str, scopes: Set[str], details: Set[str], jkt: int): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effScopes = scopes.exclude(Set("offline_access"))
    all {
      cl.grants.contains("device_code"),
      counter < MAX_IDS,
      sessions' = sessions.put(2 * counter, {
        client: client,
        scopes: effScopes,
        details: details,
        status: Pending,
        subject: 0,
        deviceCode: 2 * counter + 1,
        expiresAt: clock + DEVICE_TTL,
        pollInterval: POLL_BASE,
        lastPolledAt: 0,
        jkt: jkt,
      }),
      ledger' = ledger.put(2 * counter + 1, {
        client: client,
        details: details,
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
  //   - throttle first: a subject with ≥5 failures is latched out
  //     (access_denied for ALL further attempts)
  //   - expiry does NOT count a failure and blocks the transition
  //   - PENDING→VALIDATED (Subject set) is the ONLY legal transition
  //   - PENDING→DENIED is terminal
  //   - the failure counter resets on a successful approval
  action attemptUserApprove(userCode: int, subject: int, approved: bool): bool = {
    val fc = if (failures.keys().contains(subject)) failures.get(subject) else 0
    val s = if (sessions.keys().contains(userCode)) sessions.get(userCode) else NO_SESSION
    val led = if (ledger.keys().contains(s.deviceCode)) ledger.get(s.deviceCode) else NO_LEDGER
    all {
      sessions.keys().contains(userCode),
      ledger.keys().contains(s.deviceCode),
      clock < s.expiresAt,              // expired: no failure counted, no transition
      s.status == Pending,              // only legal transition source
      fc < THROTTLE_LIMIT,              // brute-force latch
      clients' = clients,
      tokens' = tokens,
      clock' = clock,
      counter' = counter,
      failures' =
        if (approved)
          failures.keys().filter(k => k != subject).mapBy(k => failures.get(k))
        else
          failures,
      sessions' =
        if (approved)
          sessions.put(userCode, { ...s, status: Validated, subject: subject })
        else
          sessions.put(userCode, { ...s, status: Denied }),
      ledger' =
        if (approved)
          ledger.put(s.deviceCode, { ...led, subject: subject, valFailures: fc })
        else
          ledger,
    }
  }

  // Brute-force attempt on the user_code namespace: an UNKNOWN user_code
  // counts one failure for the subject (≥5 latches access_denied).
  // Guessing a KNOWN code is not this action — it is attemptUserApprove.
  action attemptUserCodeBrute(subject: int, guessedCode: int): bool = {
    val fc = if (failures.keys().contains(subject)) failures.get(subject) else 0
    all {
      not(sessions.keys().contains(guessedCode)),
      clients' = clients,
      sessions' = sessions,
      tokens' = tokens,
      ledger' = ledger,
      clock' = clock,
      counter' = counter,
      failures' = failures.put(subject, fc + 1),
    }
  }

  // Token endpoint, device_code grant (grant_device_code.go).
  // FAITHFUL GUARD ORDER:
  //   1. validateGrantPreamble: client grants ∋ device_code
  //      (unsupported_grant_type)
  //   2. authorization_details len == 0 REQUIRED
  //      (invalid_authorization_details) — smuggling is rejected closed
  //   3. enforceSenderBinding: a session bound to DPoP key K polls only
  //      with a proof from K (RFC 9449 §10 analog of solid.qnt)
  //   4. lookup by device_code; unknown → invalid_request
  //   5. client match session.client (invalid_request)
  //   6. expiry → expired_token (no state change; expiry never counted
  //      as an approval failure either)
  //   7. status: PENDING → enforcePollInterval (grants.go):
  //        too fast ⇒ slow_down: interval += 5 persisted,
  //                    LastPolledAt NOT advanced
  //        timely  ⇒ authorization_pending: LastPolledAt = now
  //      DENIED → access_denied (no change)
  //      VALIDATED → ATOMIC consume (DeleteAndGetByDeviceCode):
  //                    session removed; second/concurrent poll finds
  //                    nothing (invalid_grant); exactly one AT minted
  //                    with subject, client, scopes, details from the
  //                    session — NEVER a refresh token (RFC 10027
  //                    §6.1.9/6.1.10); fresh random16 GrantId.
  action poll(deviceCode: int, client: str, details: Set[str], proofJkt: int): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val uk = userCodeOf(sessions, deviceCode)
    val known = uk != -1
    val s = if (known) sessions.get(uk) else NO_SESSION
    val led = if (ledger.keys().contains(s.deviceCode)) ledger.get(s.deviceCode) else NO_LEDGER
    val dpopOk = s.jkt == 0 or s.jkt == proofJkt
    val clientOk = client == s.client
    val live = known and clock < s.expiresAt
    val slow = live and s.status == Pending and s.lastPolledAt != 0 and clock < s.lastPolledAt + s.pollInterval
    val pending = live and s.status == Pending and not(slow)
    val mint = live and s.status == Validated and clientOk and dpopOk and s.subject != 0
    all {
      cl.grants.contains("device_code"),
      details == Set(),
      known,
      clientOk,
      dpopOk,
      ledger.keys().contains(s.deviceCode),
      if (mint) counter + 1 <= MAX_IDS else true,
      clients' = clients,
      failures' = failures,
      clock' = clock,
      counter' = if (mint) counter + 1 else counter,
      tokens' =
        if (mint)
          tokens.put(counter, mkToken(counter, s.client, s.subject, s.deviceCode,
                                      counter, s.scopes, s.details, proofJkt))
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
    nondet jkt = JKTS.oneOf()
    issueDeviceAuth(client, scopes, details, jkt)
  }

  action approveStep: bool = {
    nondet userCode = 0.to(2 * MAX_IDS).oneOf()
    nondet subject = USERS.oneOf()
    nondet approved = Set(true, false).oneOf()
    attemptUserApprove(userCode, subject, approved)
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

  // D6 — details are fixed at device-auth time: minted details equal the
  // session's issue-time details; no token-endpoint narrowing or widening.
  val inv_detailsFixed: bool =
    allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and t.details == ledger.get(t.deviceCode).details)

  // D7 — brute-force latch: the approver behind every minted token had
  // fewer than 5 failures at VALIDATE time (a latched subject can never
  // validate), and the latch itself is absorbing.
  val inv_bruteForceLatch: bool =
    allTokens.forall(t =>
      ledger.keys().contains(t.deviceCode)
      and ledger.get(t.deviceCode).valFailures < THROTTLE_LIMIT)

  // Session-status hygiene: subjects are set only by VALIDATE.
  val inv_statusHygiene: bool =
    allSessions.forall(s =>
      (s.status == Pending implies s.subject == 0)
      and (s.status == Validated implies s.subject != 0))

  val allInvariants: bool = all {
    inv_deviceSingleUse,
    inv_noRefreshToken,
    inv_subjectBinding,
    inv_clientBinding,
    inv_pollThrottle,
    inv_detailsFixed,
    inv_bruteForceLatch,
    inv_statusHygiene,
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
  val w_bruteCounted: bool = failures.keys().exists(k => failures.get(k) > 0)
  val w_throttleLatched: bool = failures.keys().exists(k => failures.get(k) >= THROTTLE_LIMIT)
  val w_expiredObserved: bool = allSessions.exists(s => clock >= s.expiresAt)
  val w_offlineStripped: bool = allSessions.exists(s =>
    not(s.scopes.contains("offline_access")))

}
