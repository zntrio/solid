/**
 * devicecode_test.qnt — deterministic scenario tests for the devicecode model.
 * Run: quint test spec/devicecode_test.qnt --main devicecodeTest
 */

module devicecodeTest {

  import devicecode.* from "./devicecode"

  /** Happy path: issue → approve → poll → single AT, subject == approver,
   *  details and audience frozen at issue. */
  run happyPathTest =
    init
      .then(issueDeviceAuth("c1", Set("openid", "offline_access"), Set("tx:pay1"), "https://api.example/", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).kind == Access,
        tokens.get(1).subject == 1,
        tokens.get(1).client == "c1",
        tokens.get(1).details == Set("tx:pay1"),
        tokens.get(1).audience == "https://api.example/",
        tokens.get(1).grantId == 1,
      })

  /** RFC 10027: offline_access is stripped at issue; the poll mints an AT
   *  with the stripped scopes and NEVER a refresh token. */
  run noRefreshTokenTest =
    init
      .then(issueDeviceAuth("c1", Set("openid", "offline_access"), Set(), "", true))
      .expect(sessions.get(0).scopes == Set("openid"))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).scopes == Set("openid"),
        tokens.get(1).kind == Access,
      })

  /** D1 single-use: the second poll on the consumed session is disabled. */
  run deviceSingleUseTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(tokens.keys().size() == 1)
      .then(poll(1, "c1", Set(), 0).fail())

  /** Poll before approval: authorization_pending; first poll is always
   *  admissible (LastPolledAt 0 = never polled) and advances it to clock. */
  run authorizationPendingTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        sessions.get(0).status == Pending,
        sessions.get(0).lastPolledAt == 1,
        sessions.get(0).pollInterval == 5,
      })

  /** D5 slow_down: a too-fast poll bumps the interval by +5 and does NOT
   *  advance LastPolledAt. */
  run slowDownBumpsIntervalTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(poll(1, "c1", Set(), 0))            // admissible: lastPolledAt = 1
      .then(poll(1, "c1", Set(), 0))            // too fast: slow_down
      .expect(all {
        sessions.get(0).pollInterval == 10,
        sessions.get(0).lastPolledAt == 1,      // NOT advanced on slow_down
        sessions.get(0).status == Pending,
      })
      .then(poll(1, "c1", Set(), 0))            // clock 1 < 1 + 10: slow again
      .expect(sessions.get(0).pollInterval == 15)

  /** Timely pending poll after time passes: LastPolledAt advances to clock. */
  run timelyPendingTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(poll(1, "c1", Set(), 0))            // lastPolledAt = 1, interval 5
      .then(poll(1, "c1", Set(), 0))            // interval 10
      .then(tick(30))                           // clock 31 ≥ 1 + 10
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        sessions.get(0).status == Pending,
        sessions.get(0).lastPolledAt == 31,
        sessions.get(0).pollInterval == 10,
      })

  /** PIN: the MINTING poll bypasses enforcePollInterval — the interval
   *  check exists only in the PENDING branch (grant_device_code.go:112-
   *  123), so once the session is VALIDATED an immediate poll mints
   *  despite clock < lastPolledAt + pollInterval. Issue → poll
   *  (slow_down) → approve → immediate poll MINTS. */
  run mintInsideSlowDownWindowTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(poll(1, "c1", Set(), 0))            // lastPolledAt = 1, interval 5
      .then(poll(1, "c1", Set(), 0))            // too fast: slow_down, interval 10
      .expect(all {
        sessions.get(0).pollInterval == 10,
        sessions.get(0).status == Pending,
      })
      .then(attemptUserApprove(0, 1))           // now VALIDATED...
      .then(poll(1, "c1", Set(), 0))             // clock 1 < 1 + 10 — MINTS anyway
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).subject == 1,
        sessions.keys().size() == 0,             // consumed
      })

  /** Deny → session DENIED → poll returns access_denied, mints nothing. */
  run denyBlocksMintTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserDeny(0))
      .expect(sessions.get(0).status == Denied)
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.get(0).status == Denied,       // unchanged: no mint, no consume
      })

  /** Deny is NOT expiry-checked: an expired PENDING session can still be
   *  denied ( service.go Deny has no expiry guard ). */
  run denyAfterExpiryTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(tick(121))                          // clock 122 > expiresAt 121: expired,
      .then(attemptUserDeny(0))                 // yet deny is still admissible
      .expect(sessions.get(0).status == Denied)

  /** Expiry: approval of an expired session is disabled (blocked by the
   *  expiry guard), and expiry does NOT count a brute-force failure.
   *  A disabled action is atomic: the pre-state it sees is what it leaves.
   *  Boundary: expired iff clock > expiresAt — needs tick(121) past
   *  issue-at-clock-1 (expiresAt 121). */
  run expiryBlocksApproveTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(tick(121))                          // clock 122 > expiresAt 121: expired
      .expect(all {
        tokens.keys().size() == 0,
        sessions.get(0).status == Pending,
        failures.keys().size() == 0,            // expiry counted NO failure
      })
      .then(attemptUserApprove(0, 1).fail())

  /** Boundary pin: at clock == expiresAt the session is STILL LIVE —
   *  the code checks session.ExpiresAt < now (service.go:283), so at
   *  equality approval is admissible and a poll mints. */
  run expiryBoundaryLiveTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(tick(120))                          // clock 121 == expiresAt 121: LIVE
      .then(attemptUserApprove(0, 1))
      .expect(sessions.get(0).status == Validated)
      .then(poll(1, "c1", Set(), 0))
      .expect(tokens.keys().size() == 1)

  /** Expiry: polling an expired VALIDATED session is a no-op error step
   *  (expired_token): enabled, mints nothing, consumes nothing.
   *  Boundary: expired iff clock > expiresAt. */
  run expiryPollIsNoopTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(tick(121))                          // clock 122 > expiresAt 121: expired
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 0,              // expired_token: no mint
        sessions.keys().size() == 1,            // session not consumed
        sessions.get(0).status == Validated,
      })

  /** Boundary pin: at clock == expiresAt a poll on a VALIDATED session
   *  still MINTS (live at equality). */
  run expiryBoundaryPollMintsTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(tick(120))                          // clock 121 == expiresAt 121: LIVE
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        sessions.keys().size() == 0,
      })

  /** D4 wrong client: a poll by a different client is disabled; being
   *  disabled it consumes nothing (atomic disabled action). */
  run wrongClientPollTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .expect(all {
        sessions.get(0).status == Validated,
        tokens.keys().size() == 0,
      })
      .then(poll(1, "c2", Set(), 1).fail())     // proof passes binding; client match fails

  /** Unknown device_code: no session matches, poll disabled (invalid_request). */
  run unknownDeviceCodeTest =
    init
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0,
      })
      .then(poll(99, "c1", Set(), 0).fail())

  /** Client without device_code capability: issue is disabled
   *  (unsupported_grant_type); its poll is disabled too
   *  (unauthorized_client at the token endpoint). */
  run capabilityIssueTest =
    init
      .then(issueDeviceAuth("c3", Set("openid"), Set(), "", true).fail())

  run capabilityPollTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .expect(all {
        sessions.get(0).status == Validated,
        tokens.keys().size() == 0,
      })
      .then(poll(1, "c3", Set(), 0).fail())

  /** RFC 9396: unregistered authorization_details at ISSUE time fail
   *  closed (invalid_authorization_details) — no session is created. */
  run unregisteredDetailsRejectedTest =
    init
      .expect(all {
        sessions.keys().size() == 0,
        ledger.keys().size() == 0,
      })
      .then(issueDeviceAuth("c1", Set("openid"), Set("tx:pay1"), "", false).fail())

  /** D6 details smuggling: presenting authorization_details at the token
   *  endpoint is rejected closed (invalid_authorization_details). */
  run detailsSmugglingRejectedTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set("tx:pay1"), 0).fail())

  /** The smuggle attempt above consumed nothing: an honest retry on a
   *  freshly-seeded session still mints with the frozen details. */
  run detailsFrozenAtIssueTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set("tx:pay1"), "", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).details == Set("tx:pay1"),  // request-time details
      })

  /** RFC 8707: the audience consented at device-authorization time is the
   *  audience of the minted token; an absent audience stays absent. */
  run audienceFrozenAtIssueTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "https://api.example/", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(tokens.get(1).audience == "https://api.example/")

  run audienceEmptyStaysEmptyTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(tokens.get(1).audience == "")

  /** Sender binding is CLIENT REGISTRATION POLICY ( enforceSenderBinding,
   *  grants.go:91-94 ): c2 is registered dpop_bound, so its poll without a
   *  proof jkt is disabled (invalid_request) — even with the session
   *  already VALIDATED, nothing is consumed. */
  run dpopBoundClientWithoutProofTest =
    init
      .then(issueDeviceAuth("c2", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .expect(all {
        sessions.get(0).status == Validated,
        tokens.keys().size() == 0,
      })
      .then(poll(1, "c2", Set(), 0).fail())     // guard ran pre-lookup: untouched

  /** A dpop_bound client presenting a proof mints with the PRESENTED
   *  confirmation carried into the token (any well-formed jkt works —
   *  the code has no session-key equality to satisfy). */
  run dpopBoundClientWithProofMintsTest =
    init
      .then(issueDeviceAuth("c2", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c2", Set(), 2))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 2,                // presented confirmation carried
        tokens.get(1).client == "c2",
      })

  /** A NON-bound client (c1) mints UNKEYED — sender binding is a
   *  one-directional registration policy, not a session-key equality. */
  run unboundClientMintsUnkeyedTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 0,
      })

  /** D7 brute-force latch: 5 in-window unknown user_code attempts by
   *  subject 1 → even the CORRECT user_code can no longer be approved
   *  (the .fail() proves the guard fc < THROTTLE_LIMIT rejected it). */
  run bruteForceLatchTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .expect(all {
        effFailures(failures.get(1), clock) == 5,
        sessions.get(0).status == Pending,      // untouched by the failures
      })
      .then(attemptUserApprove(0, 1).fail())

  /** A LATCHED subject can still DENY (service.go Deny is deliberately
   *  not throttled). */
  run latchedSubjectCanStillDenyTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .expect(effFailures(failures.get(1), clock) == 5)
      .then(attemptUserDeny(0))
      .expect(sessions.get(0).status == Denied)

  /** F4: the latch DECAYS — 5 failures, then the 300-unit window passes
   *  and the same subject can approve again ( sliding window, not
   *  absorbing ). */
  run latchExpiresTest =
    init
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .expect(effFailures(failures.get(1), clock) == 5)
      .then(tick(300))                         // clock 301: window (1+300) passed
      .expect(effFailures(failures.get(1), clock) == 0)
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserApprove(0, 1))           // same subject approves again
      .expect(sessions.get(0).status == Validated)

  /** 4 failures is still below the limit: approval remains possible and
   *  resets the counter. */
  run bruteForceBelowLimitTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserApprove(0, 1))
      .expect(all {
        sessions.get(0).status == Validated,
        not(failures.keys().contains(1)),
      })

  /** D3 DENIED is terminal: even the legit approver cannot validate, and
   *  no subject is ever set. */
  run deniedIsTerminalTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(attemptUserDeny(0))
      .expect(all {
        sessions.get(0).status == Denied,
        sessions.get(0).subject == 0,          // never validated
      })
      .then(attemptUserApprove(0, 2).fail())
      // (DENIED→DENIED is also illegal; DENIED terminality for deny is
      //  covered by the statemachine — only one trailing .fail() keeps
      //  a defined state)

  /** Two sessions mint exactly two tokens (ids 2,3: issues consume no
   *  counter); each session is single-use. */
  run twoSessionsTwoTokensTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), "", true))
      .then(issueDeviceAuth("c1", Set("profile"), Set("tx:pay2"), "", true))
      .then(attemptUserApprove(0, 1))
      .then(attemptUserApprove(2, 2))
      .then(poll(1, "c1", Set(), 0))
      .then(poll(3, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 2,
        tokens.get(2).subject == 1,
        tokens.get(3).subject == 2,
        tokens.get(3).details == Set("tx:pay2"),
      })
      .then(poll(3, "c1", Set(), 0).fail())

}
