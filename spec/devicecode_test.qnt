/**
 * devicecode_test.qnt — deterministic scenario tests for the devicecode model.
 * Run: quint test spec/devicecode_test.qnt --main devicecodeTest
 */

module devicecodeTest {

  import devicecode.* from "./devicecode"

  /** Happy path: issue → approve → poll → single AT, subject == approver. */
  run happyPathTest =
    init
      .then(issueDeviceAuth("c1", Set("openid", "offline_access"), Set("tx:pay1"), 0))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).kind == Access,
        tokens.get(1).subject == 1,
        tokens.get(1).client == "c1",
        tokens.get(1).details == Set("tx:pay1"),
        tokens.get(1).grantId == 1,
      })

  /** RFC 10027: offline_access is stripped at issue; the poll mints an AT
   *  with the stripped scopes and NEVER a refresh token. */
  run noRefreshTokenTest =
    init
      .then(issueDeviceAuth("c1", Set("openid", "offline_access"), Set(), 0))
      .expect(sessions.get(0).scopes == Set("openid"))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).scopes == Set("openid"),
        tokens.get(1).kind == Access,
      })

  /** D1 single-use: the second poll on the consumed session is disabled. */
  run deviceSingleUseTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set(), 0))
      .expect(tokens.keys().size() == 1)
      .then(poll(1, "c1", Set(), 0).fail())

  /** Poll before approval: authorization_pending; first poll is always
   *  admissible (LastPolledAt 0 = never polled) and advances it to clock. */
  run authorizationPendingTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
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
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
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
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(poll(1, "c1", Set(), 0))            // lastPolledAt = 1, interval 5
      .then(poll(1, "c1", Set(), 0))            // interval 10
      .then(tick(30))                           // clock 31 ≥ 1 + 10
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        sessions.get(0).status == Pending,
        sessions.get(0).lastPolledAt == 31,
        sessions.get(0).pollInterval == 10,
      })


  /** Deny → session DENIED → poll returns access_denied, mints nothing. */
  run denyBlocksMintTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, false))
      .expect(sessions.get(0).status == Denied)
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.get(0).status == Denied,       // unchanged: no mint, no consume
      })

  /** Expiry: approval of an expired session is disabled (blocked by the
   *  expiry guard), and expiry does NOT count a brute-force failure.
   *  A disabled action is atomic: the pre-state it sees is what it leaves. */
  run expiryBlocksApproveTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(tick(120))                          // clock == expiresAt
      .expect(all {
        tokens.keys().size() == 0,
        sessions.get(0).status == Pending,
        failures.keys().size() == 0,            // expiry counted NO failure
      })
      .then(attemptUserApprove(0, 1, true).fail())

  /** Expiry: polling an expired VALIDATED session is a no-op error step
   *  (expired_token): enabled, mints nothing, consumes nothing. */
  run expiryPollIsNoopTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, true))
      .then(tick(120))                          // clock == expiresAt
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 0,              // expired_token: no mint
        sessions.keys().size() == 1,            // session not consumed
        sessions.get(0).status == Validated,
      })

  /** D4 wrong client: a poll by a different client is disabled; being
   *  disabled it consumes nothing (atomic disabled action). */
  run wrongClientPollTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, true))
      .expect(all {
        sessions.get(0).status == Validated,
        tokens.keys().size() == 0,
      })
      .then(poll(1, "c2", Set(), 0).fail())

  /** Unknown device_code: no session matches, poll disabled (invalid_request). */
  run unknownDeviceCodeTest =
    init
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0,
      })
      .then(poll(99, "c1", Set(), 0).fail())

  /** Client without device_code capability: issue is disabled
   *  (unsupported_grant_type); its poll is disabled too. */
  run capabilityIssueTest =
    init
      .then(issueDeviceAuth("c3", Set("openid"), Set(), 0).fail())

  run capabilityPollTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, true))
      .expect(all {
        sessions.get(0).status == Validated,
        tokens.keys().size() == 0,
      })
      .then(poll(1, "c3", Set(), 0).fail())

  /** D6 details smuggling: presenting authorization_details at the token
   *  endpoint is rejected closed (invalid_authorization_details). */
  run detailsSmugglingRejectedTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set("tx:pay1"), 0).fail())

  /** The smuggle attempt above consumed nothing: an honest retry on a
   *  freshly-seeded session still mints with the frozen details. */
  run detailsFrozenAtIssueTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set("tx:pay1"), 0))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set(), 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).details == Set("tx:pay1"),  // request-time details
      })

  /** Sender binding: a session bound to DPoP key 1 rejects a proof from
   *  key 2 (disabled, nothing consumed). */
  run dpopKeySwapRejectedTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 1))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set(), 2).fail())

  /** Sender binding: the bound key itself mints with confirmation carried. */
  run dpopBoundPollOkTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 1))
      .then(attemptUserApprove(0, 1, true))
      .then(poll(1, "c1", Set(), 1))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 1,
      })

  /** D7 brute-force latch: 5 unknown user_code attempts by subject 1 →
   *  even the CORRECT user_code can no longer be approved (the .fail()
   *  proves the guard fc < THROTTLE_LIMIT rejected it). */
  run bruteForceLatchTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .expect(all {
        failures.get(1) == 5,
        sessions.get(0).status == Pending,      // untouched by the failures
      })
      .then(attemptUserApprove(0, 1, true).fail())

  /** 4 failures is still below the limit: approval remains possible and
   *  resets the counter. */
  run bruteForceBelowLimitTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserCodeBrute(1, 99))
      .then(attemptUserApprove(0, 1, true))
      .expect(all {
        sessions.get(0).status == Validated,
        not(failures.keys().contains(1)),
      })

  /** D3 DENIED is terminal: even the legit approver cannot validate, and
   *  no subject is ever set. */
  run deniedIsTerminalTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(attemptUserApprove(0, 1, false))
      .expect(all {
        sessions.get(0).status == Denied,
        sessions.get(0).subject == 0,          // never validated
      })
      .then(attemptUserApprove(0, 2, true).fail())

  /** Two sessions mint exactly two tokens (ids 2,3: issues consume no
   *  counter); each session is single-use. */
  run twoSessionsTwoTokensTest =
    init
      .then(issueDeviceAuth("c1", Set("openid"), Set(), 0))
      .then(issueDeviceAuth("c2", Set("profile"), Set("tx:pay2"), 0))
      .then(attemptUserApprove(0, 1, true))
      .then(attemptUserApprove(2, 2, true))
      .then(poll(1, "c1", Set(), 0))
      .then(poll(3, "c2", Set(), 0))
      .expect(all {
        tokens.keys().size() == 2,
        tokens.get(2).subject == 1,
        tokens.get(3).subject == 2,
        tokens.get(3).client == "c2",
        tokens.get(3).details == Set("tx:pay2"),
      })
      .then(poll(3, "c2", Set(), 0).fail())

}
