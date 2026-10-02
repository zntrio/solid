/**
 * ciba_test.qnt — deterministic scenario tests for the CIBA model.
 * Run: quint test spec/ciba_test.qnt --main cibaTest
 */

module cibaTest {

  import ciba.* from "./ciba"

  // ------------------------------------------------------------------
  // bc-authorize acceptance / rejection
  // ------------------------------------------------------------------

  /** Happy authorize: exactly one hint, valid binding message, openid. */
  run bcAuthorizeHappyTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(all {
        sessions.keys().size() == 1,
        sessions.get(0).status == Pending,
        sessions.get(0).expiresAt == 4,      // requested_expiry honored
        sessions.get(0).pollInterval == 5,
        sessions.get(0).client == "c1",
      })

  /** requested_expiry 0 → server default. */
  run bcAuthorizeDefaultExpiryTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 0, "d1", "a1", 0, false, false, false))
      .expect(sessions.get(0).expiresAt == DEFAULT_EXPIRY)

  /** Missing binding message (anti-phishing interlock) is rejected. */
  run bcAuthorizeNoBindingMessageTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, false, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false).fail())

  /** Two hints at once: invalid_request. */
  run bcAuthorizeTwoHintsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 2, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false).fail())

  /** No hint at all: invalid_request. */
  run bcAuthorizeNoHintTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 0, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false).fail())

  /** Scope without openid: invalid_scope. */
  run bcAuthorizeNoOpenidTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("profile"), true, true, 4, "d1", "a1", 0, false, false, false).fail())

  /** Unregistered details: invalid_authorization_details, fail closed. */
  run bcAuthorizeBadDetailsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), false, true, 4, "d1", "a1", 0, false, false, false).fail())

  /** Hint not resolvable to a subject: unknown_user_id. */
  run bcAuthorizeUnresolvableHintTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, false, 4, "d1", "a1", 0, false, false, false).fail())

  /** Client without the ciba grant type: unauthorized_client. */
  run bcAuthorizeNoCapabilityTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c3", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false).fail())

  /** offline_access requested: silently stripped from the session (B2). */
  run bcAuthorizeStripsOfflineTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid", "offline_access"), true, true, 4, "d1", "a1", 0, false, false, false))
      .expect(all {
        not(sessions.get(0).scopes.contains("offline_access")),
        sessions.get(0).scopes.contains("openid"),
      })

  /** Signed request object (§7.1.1): iss == client_id and no unsigned
      parameters alongside; otherwise rejected. */
  run bcAuthorizeSignedOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true))
      .expect(sessions.get(0).signed)

  run bcAuthorizeSignedUnsignedParamTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, true, true).fail())

  run bcAuthorizeSignedIssMismatchTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, false).fail())

  // ------------------------------------------------------------------
  // Approval state machine
  // ------------------------------------------------------------------

  /** Validate: PENDING → VALIDATED with the resolved subject. */
  run validateOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.get(0).status == Validated,
        sessions.get(0).subject == 1,
      })

  /** Deny: PENDING → DENIED, terminal (no re-validate). */
  run denyTerminalTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, false))
      .expect(sessions.get(0).status == Denied)
      .then(attemptValidate(0, 1, true).fail())

  /** VALIDATED is terminal too: only PENDING can transition. */
  run validatedTerminalTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(attemptValidate(0, 2, true).fail())

  /** Expired sessions can no longer be validated or denied. */
  run expiredApprovalBlockedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .then(tick(4))                       // now == expiresAt: expired
      .expect(sessions.get(0).status == Pending)
      .then(attemptValidate(0, 1, true).fail())

  // ------------------------------------------------------------------
  // Poll / mint
  // ------------------------------------------------------------------

  /** Happy path: authorize → validate → poll mints one AT with the
      approver's subject (B3) and the session's audience/details (B6).
      Token id / GrantId come from the shared counter (fresh, ≠ auth_req_id). */
  run happyPathTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 2, true))
      .then(poll(0, "c1", 0, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).subject == 2,
        tokens.get(1).client == "c1",
        tokens.get(1).grantId == 1,
        tokens.get(1).audience == "a1",
        tokens.get(1).details == "d1",
        not(tokens.get(1).scopes.contains("offline_access")),
        sessions.keys().size() == 0,        // atomic consume
      })

  /** B1: single use — the second poll of the same auth_req_id fails. */
  run sessionSingleUseTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false))
      .expect(tokens.keys().size() == 1)
      .then(poll(0, "c1", 0, false).fail()) // replay ≡ unknown ⇒ invalid_grant

  /** Early poll: authorization_pending, session stays, nothing minted.
      (lastPolledAt is set to now at creation, so an immediate poll is
      within the interval ⇒ slow_down per Go; admissibility after tick.) */
  run pendingPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(tick(5))                       // 5 >= interval 5: admissible
      .then(poll(0, "c1", 0, false))
      .expect(all {
        sessions.keys().size() == 1,
        sessions.get(0).status == Pending,
        sessions.get(0).lastPolledAt == 5,
        tokens.keys().size() == 0,
      })

  /** B7: fast re-poll → slow_down: Interval += 5, LastPolledAt unchanged. */
  run slowDownIntervalGrowthTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 20, "d1", "a1", 0, false, false, false))
      .then(tick(5))
      .then(poll(0, "c1", 0, false))       // admissible: lastPolledAt = 5
      .then(poll(0, "c1", 0, false))       // immediate: slow_down
      .expect(all {
        sessions.get(0).pollInterval == 10,
        sessions.get(0).lastPolledAt == 5,  // unchanged
        sessions.get(0).status == Pending,
        tokens.keys().size() == 0,
      })

  /** After slow_down the grown interval is enforced until it elapses. */
  run slowDownBlocksUntilIntervalTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 40, "d1", "a1", 0, false, false, false))
      .then(tick(5))                       // now = 5
      .then(poll(0, "c1", 0, false))       // admissible: lastPolledAt = 5
      .then(poll(0, "c1", 0, false))       // slow_down: interval 10
      .then(tick(5))                       // now = 10; 10-5 = 5 < 10
      .then(poll(0, "c1", 0, false))
      .expect(sessions.get(0).pollInterval == 15)
      .then(tick(10))                      // now = 20; 20-5 = 15 >= 15: admissible
      .then(poll(0, "c1", 0, false))
      .expect(all {
        sessions.get(0).lastPolledAt == 20,
        sessions.get(0).pollInterval == 15,
      })

  /** Denied → access_denied: nothing mints, session remains pollable. */
  run deniedPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, false))
      .then(poll(0, "c1", 0, false))
      .expect(all {
        sessions.get(0).status == Denied,
        tokens.keys().size() == 0,
      })

  /** Expired session poll: disabled (expired_token). */
  run expiredPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(tick(4))                       // now == expiresAt: expired
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, false).fail()) // expired_token; nothing consumed

  /** B4: wrong client poll mints nothing. */
  run wrongClientPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(tokens.keys().size() == 0)
      .then(poll(0, "c2", 0, false).fail())

  /** Unknown auth_req_id: invalid_grant, no state change (CIBA-strict). */
  run unknownAuthReqIdTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(poll(7, "c1", 0, false).fail())

  /** Polling client without the ciba grant: unauthorized_client. */
  run pollCapabilityTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(poll(0, "c3", 0, false).fail())

  /** authorization_details on the token request: fail closed (B6 smuggling). */
  run pollCarriesDetailsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, true).fail())

  /** Pending poll consumes nothing: a later validate-then-poll still mints. */
  run pendingThenValidatedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 40, "d1", "a1", 0, false, false, false))
      .then(tick(5))
      .then(poll(0, "c1", 0, false))       // authorization_pending, lastPolledAt = 5
      .then(attemptValidate(0, 2, true))
      .then(tick(5))                       // now = 10, within expiry
      .then(poll(0, "c1", 0, false))       // VALIDATED: mint + atomic consume
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).subject == 2,        // approver's subject (B3)
        sessions.keys().size() == 0,       // consumed
      })

  /** B2: even with offline_access requested, only an AT is minted — never an RT. */
  run noRefreshTokenEverTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid", "offline_access"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false))
      .expect(all {
        tokens.keys().size() == 1,
        not(tokens.get(1).scopes.contains("offline_access")),
      })

  /** B6: details fixed at bc-authorize, carried verbatim into the token. */
  run detailsFixedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d2", "a2", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false))
      .expect(tokens.get(1).details == "d2")

  // ------------------------------------------------------------------
  // DPoP session binding (RFC 9449 §10, B5)
  // ------------------------------------------------------------------

  /** Bound session + matching proof: mints and the jkt carries into the token. */
  run dpopBoundMintOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 1, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 1, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 1,
      })

  /** Bound session + mismatched proof: rejected, nothing minted. */
  run dpopMismatchRejectedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 1, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 2, false).fail())

  /** Bound session + no proof at all: rejected. */
  run dpopNoProofRejectedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 1, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, false).fail())

  /** Unbound session + any proof: still mints, proof key carried. */
  run dpopUnboundAnyProofTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 2, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 2,
      })

}
