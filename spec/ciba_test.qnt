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
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(all {
        sessions.keys().size() == 1,
        sessions.get(0).status == Pending,
        sessions.get(0).expiresAt == 4,      // requested_expiry honored
        sessions.get(0).pollInterval == 5,
        sessions.get(0).client == "c1",
        sessions.get(0).subject == 1,       // hint-resolved subject stored
        sessions.get(0).lastPolledAt == -1, // never-polled sentinel
      })

  /** requested_expiry 0 → server default. */
  run bcAuthorizeDefaultExpiryTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 0, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.get(0).expiresAt == DEFAULT_EXPIRY)

  /** Missing binding message (anti-phishing interlock) is rejected. */
  run bcAuthorizeNoBindingMessageTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, false, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** Two hints at once: invalid_request. */
  run bcAuthorizeTwoHintsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 2, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** No hint at all: invalid_request. */
  run bcAuthorizeNoHintTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 0, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** Scope without openid: invalid_scope. */
  run bcAuthorizeNoOpenidTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("profile"), true, true, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** Unregistered details: invalid_authorization_details, fail closed. */
  run bcAuthorizeBadDetailsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), false, true, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** Hint not resolvable to a subject: unknown_user_id. */
  run bcAuthorizeUnresolvableHintTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, false, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** Client without the ciba grant type: unauthorized_client. */
  run bcAuthorizeNoCapabilityTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c3", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false).fail())

  /** offline_access requested: silently stripped from the session (B2). */
  run bcAuthorizeStripsOfflineTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid", "offline_access"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .expect(all {
        not(sessions.get(0).scopes.contains("offline_access")),
        sessions.get(0).scopes.contains("openid"),
      })

  /** Signed request object (§7.1.1): iss == client_id, aud contains the
      issuer, and no unsigned parameters alongside; otherwise rejected. */
  run bcAuthorizeSignedOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true, true))
      .expect(sessions.get(0).signed)

  run bcAuthorizeSignedUnsignedParamTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true, true))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, true, true, true).fail())

  run bcAuthorizeSignedIssMismatchTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true, true))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, false, true).fail())

  /** §7.1.1: the signed object's aud claim must contain the issuer. */
  run bcAuthorizeSignedAudMismatchTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true, true))
      .expect(sessions.keys().size() == 1)
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, true, false, true, false).fail())

  // ------------------------------------------------------------------
  // Approval state machine
  // ------------------------------------------------------------------

  /** Validate: PENDING → VALIDATED with the resolved subject. */
  run validateOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.get(0).status == Validated,
        sessions.get(0).subject == 1,
      })

  /** Approver identity substitution: the confirming user MUST be the
      hint-resolved subject (service.go:330-338); the mismatched approval
      is rejected. A disabled action makes no state change, so the
      session stays PENDING — pinned by the same test's pre-expect. */
  run validateSubjectMismatchTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .expect(all {
        sessions.get(0).status == Pending,
        sessions.get(0).subject == 1,
      })
      .then(attemptValidate(0, 2, true).fail())

  /** Companion: the resolving subject's approval is the one that
      transitions the session (contrast with the mismatch test above). */
  run validateMismatchThenCorrectSubjectTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(sessions.get(0).status == Validated)

  /** Deny: PENDING → DENIED, terminal (no re-validate). */
  run denyTerminalTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, false))
      .expect(sessions.get(0).status == Denied)
      .then(attemptValidate(0, 1, true).fail())

  /** VALIDATED is terminal too: only PENDING can transition. */
  run validatedTerminalTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(attemptValidate(0, 2, true).fail())

  /** Expiry is LENIENT at equality (code: only ExpiresAt < now is
      rejected): a poll at now == expiresAt still succeeds. */
  run approveAtExpiryBoundaryOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(tick(4))                       // now == expiresAt: still live
      .then(attemptValidate(0, 1, true))
      .expect(sessions.get(0).status == Validated)
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        tokens.keys().size() == 1,         // minted at the boundary
        sessions.keys().size() == 0,
      })

  /** Past the boundary, approval is blocked (expired_token). */
  run expiredApprovalBlockedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))                       // now > expiresAt: expired
      .expect(sessions.get(0).status == Pending)
      .then(attemptValidate(0, 1, true).fail())

  /** D4: an expired PENDING session can still be denied (Deny never
      reads the clock), and the denial is terminal. */
  run denyAfterExpirySucceedsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))                       // now > expiresAt: expired
      .then(attemptValidate(0, 1, false))  // deny: no expiry check
      .expect(sessions.get(0).status == Denied)
      .then(attemptValidate(0, 1, true).fail()) // terminal

  /** D4 companion: past expiry the approval branch alone is rejected. */
  run approveAfterExpiryRejectedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))
      .then(attemptValidate(0, 1, true).fail()) // approval: expired_token

  // ------------------------------------------------------------------
  // Poll / mint
  // ------------------------------------------------------------------

  /** Happy path: authorize → validate → poll mints one AT with the
      hint-resolved subject (B3) and the session's audience/details (B6).
      Token id / GrantId come from the shared counter (fresh, ≠ auth_req_id). */
  run happyPathTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).subject == 1,
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
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false))
      .expect(tokens.keys().size() == 1)
      .then(poll(0, "c1", 0, false, false).fail()) // replay ≡ unknown ⇒ invalid_grant

  /** D6: the FIRST poll of a fresh session is ALWAYS admissible (Go
      zero-value LastPolledAt sentinel) — no slow_down before it. */
  run firstPollAlwaysAdmissibleTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(poll(0, "c1", 0, false, false)) // immediate, no tick: admissible
      .expect(all {
        sessions.keys().size() == 1,
        sessions.get(0).status == Pending,
        sessions.get(0).lastPolledAt == 0,  // set to now
        sessions.get(0).pollInterval == 5,   // unchanged
        tokens.keys().size() == 0,
      })

  /** D6 follow-up: after an admissible first poll at t, an immediate
      second poll slow_downs. */
  run secondImmediatePollSlowDownTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 20, "d1", "a1", 0, false, false, false, false))
      .then(poll(0, "c1", 0, false, false)) // first: admissible, lastPolledAt = 0
      .then(poll(0, "c1", 0, false, false)) // second, immediate: slow_down
      .expect(all {
        sessions.get(0).pollInterval == 10,
        sessions.get(0).lastPolledAt == 0,  // unchanged
      })

  /** Admissible poll after the base interval: authorization_pending. */
  run pendingPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))                       // 5 >= interval 5: admissible
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        sessions.keys().size() == 1,
        sessions.get(0).status == Pending,
        sessions.get(0).lastPolledAt == 5,
        tokens.keys().size() == 0,
      })

  /** B7: fast re-poll → slow_down: Interval += 5, LastPolledAt unchanged. */
  run slowDownIntervalGrowthTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 20, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))
      .then(poll(0, "c1", 0, false, false))       // admissible: lastPolledAt = 5
      .then(poll(0, "c1", 0, false, false))       // immediate: slow_down
      .expect(all {
        sessions.get(0).pollInterval == 10,
        sessions.get(0).lastPolledAt == 5,  // unchanged
        sessions.get(0).status == Pending,
        tokens.keys().size() == 0,
      })

  /** After slow_down the grown interval is enforced until it elapses. */
  run slowDownBlocksUntilIntervalTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 40, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))                       // now = 5
      .then(poll(0, "c1", 0, false, false)) // admissible: lastPolledAt = 5
      .then(poll(0, "c1", 0, false, false)) // slow_down: interval 10
      .then(tick(5))                       // now = 10; 10-5 = 5 < 10
      .then(poll(0, "c1", 0, false, false))
      .expect(sessions.get(0).pollInterval == 15)
      .then(tick(10))                      // now = 20; 20-5 = 15 >= 15: admissible
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        sessions.get(0).lastPolledAt == 20,
        sessions.get(0).pollInterval == 15,
      })

  /** P1 (pinned): a MINTING poll bypasses enforcePollInterval — the
      interval check lives only in the PENDING branch of the Go guard
      chain (grant_ciba.go), so a VALIDATED session mints immediately
      even inside a slow_down window. */
  run mintBypassesThrottleTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 40, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))                       // now = 5
      .then(poll(0, "c1", 0, false, false)) // admissible: lastPolledAt = 5
      .then(poll(0, "c1", 0, false, false)) // slow_down: interval 10
      .then(tick(2))                       // now = 7; 7-5 = 2 < 10: window open
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false)) // VALIDATED: mints immediately
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).subject == 1,
        sessions.keys().size() == 0,       // consumed
      })

  /** Denied → access_denied: nothing mints, session remains pollable. */
  run deniedPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, false))
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        sessions.get(0).status == Denied,
        tokens.keys().size() == 0,
      })

  /** Expiry is LENIENT at equality: a poll at now == expiresAt mints. */
  run pollAtExpiryBoundaryMintsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(tick(4))                       // now == expiresAt: still live
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        sessions.keys().size() == 0,
      })

  /** Past the boundary, the poll is expired_token; nothing consumed. */
  run expiredPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 4, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(tick(5))                       // now > expiresAt: expired
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, false, false).fail()) // expired_token; nothing consumed

  /** B4: wrong client poll mints nothing. */
  run wrongClientPollTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(tokens.keys().size() == 0)
      .then(poll(0, "c2", 0, false, false).fail())

  /** Unknown auth_req_id: invalid_grant, no state change (CIBA-strict). */
  run unknownAuthReqIdTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .expect(sessions.keys().size() == 1)
      .then(poll(7, "c1", 0, false, false).fail())

  /** Polling client without the ciba grant: unauthorized_client. */
  run pollCapabilityTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(poll(0, "c3", 0, false, false).fail())

  /** authorization_details on the token request: fail closed (B6 smuggling). */
  run pollCarriesDetailsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, false, true).fail())

  /** Pending poll consumes nothing: a later validate-then-poll still mints. */
  run pendingThenValidatedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 40, "d1", "a1", 0, false, false, false, false))
      .then(tick(5))
      .then(poll(0, "c1", 0, false, false))       // authorization_pending, lastPolledAt = 5
      .then(attemptValidate(0, 1, true))          // the hint-resolved subject
      .then(tick(5))                       // now = 10, within expiry
      .then(poll(0, "c1", 0, false, false))       // VALIDATED: mint + atomic consume
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).subject == 1,        // hint-resolved subject (B3)
        sessions.keys().size() == 0,       // consumed
      })

  /** B2: even with offline_access requested, only an AT is minted — never an RT. */
  run noRefreshTokenEverTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid", "offline_access"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        not(tokens.get(1).scopes.contains("offline_access")),
      })

  /** B6: details fixed at bc-authorize, carried verbatim into the token. */
  run detailsFixedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d2", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false))
      .expect(tokens.get(1).details == "d2")

  // ------------------------------------------------------------------
  // Sender-constrained policy (grants.go enforceSenderBinding, D1)
  // ------------------------------------------------------------------

  /** One-sided as enforced: a DPoP-bound client (c2) MUST present a jkt —
      a proof-less poll is rejected before the session lookup; a disabled
      action makes no state change, so the session stays pollable (the
      with-proof mint below exercises the same session shape). */
  run dpopBoundClientNeedsProofTest =
    init
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c2", 0, false, false).fail())

  /** A DPoP-bound client presenting its proof mints; the jkt is carried
      into the minted token verbatim (B10). */
  run dpopBoundClientWithProofMintsTest =
    init
      .then(bcAuthorize("c2", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c2", 1, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 1,            // carried verbatim (B10)
      })

  /** A TLS-bound client (c4) MUST present an x5t#S256 confirmation. */
  run tlsBoundClientNeedsX5tTest =
    init
      .then(bcAuthorize("c4", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c4", 0, false, false).fail())  // no x5t: rejected; nothing minted


  run tlsBoundClientWithX5tMintsTest =
    init
      .then(bcAuthorize("c4", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c4", 0, true, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).x5t,                 // carried verbatim (B10)
      })

  // ------------------------------------------------------------------
  // Audience registry (RFC 8707 §2, D2)
  // ------------------------------------------------------------------

  /** An unregistered session audience is rejected at MINT time, AFTER
      the atomic consume: the session is burned with nothing minted
      (invalid_target), and the replay answers invalid_grant (unknown). */
  run unregisteredAudienceBurnsSessionTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a2", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false))       // a2 unregistered: burned
      .expect(all {
        sessions.keys().size() == 0,       // consumed regardless
        tokens.keys().size() == 0,         // invalid_target: nothing minted
      })
      .then(poll(0, "c1", 0, false, false).fail()) // replay ≡ unknown

  /** B9: a registered audience lands in the minted token's aud. */
  run registeredAudienceMintsTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 0, false, false))
      .expect(tokens.get(1).audience == "a1")

  // ------------------------------------------------------------------
  // DPoP session binding (RFC 9449 §10, B5)
  // ------------------------------------------------------------------

  /** Bound session + matching proof: mints and the jkt carries into the token. */
  run dpopBoundMintOkTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 1, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 1, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 1,
      })

  /** Bound session + mismatched proof: rejected, nothing minted. */
  run dpopMismatchRejectedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 1, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 2, false, false).fail())

  /** Bound session + no proof at all: rejected. */
  run dpopNoProofRejectedTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 1, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .expect(all {
        sessions.keys().size() == 1,
        tokens.keys().size() == 0,
      })
      .then(poll(0, "c1", 0, false, false).fail())

  /** Unbound session + any proof: still mints, proof key carried. */
  run dpopUnboundAnyProofTest =
    init
      .then(bcAuthorize("c1", 1, 1, true, Set("openid"), true, true, 10, "d1", "a1", 0, false, false, false, false))
      .then(attemptValidate(0, 1, true))
      .then(poll(0, "c1", 2, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).jkt == 2,
      })

}
