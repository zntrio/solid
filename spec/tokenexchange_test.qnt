/**
 * tokenexchange_test.qnt — deterministic scenario tests for the
 * tokenexchange model.
 * Run: quint test spec/tokenexchange_test.qnt --main tokenexchangeTest
 */

module tokenexchangeTest {

  import tokenexchange.* from "./tokenexchange"

  /** Happy path: plain exchange (no actor) of an ungated token mints an AT
   *  with the subject token's subject and the exchanging client. */
  run happyPathPlainTest =
    init
      .then(seedToken("owner", 11, Set("openid", "profile"), 0, Set(), List(), 5))
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", false))
      .expect(all {
        exchangeTokens.size() == 1,
        exchangeTokens.exists(et =>
          et.subject == 11 and et.client == "c1" and et.actorChain.length() == 0),
      })

  /** Exchange with an actor whose subject is in the subject token's
   *  may_act list succeeds and records the act chain. */
  run actorAllowedByMayActTest =
    init
      .then(seedToken("owner", 11, Set("openid", "profile"), 0, Set(11), List(), 5))  // gated on 11
      .then(seedToken("c1", 11, Set("openid"), 0, Set(), List(12), 5))               // actor token
      .then(exchange("c1", 0, 0, false, 1, 0, Set(), "", false))
      .expect(all {
        exchangeTokens.size() == 1,
        exchangeTokens.exists(et =>
          et.actorChain == List(11, 12) and et.subject == 11),
      })

  /** may_act-gated token + actor NOT in the list: the exchange action is
   *  disabled (guard rejection — no token is minted). */
  run actorNotListedRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(12), List(), 5))  // gated on 12
      .then(seedToken("c1", 11, Set("openid"), 0, Set(), List(), 5))       // actor subject 11 ∉ {12}
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, 1, 0, Set(), "", false).fail())

  /** may_act-gated token exchanged WITHOUT any actor: disabled. */
  run actorRequiredWhenGatedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(11), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", false).fail())

  /** cnf carried: bound subject token exchanged with the matching proof
   *  mints a token carrying the same jkt. */
  run jktCarriedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 1, Set(), List(), 5))
      .then(exchange("c1", 0, 0, false, -1, 1, Set(), "", false))
      .expect(all {
        exchangeTokens.size() == 1,
        exchangeTokens.exists(et => et.jkt == 1),
      })

  /** cnf swap attempt: bound subject token + proof from a different key —
   *  the exchange action is disabled (guard rejection). */
  run jktSwapRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 1, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 2, Set(), "", false).fail())

  /** cnf stripping attempt: bound subject token + no proof — disabled. */
  run jktNoProofRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 1, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", false).fail())

  /** Scope narrowing: a subset of the subject scope mints fine. */
  run scopeNarrowingOkTest =
    init
      .then(seedToken("owner", 11, Set("openid", "profile"), 0, Set(), List(), 5))
      .then(exchange("c1", 0, 0, false, -1, 0, Set("profile"), "", false))
      .expect(all {
        exchangeTokens.size() == 1,
        exchangeTokens.exists(et => et.scopes == Set("profile")),
      })

  /** Scope escalation: requesting a scope outside the subject token's
   *  scope — the exchange action is disabled (no token minted). */
  run scopeEscalationRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 0, Set("openid", "admin"), "", false).fail())

  /** Unknown audience: not in the resource registry — disabled
   *  (invalid_target, no token minted). */
  run unknownAudienceRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "https://evil.example", false).fail())

  /** Registered audience: the minted audience is the registry URN. */
  run audienceRegistryUrnTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "https://rs.example/api", false))
      .expect(exchangeTokens.exists(et => et.audience == 100))

  /** Act chain depth cap: actor with a length-2 prior chain gives depth 3 — OK. */
  run chainDepth3OkTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .then(seedToken("c1", 12, Set("openid"), 0, Set(), List(11, 12), 5))  // actor, prior depth 2
      .then(exchange("c1", 0, 0, false, 1, 0, Set(), "", false))
      .expect(exchangeTokens.exists(et => et.actorChain.length() == 3))

  /** Act chain depth cap: actor with a length-3 prior chain gives depth 4 —
   *  fail closed: the exchange action is disabled (never truncated). */
  run chainDepth4RejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .then(seedToken("c1", 12, Set("openid"), 0, Set(), List(11, 12, 21), 5)) // prior depth 3
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, 1, 0, Set(), "", false).fail())

  /** authorization_details smuggling: the RFC 9396 gate fails closed —
   *  the exchange action is disabled. */
  run authzDetailsRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, true, -1, 0, Set(), "", false).fail())

  /** Client without the token_exchange capability (c2): the exchange
   *  action is disabled (validateGrantPreamble rejection). */
  run noCapabilityRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c2", 0, 0, false, -1, 0, Set(), "", false).fail())

  /** No refresh token: an exchange requesting an RT is disabled. */
  run noRefreshTokenRequestedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", true).fail())

  /** No refresh token: the successful mint is an access token only —
   *  no RT is ever minted from exchange. */
  run noRefreshTokenMintedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", false))
      .expect(all {
        exchangeTokens.size() == 1,
        exchangeTokens.forall(et => tokens.get(et.id).kind == Access),
      })

  /** Expired subject token: exchange mints nothing (tick past expiry). */
  run expiredSubjectTokenTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .then(tick)  // clock 1... not yet
      .then(tick)  // clock 2
      .then(tick)  // clock 3
      .then(tick)  // clock 4
      .then(tick)  // clock 5 == expiresAt -> expired
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", false).fail())

  /** requested_token_type other than access_token: disabled. */
  run requestedTypeOtherRejectedTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .expect(exchangeTokens.size() == 0)
      .then(exchange("c1", 0, 2, false, -1, 0, Set(), "", false).fail())

  /** Subject is preserved even when the exchanging client owns a token
   *  with a different subject: T1 across clients. */
  run subjectPreservationAcrossClientsTest =
    init
      .then(seedToken("owner", 11, Set("openid"), 0, Set(), List(), 5))
      .then(seedToken("c1", 12, Set("openid"), 0, Set(), List(), 5))  // c1's own subject
      .then(exchange("c1", 0, 0, false, -1, 0, Set(), "", false))    // exchange owner's token
      .expect(exchangeTokens.exists(et => et.subject == 11 and et.client == "c1"))

}
