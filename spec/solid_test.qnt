/**
 * solid_test.qnt — deterministic scenario tests for the solid model.
 * Run: quint test solid_test.qnt --main solidTest
 */

module solidTest {

  import solid.* from "./solid"

  /** PAR → authorize → redeem with matching verifier and redirect yields AT+RT. */
  run happyPathTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid", "offline_access"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 2,
        tokens.get(2).kind == Access,
        tokens.get(3).kind == Refresh,
        tokens.get(2).grantId == 1,
        tokens.get(3).grantId == 1,
      })

  /** Second redeem of the same code is impossible: the burn precedes all checks. */
  run codeSingleUseTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0))
      .expect(tokens.keys().size() == 1)
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0).fail())

  /** redeem with a WRONG verifier is still enabled (burns the code) but mints nothing. */
  run wrongVerifierBurnsCodeTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 2, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0, // code consumed despite failed PKCE
      })

  /** A wrong-verifier redeem blocks a subsequent correct redeem: burn is unconditional. */
  run failedRedeemBlocksHonestRetryTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 2, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0, // wrong verifier burned the code
      })
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0).fail())

  /** Code issued to c1 cannot be redeemed by c2, even with correct verifier/redirect. */
  run clientBindingTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c2", 1, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0, // burn still consumed the code
      })

  /** PAR request_uri is burn-after-read: a second authorize on it is disabled. */
  run parSingleUseTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(authorizePAR(0))
      .expect(sessions.keys().size() == 1)
      .then(authorizePAR(0).fail())

  /** refresh rotates: new AT+RT minted via FromRefresh, old RT revoked, single active RT. */
  run refreshRotationTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid", "offline_access"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0))
      .then(refresh(3, "c1"))
      .expect(all {
        tokens.get(3).status == Revoked,               // old RT rotated out
        tokens.get(4).kind == Access, tokens.get(4).via == FromRefresh,
        tokens.get(5).kind == Refresh, tokens.get(5).via == FromRefresh,
        tokens.get(4).grantId == tokens.get(3).grantId, // family preserved
      })

  /** Replay of the revoked RT revokes the ENTIRE grant family (theft response). */
  run replayRevokesFamilyTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid", "offline_access"), true, 0))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0))
      .then(refresh(3, "c1"))
      .then(refresh(3, "c1"))                          // replay the rotated-out RT
      .expect(all {
        replayDetected == Set(1),
        tokens.get(2).status == Revoked,               // original AT
        tokens.get(4).status == Revoked,               // refreshed AT
        tokens.get(5).status == Revoked,               // rotated RT
        tokens.get(3).status == Revoked,               // replayed RT
      })

  /** c2 lacks the refresh_token grant: its refresh attempts are disabled. */
  run refreshCapabilityTest =
    init
      .then(authorizeDirect("c2", 1, 1, "https://c2.example/cb", Set("openid", "offline_access"), true, 0))
      .then(redeem(0, "c2", 1, "https://c2.example/cb", 0))
      .expect(tokens.keys().size() == 2)               // RT minted to family anyway
      .then(refresh(1, "c2").fail())                    // but c2 cannot use it

  /** Revocation by a non-owner client leaves the token ACTIVE. */
  run revokeOwnerOnlyTest =
    init
      .then(authorizeDirect("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(redeem(0, "c1", 1, "https://c1.example/cb", 0))
      .then(revoke(1, "c2"))
      .expect(tokens.get(1).status == Active)
      .then(revoke(1, "c1"))
      .expect(tokens.get(1).status == Revoked)

  /** Pairwise: same user, different clients ⇒ different pseudonyms. */
  run pairwiseDisjointnessTest =
    init
      .then(authorizeDirect("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 0))
      .then(authorizeDirect("c2", 1, 1, "https://c2.example/cb", Set("openid"), true, 0))
      .then(redeem(0, "c1", 1, "https://c1.example/cb", 0))
      .then(redeem(1, "c2", 1, "https://c2.example/cb", 0))
      .expect(tokens.get(2).subject != tokens.get(3).subject)

  /** Without consent, offline_access is stripped at authorize time: no RT minted. */
  run offlineNeedsConsentTest =
    init
      .then(authorizeDirect("c1", 1, 1, "https://c1.example/cb", Set("openid", "offline_access"), false, 0))
      .then(redeem(0, "c1", 1, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(1).kind == Access,
      })

  /** Non-openid scope: redemption succeeds but mints nothing (code is still burned). */
  run noOpenidNoTokensTest =
    init
      .then(authorizeDirect("c1", 1, 1, "https://c1.example/cb", Set("profile"), true, 0))
      .then(redeem(0, "c1", 1, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0,
      })

  /** DPoP: code bound at PAR with key K redeems fine with a proof from K. */
  run dpopBoundRedeemOkTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 1))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 1))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(2).jkt == 1, // confirmation carried into the token
      })

  /** DPoP: bound code + proof from a DIFFERENT key burns the code, mints nothing. */
  run dpopKeySwapRejectedTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 1))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 2))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0, // burn still consumed the code
      })

  /** DPoP: bound code without any proof (jkt 0) burns the code, mints nothing. */
  run dpopNoProofRejectedTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid"), true, 1))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 0))
      .expect(all {
        tokens.keys().size() == 0,
        sessions.keys().size() == 0,
      })

  /** DPoP: the key binding survives refresh — rotated tokens keep the family key. */
  run dpopKeyContinuityThroughRefreshTest =
    init
      .then(registerPAR("c1", 1, 1, "https://c1.example/cb", Set("openid", "offline_access"), true, 1))
      .then(authorizePAR(0))
      .then(redeem(1, "c1", 1, "https://c1.example/cb", 1))
      .then(refresh(3, "c1"))
      .expect(all {
        tokens.get(4).jkt == 1,
        tokens.get(5).jkt == 1,
      })

}
