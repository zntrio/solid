/**
 * xaa_test.qnt — deterministic scenario tests for the XAA model.
 * Run: quint test xaa_test.qnt --main xaaTest
 */

module xaaTest {

  import xaa.* from "./xaa"

  /** Happy path: SSO → token exchange → jwt-bearer redemption. */
  run happyPathTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read", "chat.history")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/"))
      .expect(all {
        issuedAccessTokens.size() == 1,
        issuedAccessTokens.exists(at => at.subject == 1001 and at.client == "wiki-at-b"),
      })

  /** Scope narrowing at exchange: the ID-JAG carries only the requested subset. */
  run exchangeNarrowsScopeTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read", "chat.history")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .expect(mintedJags.exists(j => j.jti == 1 and j.scopes == Set("chat.read")))

  /** Scope escalation at exchange is rejected: admin.write not in the RT context. */
  run exchangeRejectsEscalationTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("admin.write"), 0).fail())

  /** Scope escalation at redemption is rejected: request ⊄ grant scopes. */
  run redeemRejectsEscalationTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("admin.write"), 0, "https://resource-as.example/").fail())

  /** Forged signature (attacker claims trusted iss) never redeems. */
  run forgedSignatureRejectedTest =
    init
      .then(forgeJag("https://resource-as.example/", 1001, "wiki-at-b", Set("chat.read"), 5))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/").fail())

  /** Valid signature from an untrusted issuer never redeems. */
  run untrustedIssuerRejectedTest =
    init
      .then(foreignIssuerJag("https://resource-as.example/", 1001, "wiki-at-b", Set("chat.read")))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/").fail())

  /** Grant laundering: a grant minted for AS_C cannot redeem at AS_B. */
  run grantLaunderingRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://third-as.example/", Set("chat.read"), 0))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/").fail())

  /** Expired ID-JAG (clock past exp) never redeems. */
  run expiredJagRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(tick)
      .then(tick)
      .then(tick)
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/").fail())

  /** Client impersonation: chat-at-b cannot redeem wiki's grant. */
  run clientImpersonationRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "chat-at-b", Set("chat.read"), 0, "https://resource-as.example/").fail())

  /** DPoP binding: a key-bound grant (jkt=1) rejects a mismatched proof. */
  run dpopBoundGrantRejectsWrongProofTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 1))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/").fail())

  /** DPoP binding: the matching proof redeems and the token carries the key. */
  run dpopBoundGrantAcceptsMatchingProofTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 1))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 1, "https://resource-as.example/"))
      .expect(all {
        issuedAccessTokens.size() == 1,
        issuedAccessTokens.exists(at => at.jkt == 1),
      })

  /** Subject token binding: chat cannot exchange wiki's refresh token. */
  run subjectTokenClientBindingTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .expect(mintedJags.size() == 0)
      .then(exchangeForJag("chat", 0, "https://resource-as.example/", Set("chat.read"), 0).fail())

  /** Unmapped client: the IdP fails closed without a target identifier. */
  run unmappedClientFailsClosedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("chat", 0, "https://resource-as.example/", Set("chat.read"), 0).fail())

  /** Redeeming the same ID-JAG twice succeeds (draft §4.4.3: replayable until exp). */
  run jagReplayableUntilExpiryTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/"))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), 0, "https://resource-as.example/"))
      .expect(issuedAccessTokens.size() == 2)

  /** Pairwise subjects differ per target AS: B and C pseudonyms never collide. */
  run pairwisePerTargetTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/", Set("chat.read"), 0))
      .then(exchangeForJag("wiki", 0, "https://third-as.example/", Set("chat.read"), 0))
      .expect(mintedJags.exists(j1 => mintedJags.exists(j2 =>
        j1.jti == 1 and j2.jti == 2 and j1.sub != j2.sub)))

}