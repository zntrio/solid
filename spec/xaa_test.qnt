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
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/"))
      .expect(all {
        issuedAccessTokens.size() == 1,
        issuedAccessTokens.exists(at => at.subject == 1001 and at.client == "wiki-at-b"),
      })

  /** Scope narrowing at exchange: the ID-JAG carries only the requested subset. */
  run exchangeNarrowsScopeTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read", "chat.history")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .expect(mintedJags.exists(j => j.jti == 1 and j.scopes == Set("chat.read")))

  /** Scope escalation at exchange is rejected: admin.write not in the RT context. */
  run exchangeRejectsEscalationTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("admin.write"), 0).fail())

  /** Scope escalation at redemption is rejected: request ⊄ grant scopes. */
  run redeemRejectsEscalationTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("admin.write"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Forged signature (attacker claims trusted iss) never redeems. */
  run forgedSignatureRejectedTest =
    init
      .then(forgeJag("https://resource-as.example/", 1001, "wiki-at-b",
        Set("chat.read"), "", 5))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Valid signature from an untrusted issuer never redeems. */
  run untrustedIssuerRejectedTest =
    init
      .then(foreignIssuerJag("https://resource-as.example/", 1001, "wiki-at-b",
        Set("chat.read")))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Self-issued ID-JAG (iss == local AS) never redeems (draft §9.3). */
  run selfIssuedJagRejectedTest =
    init
      .then(forgeJag("https://resource-as.example/", 1001, "wiki-at-b",
        Set("chat.read"), "", 5))
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Grant laundering: a grant minted for AS_C cannot redeem at AS_B. */
  run grantLaunderingRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://third-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Expired ID-JAG (clock past exp) never redeems. */
  run expiredJagRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(tick)
      .then(tick)
      .then(tick)
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /**
   * Over-long-lived assertion never redeems: the forged grant claims a
   * 15-minute validity window, above the 10-minute maximum
   * ( maxAssertionLifetime, grant_jwt_bearer.go:214-217 ).
   */
  run lifetimeCapRejectsLongLivedJagTest =
    init
      .then(forgeJag("https://resource-as.example/", 1001, "wiki-at-b",
        Set("chat.read"), "", 15))
      .expect(all {
        issuedAccessTokens.size() == 0,
        mintedJags.exists(j => j.jti == 0 and j.exp == 15 and j.iat == 0),
      })
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Client impersonation: chat-at-b cannot redeem wiki's grant. */
  run clientImpersonationRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "chat-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** DPoP binding: a key-bound grant (jkt=1) rejects a mismatched proof. */
  run dpopBoundGrantRejectsWrongProofTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 1))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** DPoP binding: the matching proof redeems and the token carries the key. */
  run dpopBoundGrantAcceptsMatchingProofTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 1))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 1,
        "https://resource-as.example/"))
      .expect(all {
        issuedAccessTokens.size() == 1,
        issuedAccessTokens.exists(at => at.jkt == 1),
      })

  /**
   * Sender-binding policy: chat-at-b is registered DpopBoundAccessTokens,
   * so an unbound grant redeeming without any proof must be rejected —
   * even though the grant itself carries no cnf.jkt
   * ( enforceSenderBinding, grants.go:91-94 ).
   */
  run dpopBoundClientRequiresProofTest =
    init
      .then(ssoLogin("calendar", 1, Set("chat.read")))
      .then(exchangeForJag("calendar", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .expect(issuedAccessTokens.size() == 0)
      .then(redeemJag(1, "chat-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /** Same DPoP-bound client with a presented proof redeems fine. */
  run dpopBoundClientAcceptsWithProofTest =
    init
      .then(ssoLogin("calendar", 1, Set("chat.read")))
      .then(exchangeForJag("calendar", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(redeemJag(1, "chat-at-b", Set("chat.read"), Set(), 1,
        "https://resource-as.example/"))
      .expect(issuedAccessTokens.size() == 1)

  /**
   * RFC 8707: an attacker-named resource indicator on a forged grant
   * never mints — the registry check fails closed ( invalid_target ).
   */
  run unregisteredResourceRejectedTest =
    init
      .then(forgeJag("https://resource-as.example/", 1001, "wiki-at-b",
        Set("chat.read"), "urn:evil:resource", 5))
      .expect(all {
        issuedAccessTokens.size() == 0,
        mintedJags.exists(j => j.jti == 0 and j.resource == "urn:evil:resource"),
      })
      .then(redeemJag(0, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/").fail())

  /**
   * RFC 8707: a legitimate grant with a registered resource indicator
   * redeems and the resource wins over the audience claim in the minted
   * token ( grant_jwt_bearer.go:126-128 ).
   */
  run resourceIndicatorWinsAudienceTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "urn:example:backend-api",
        Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/"))
      .expect(all {
        issuedAccessTokens.size() == 1,
        issuedAccessTokens.exists(at => at.aud == "urn:example:backend-api"),
      })

  /**
   * RFC 9396: requested authorization_details can never exceed the grant
   * (which honestly carries none — issuance is fail-closed), so any
   * non-empty detail request fails.
   */
  run authorizationDetailsWideningRejectedTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set("payment:init"), 0,
        "https://resource-as.example/").fail())

  /**
   * Empty-scope-request semantics: no requested scope carries the full
   * granted context — at exchange from the refresh token, at redemption
   * from the grant ( grant_token_exchange_idjag.go:100-110, scopeOf ).
   */
  run emptyScopeCarriesContextTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read", "chat.history")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "", Set(), 0))
      .expect(mintedJags.exists(j => j.jti == 1 and j.scopes == Set("chat.read", "chat.history")))
      .then(redeemJag(1, "wiki-at-b", Set(), Set(), 0,
        "https://resource-as.example/"))
      .expect(issuedAccessTokens.exists(at =>
        at.scopes == Set("chat.read", "chat.history")))

  /** Subject token binding: chat cannot exchange wiki's refresh token. */
  run subjectTokenClientBindingTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .expect(mintedJags.size() == 0)
      .then(exchangeForJag("chat", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0).fail())

  /**
   * Subject-token type dispatch: an id_token subject token fails closed —
   * the profile supports only refresh tokens
   * ( idjagSubjectFromIDToken, grant_token_exchange_idjag.go:72-80,244-248 ).
   */
  run exchangeRejectsIDTokenSubjectTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:id_token", "",
        Set("chat.read"), 0).fail())

  /**
   * Per-audience client mapping: calendar is mapped at AS_B but NOT at
   * AS_C, so exchanging for audience C fails closed — being mapped at one
   * target does not vouch for any other
   * ( XAAAudience.ClientIDMapping, targetClientID ).
   */
  run unmappedAtThirdASTest =
    init
      .then(ssoLogin("calendar", 1, Set("chat.read")))
      .then(exchangeForJag("calendar", 0, "https://third-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0).fail())

  /** Same client is mapped at AS_B and redeems there happily. */
  run mappedAtASBTest =
    init
      .then(ssoLogin("calendar", 1, Set("chat.read")))
      .then(exchangeForJag("calendar", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(redeemJag(1, "chat-at-b", Set("chat.read"), Set(), 1,
        "https://resource-as.example/"))
      .expect(issuedAccessTokens.size() == 1)

  /** Redeeming the same ID-JAG twice succeeds (draft §4.4.3: replayable until exp). */
  run jagReplayableUntilExpiryTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/"))
      .then(redeemJag(1, "wiki-at-b", Set("chat.read"), Set(), 0,
        "https://resource-as.example/"))
      .expect(issuedAccessTokens.size() == 2)

  /** Pairwise subjects differ per target AS: B and C pseudonyms never collide. */
  run pairwisePerTargetTest =
    init
      .then(ssoLogin("wiki", 1, Set("chat.read")))
      .then(exchangeForJag("wiki", 0, "https://resource-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .then(exchangeForJag("wiki", 0, "https://third-as.example/",
        "urn:ietf:params:oauth:token-type:refresh_token", "",
        Set("chat.read"), 0))
      .expect(mintedJags.exists(j1 => mintedJags.exists(j2 =>
        j1.jti == 1 and j2.jti == 2 and j1.sub != j2.sub)))

  /** RT possession follows the SSO consent, not the exchange capability. */
  run ssoLoginNeedsNoExchangeGrantTest =
    init
      .then(ssoLogin("chat", 1, Set("chat.read")))
      .expect(refreshTokens.keys().size() == 1)

}
