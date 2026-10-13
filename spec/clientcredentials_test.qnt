/**
 * clientcredentials_test.qnt — deterministic scenario tests for the
 * client_credentials model.
 * Run: quint test spec/clientcredentials_test.qnt --main clientcredentialsTest
 */

module clientcredentialsTest {

  import clientcredentials.* from "./clientcredentials"

  /** Happy path: DPoP-bound confidential client mints an AT, subject == client. */
  run happyConfMintTest =
    init
      .then(mint("conf", Set("read", "write"), "", "", 1, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(0).kind == "access",
        tokens.get(0).subject == "conf",
        tokens.get(0).client == "conf",
        tokens.get(0).jkt == 1,
        tokens.get(0).audience == "",
        tokens.get(0).authzDetails == false,
        counter == 1,
      })

  /** Happy path: unbound credentialed client mints an AT with jkt = 0. */
  run happyCredMintTest =
    init
      .then(mint("cred", Set("read"), "", "", 0, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(0).subject == "cred",
        tokens.get(0).jkt == 0,
      })

  /** Public client is rejected by the type gate (invalid_client). */
  run publicClientRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("pub", Set("read"), "", "", 0, false, false).fail())

  /** Unknown client is rejected (service-layer client lookup). */
  run unknownClientRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("attacker", Set("read"), "", "", 0, false, false).fail())

  /** RFC 9396 fail-closed: smuggling authorization_details is rejected. */
  run detailsSmugglingRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read"), "", "", 1, false, true).fail())

  /** The adversarial variant is guarded out whenever details are present. */
  run attemptWithDetailsConfDisabledTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(attemptWithDetails("conf", Set("read"), "", "", 1, false).fail())

  /** Adversarial variant stays disabled for the unbound credentialed client too. */
  run attemptWithDetailsCredDisabledTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(attemptWithDetails("cred", Set("read"), "", "", 0, false).fail())

  /** DPoP-bound client minting without a proof is rejected (invalid_request). */
  run dpopMissingProofRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read"), "", "", 0, false, false).fail())

  /**
   * Unbound client presenting a DPoP proof: ACCEPTED by the code (the
   * one-sided enforceSenderBinding passes it through verbatim); the
   * confirmation is carried into the minted token. Pins the documented
   * spec/code posture of grants.go:86-97.
   */
  run unboundWithProofAcceptedTest =
    init
      .then(mint("cred", Set("read"), "", "", 1, false, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(0).jkt == 1,
      })

  /** Scope smuggling: a scope outside the registered set is rejected. */
  run scopeSmugglingRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read", "admin"), "", "", 1, false, false).fail())

  /** Open-ended registration (cred): any scope is unrestricted. */
  run unrestrictedScopeTest =
    init
      .then(mint("cred", Set("read", "write", "admin"), "", "", 0, false, false))
      .expect(tokens.get(0).scopes == Set("read", "write", "admin"))

  /** Structural: no refresh token can ever be minted by this grant. */
  run noRefreshTokenEverTest =
    init
      .then(mint("conf", Set("read"), "", "", 1, false, false))
      .then(mint("conf", Set("write"), "", "", 2, false, false))
      .then(mint("cred", Set("read"), "", "", 0, false, false))
      .expect(all {
        tokens.keys().size() == 3,
        tokens.keys().forall(k => tokens.get(k).kind == "access"),
        not (tokens.keys().exists(k => tokens.get(k).kind == "refresh")),
      })

  /** Each mint is its own grant family (fresh random16 GrantId). */
  run freshGrantFamilyTest =
    init
      .then(mint("conf", Set("read"), "", "", 1, false, false))
      .then(mint("conf", Set("read"), "", "", 1, false, false))
      .expect(all {
        tokens.get(0).grantId == 0,
        tokens.get(1).grantId == 1,
        tokens.get(0).grantId != tokens.get(1).grantId,
      })

  /** RFC 8707: a registered resource indicator is the minted audience. */
  run resourceAudienceTest =
    init
      .then(mint("conf", Set("read"), "https://api.example/", "", 1, false, false))
      .expect(tokens.get(0).audience == "https://api.example/")

  /** RFC 8707: an UNREGISTERED resource indicator is rejected (invalid_target). */
  run unknownResourceRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read"), "https://evil.example/", "", 1, false, false).fail())

  /** RFC 8707: the bare audience parameter is validated against the registry. */
  run unknownAudienceRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read"), "", "https://evil.example/", 1, false, false).fail())

  /** RFC 8707: a registered audience lands in the minted aud. */
  run registeredAudienceTest =
    init
      .then(mint("conf", Set("read"), "", "https://rs.example.org", 1, false, false))
      .expect(tokens.get(0).audience == "https://rs.example.org")

  /** RFC 8707 §2: the resource parameter takes precedence over audience. */
  run resourcePrecedenceTest =
    init
      .then(mint("conf", Set("read"), "https://api.example/", "https://rs.example.org", 1, false, false))
      .expect(tokens.get(0).audience == "https://api.example/")

}
