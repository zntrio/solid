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
      .then(mint("conf", Set("read", "write"), 1, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(0).kind == "access",
        tokens.get(0).subject == "conf",
        tokens.get(0).client == "conf",
        tokens.get(0).jkt == 1,
        tokens.get(0).authzDetails == false,
        counter == 1,
      })

  /** Happy path: unbound credentialed client mints an AT with jkt = 0. */
  run happyCredMintTest =
    init
      .then(mint("cred", Set("read"), 0, false))
      .expect(all {
        tokens.keys().size() == 1,
        tokens.get(0).subject == "cred",
        tokens.get(0).jkt == 0,
      })

  /** Public client is rejected by the type gate (invalid_client). */
  run publicClientRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("pub", Set("read"), 0, false).fail())

  /** Unknown client is rejected (validateGrantPreamble client lookup). */
  run unknownClientRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("attacker", Set("read"), 0, false).fail())

  /** RFC 9396 fail-closed: smuggling authorization_details is rejected. */
  run detailsSmugglingRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read"), 1, true).fail())

  /** The adversarial variant is guarded out whenever details are present. */
  run attemptWithDetailsConfDisabledTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(attemptWithDetails("conf", Set("read"), 1).fail())

  /** Adversarial variant stays disabled for the unbound credentialed client too. */
  run attemptWithDetailsCredDisabledTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(attemptWithDetails("cred", Set("read"), 0).fail())

  /** DPoP-bound client minting without a proof is rejected (invalid_request). */
  run dpopMissingProofRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read"), 0, false).fail())

  /** Unbound client presenting a DPoP proof is rejected (binding policy). */
  run unboundWithProofRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("cred", Set("read"), 1, false).fail())

  /** Scope smuggling: a scope outside the registered set is rejected. */
  run scopeSmugglingRejectedTest =
    init
      .expect(tokens.keys().size() == 0)
      .then(mint("conf", Set("read", "admin"), 1, false).fail())


  /** Structural: no refresh token can ever be minted by this grant. */
  run noRefreshTokenEverTest =
    init
      .then(mint("conf", Set("read"), 1, false))
      .then(mint("conf", Set("write"), 2, false))
      .then(mint("cred", Set("read"), 0, false))
      .expect(all {
        tokens.keys().size() == 3,
        tokens.keys().forall(k => tokens.get(k).kind == "access"),
        not (tokens.keys().exists(k => tokens.get(k).kind == "refresh")),
      })

  /** Each mint is its own grant family (fresh random16 GrantId). */
  run freshGrantFamilyTest =
    init
      .then(mint("conf", Set("read"), 1, false))
      .then(mint("conf", Set("read"), 1, false))
      .expect(all {
        tokens.get(0).grantId == 0,
        tokens.get(1).grantId == 1,
        tokens.get(0).grantId != tokens.get(1).grantId,
      })

}

