/**
 * clientcredentials.qnt — formal model of the solid client_credentials
 * (machine-to-machine, RFC 6749 §4.4) grant lifecycle ( zntr.io/solid,
 * module `clientcredentials` ).
 *
 * COVERS
 *   - Inline grant preamble: nullity, issuer syntax, client type,
 *     authorization_details fail-closed, grant capability — in the
 *     grant's OWN guard order ( grant_client_credentials.go:41-101,
 *     NOT the shared validateGrantPreamble: this grant checks sender
 *     binding BEFORE issuer/type/details/capability )
 *   - Sender-constrained token policy: DPoP and TLS-certificate key
 *     binding, one-sided as enforced ( grants.go enforceSenderBinding:
 *     a bound client MUST present its confirmation; an unbound client
 *     presenting one anyway is passed through verbatim into the minted
 *     token — no rejection branch exists in the code )
 *   - Client type gating: only CONFIDENTIAL / CREDENTIALED clients may mint
 *     ( grant_client_credentials.go:75-86, invalid_client for public clients )
 *   - RFC 9396 fail-closed: authorization_details are rejected outright —
 *     the grant has no end-user consent authority
 *     ( grant_client_credentials.go:88-94 )
 *   - RFC 8707 audience authority: resource indicators are singular and
 *     registry-validated; the audience parameter is validated against
 *     the same registry when no resource is given; the minted aud is
 *     the resource when present, else the validated audience
 *     ( grant_client_credentials.go:103-134, 161-168 )
 *   - AT-only minting: NO refresh token is ever issued (no user, no
 *     consent); subject == client_id (RFC 9068 §4 — the client is the
 *     resource owner); GrantId = fresh random16 per mint, so every mint
 *     is its own grant family
 *   - Scope containment: minted scope ⊆ client's registered scope; an
 *     open-ended registration (no registered scope) is unrestricted
 *     ( grant_client_credentials.go:136-148 )
 *
 * DOES NOT COVER (deliberate abstractions)
 *   - Cryptography: JWT/DPoP signatures, key thumbprints are assumed
 *     correct; jkt/x5t are abstract presence flags.
 *   - Expiry / wall-clock: the 1h AT lifetime manifests as "minted" and
 *     never changes state (no clock in the model).
 *   - Client authentication — modeled as a closed client registry.
 *   - Issuer syntax check (RFC 6749 §5.2 invalid_request) — abstract.
 *
 * KNOWN SPEC/CODE DIVERGENCE (flagged 2026-10-13, spec-as-documented):
 *   - The one-sided sender binding (unbound client + presented proof is
 *     accepted and the confirmation carried into the token) reflects the
 *     code. The stricter posture — an unbound client MUST NOT present a
 *     proof — would be a code change in enforceSenderBinding, not a
 *     model change; the model encodes the code as implemented.
 *
 * WHEN TO UPDATE: re-verify this spec before changing
 *   server/services/token/grant_client_credentials.go or
 *   server/services/token/grants.go ( enforceSenderBinding ).
 *
 * The spec is the ground truth. Never edit it to match broken code.
 */

module clientcredentials {

  // ------------------------------------------------------------------
  // Symbolic domains
  // ------------------------------------------------------------------

  pure val MAX_IDS: int = 12          // exploration bound on minted artifacts
  pure val CLIENTS: Set[str] = Set("pub", "conf", "cred")
  pure val CLIENT_TYPES: Set[str] = Set("public", "confidential", "credentialed")
  pure val M2M_TYPES: Set[str] = Set("confidential", "credentialed")
  pure val JKTS: Set[int] = Set(0, 1, 2) // abstract DPoP key ids; 0 = no proof

  // Abstract resource registry (server/storage resource reader): the
  // registered resource indicators. Any other string is an unregistered
  // laundering attempt (invalid_target, grant_client_credentials.go:107-134).
  pure val RESOURCES: Set[str] = Set("https://api.example/", "https://rs.example.org")
  // Requestable resource/audience strings: registered ones plus an
  // attacker-controlled unregistered value.
  pure val TARGETS: Set[str] = Set("", "https://api.example/", "https://rs.example.org", "https://evil.example/")

  // Scope universe: subsets of allowed scopes plus smuggling attempts.
  pure val SCOPE_SETS: Set[Set[str]] = Set(
    Set(),
    Set("read"),
    Set("write"),
    Set("read", "write"),
    Set("admin"),            // never registered: smuggling attempt
    Set("read", "admin"),    // mixed smuggling attempt
  )

  // ------------------------------------------------------------------
  // Types
  // ------------------------------------------------------------------

  type Client = {
    grants: Set[str],        // "client_credentials" capability
    clientType: str,         // public | confidential | credentialed
    dpopBound: bool,         // DpopBoundAccessTokens policy (RFC 10027 §6.1.12)
    tlsBound: bool,          // TlsClientCertificateBoundAccessTokens (RFC 8705 §3)
    openScopes: bool,        // open-ended registration: no registered scope ⇒ unrestricted
    allowedScopes: Set[str],  // registered/default scope authority (ignored when openScopes)
  }

  type Token = {              // map presence = minted (ACTIVE)
    id: int,                  // jti; token value == id (abstract lookup key)
    kind: str,                // "access" | "refresh" (refresh is unreachable)
    client: str,              // authenticated client id
    subject: str,             // == client_id (RFC 9068 §4)
    grantId: int,             // fresh random16 per mint: own grant family
    scopes: Set[str],
    audience: str,            // effective aud (RFC 8707 §2): resource when
                              // given, else the validated audience; "" = none
    jkt: int,                 // DPoP key confirmation; 0 = no proof
    x5t: bool,                // TLS client-certificate confirmation presented
    authzDetails: bool,       // authorization_details (RFC 9396) smuggled in
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  var clients: str -> Client  // registry (static after init)
  var tokens: int -> Token     // token id -> record
  var counter: int             // fresh id source (jtis, grant ids)

  // Sentinel defaults so guarded actions never .get() a missing key.
  pure val NO_CLIENT: Client =
    { grants: Set(), clientType: "public", dpopBound: false, tlsBound: false,
      openScopes: false, allowedScopes: Set() }
  pure val NO_TOKEN: Token =
    { id: -1, kind: "access", client: "", subject: "", grantId: -1,
      scopes: Set(), audience: "", jkt: 0, x5t: false, authzDetails: false }

  // ------------------------------------------------------------------
  // Functional layer (pure)
  // ------------------------------------------------------------------

  // RFC 8707 §2 precedence: the resource indicator is the minted audience;
  // the bare audience parameter applies only when no resource was given.
  pure def effectiveAudience(resource: str, audience: str): str =
    if (resource != "") resource else audience

  pure def mkToken(id: int, client: str, grantId: int,
                   scopes: Set[str], audience: str, jkt: int, x5t: bool): Token =
    { id: id, kind: "access", client: client, subject: client,
      grantId: grantId, scopes: scopes, audience: audience,
      jkt: jkt, x5t: x5t, authzDetails: false }

  // ------------------------------------------------------------------
  // State machine (guarded actions)
  // ------------------------------------------------------------------

  action init: bool = all {
    clients' = Map(
      // public client WITHOUT the client_credentials capability:
      // exercises both the type gate and the capability gate.
      "pub" -> { grants: Set(),
                 clientType: "public",
                 dpopBound: false, tlsBound: false,
                 openScopes: false, allowedScopes: Set("read") },
      // confidential, DPoP-bound, with the capability.
      "conf" -> { grants: Set("client_credentials"),
                  clientType: "confidential",
                  dpopBound: true, tlsBound: false,
                  openScopes: false, allowedScopes: Set("read", "write") },
      // credentialed, not DPoP-bound, open-ended scope registration.
      "cred" -> { grants: Set("client_credentials"),
                  clientType: "credentialed",
                  dpopBound: false, tlsBound: false,
                  openScopes: true, allowedScopes: Set() },
    ),
    tokens' = Map(),
    counter' = 0,
  }

  // Token endpoint, client_credentials grant (grant_client_credentials.go).
  // FAITHFUL ORDERING, all guards BEFORE any effect (this grant has no
  // burn-before-check hazard — nothing is consumed). Order as in code:
  //   1. client exists (service-layer lookup; invalid_client otherwise)
  //   2. sender binding (enforceSenderBinding, ONE-SIDED as enforced):
  //      a DPoP-bound client MUST present a jkt proof; a TLS-bound
  //      client MUST present an x5t#S256; an unbound client presenting
  //      a proof anyway is accepted (confirmation carried verbatim)
  //   3. client type ∈ {confidential, credentialed} (else invalid_client)
  //   4. authorization_details == ∅ (RFC 9396 fail-closed: no consent
  //      authority exists at this grant → invalid_authorization_details)
  //   5. capability client_credentials (else unauthorized_client)
  //   6. resource singular + registered; audience registered when no
  //      resource (RFC 8707 §2.2 → invalid_target)
  //   7. requested scope ⊆ registered scope; an open-ended registration
  //      is unrestricted (grant_client_credentials.go:136-148)
  //   8. fresh ids available
  // Effect: mint exactly ONE access token. Subject == client_id, GrantId
  // is fresh (own family), no refresh token can ever appear. The minted
  // audience is the resource when given, else the validated audience.
  action mint(client: str, scopes: Set[str], resource: str, audience: str,
              proofJkt: int, proofX5t: bool, authzDetails: bool): bool = {
    val cl = if (clients.keys().contains(client)) clients.get(client) else NO_CLIENT
    val effAudience = effectiveAudience(resource, audience)
    all {
      clients.keys().contains(client),
      // enforceSenderBinding: bound ⇒ proof present (one-directional).
      not (cl.dpopBound and proofJkt == 0),
      not (cl.tlsBound and not(proofX5t)),
      M2M_TYPES.contains(cl.clientType),
      not (authzDetails),
      cl.grants.contains("client_credentials"),
      // RFC 8707 §2.2: resource singular and registered; audience
      // registered when no resource is requested.
      (resource != "" or audience == "") or RESOURCES.contains(audience),
      resource == "" or RESOURCES.contains(resource),
      // Scope containment unless the registration is open-ended.
      cl.openScopes or scopes.forall(s => cl.allowedScopes.contains(s)),
      counter < MAX_IDS,
      tokens' = tokens.put(counter,
        mkToken(counter, client, counter, scopes, effAudience, proofJkt, proofX5t)),
      clients' = clients,
      counter' = counter + 1,
    }
  }

  // Adversarial variant (integration/rfc9396_adversarial_test.go):
  // a request that smuggles authorization_details. Its guard requires
  // authzDetails ∅, so this action is DISABLED in every reachable state —
  // the fail-closed policy made structural.
  action attemptWithDetails(client: str, scopes: Set[str], resource: str,
                            audience: str, proofJkt: int, proofX5t: bool): bool =
    mint(client, scopes, resource, audience, proofJkt, proofX5t, true)

  // ------------------------------------------------------------------
  // Step (random protocol walks)
  // ------------------------------------------------------------------

  action mintStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet resource = TARGETS.oneOf()
    nondet audience = TARGETS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    nondet proofX5t = Set(true, false).oneOf()
    nondet authzDetails = Set(true, false).oneOf()
    mint(client, scopes, resource, audience, proofJkt, proofX5t, authzDetails)
  }

  action attemptWithDetailsStep: bool = {
    nondet client = CLIENTS.oneOf()
    nondet scopes = SCOPE_SETS.oneOf()
    nondet resource = TARGETS.oneOf()
    nondet audience = TARGETS.oneOf()
    nondet proofJkt = JKTS.oneOf()
    nondet proofX5t = Set(true, false).oneOf()
    attemptWithDetails(client, scopes, resource, audience, proofJkt, proofX5t)
  }

  action step: bool = any {
    mintStep,
    attemptWithDetailsStep,
  }

  // ------------------------------------------------------------------
  // Safety invariants
  // ------------------------------------------------------------------

  val allTokens: Set[Token] = tokens.keys().map(k => tokens.get(k))

  // CC1 — RFC 9396 fail-closed + scope authority: a client_credentials
  // mint NEVER carries authorization_details, and its scope is within
  // the client's registered/default scope set — unless the registration
  // is open-ended (no registered scope), which is unrestricted.
  val inv_cc1_noDetailsAndScopeContained: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      not (t.authzDetails)
      and (cl.openScopes or t.scopes.forall(s => cl.allowedScopes.contains(s)))
    })

  // CC2 — no refresh token: structurally, every token ever minted by this
  // grant is an access token; no RT can exist in any reachable state.
  val inv_cc2_noRefreshToken: bool =
    allTokens.forall(t => t.kind == "access")

  // CC3 — subject == client: the client IS the resource owner
  // (RFC 9068 §4); impersonation of another principal is impossible.
  val inv_cc3_subjectIsClient: bool =
    allTokens.forall(t => t.subject == t.client)

  // CC4 — client type & capability gating: tokens are only ever minted
  // for clients with type ∈ {confidential, credentialed} that hold the
  // client_credentials grant capability.
  val inv_cc4_m2mCapableOnly: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      M2M_TYPES.contains(cl.clientType)
      and cl.grants.contains("client_credentials")
    })

  // CC5 — sender binding respected (one-directional, as enforced by
  // grants.go enforceSenderBinding): a DPoP-bound client's tokens always
  // carry a non-empty jkt; a TLS-bound client's tokens always carry an
  // x5t confirmation. An unbound client MAY carry a presented proof
  // (passed through verbatim) — no converse is enforced by the code.
  val inv_cc5_senderBinding: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      (not(cl.dpopBound) or t.jkt != 0)
    })
  val inv_cc5b_tlsBinding: bool =
    allTokens.forall(t => {
      val cl = if (clients.keys().contains(t.client)) clients.get(t.client) else NO_CLIENT
      (not(cl.tlsBound) or t.x5t)
    })

  // CC6 — fresh grant families: GrantId = random16 per mint, so distinct
  // tokens never share a grant family.
  val inv_cc6_uniqueGrantFamilies: bool =
    not (allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id
      and t1.grantId == t2.grantId)))

  // CC7 — RFC 8707 audience authority: the minted audience is either
  // empty (none requested) or a registry-resolved resource indicator —
  // an attacker-controlled string never lands verbatim in aud.
  val inv_cc7_registeredAudience: bool =
    allTokens.forall(t => t.audience == "" or RESOURCES.contains(t.audience))

  val allInvariants: bool = all {
    inv_cc1_noDetailsAndScopeContained,
    inv_cc2_noRefreshToken,
    inv_cc3_subjectIsClient,
    inv_cc4_m2mCapableOnly,
    inv_cc5_senderBinding,
    inv_cc5b_tlsBinding,
    inv_cc6_uniqueGrantFamilies,
    inv_cc7_registeredAudience,
  }

  // ------------------------------------------------------------------
  // Witnesses (one per action — reachability / liveness-of-effect)
  // ------------------------------------------------------------------

  val w_minted: bool = allTokens.size() > 0
  val w_confDpopBoundMinted: bool =
    allTokens.exists(t => t.client == "conf" and t.jkt != 0)
  val w_credUnboundMinted: bool =
    allTokens.exists(t => t.client == "cred" and t.jkt == 0)
  val w_twoGrantsDistinctFamilies: bool =
    allTokens.exists(t1 => allTokens.exists(t2 =>
      t1.id != t2.id and t1.grantId != t2.grantId))

}
