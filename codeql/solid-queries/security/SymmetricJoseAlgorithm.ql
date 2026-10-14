/**
 * @name Symmetric MAC algorithm offered for an asymmetric-only surface
 * @description solid enforces elliptic-curve (asymmetric) JOSE
 *              algorithms only; any use of an HSxxx (HMAC) or RSxxx
 *              (PKCS#1 v1.5) identifier on a signing, verification,
 *              or capability advertisement surface is a degradation
 *              of the cryptographic posture.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision very-high
 * @id solid/symmetric-jose-algorithm
 * @tags security
 *       external/cwe/cwe-327
 *
 * RFC 8725 section 3.1: "applications MUST NOT use insecure algorithms
 * ... and MUST NOT use non-standard or deprecated algorithms";
 * section 3.4 prefers asymmetric signatures — with symmetric MACs
 * every verifier can forge tokens (shared key), and RSASSA-PKCS1-v1_5
 * is legacy. solid pins the profile: EC / EdDSA / ML-DSA only
 * (AGENTS.md: "no HSxxx/RSxxx JOSE algorithms (elliptic curves
 * only)"). A string literal naming HS* or RS* anywhere in the sdk or
 * server packages reintroduces a forbidden primitive.
 */

import go

from StringLit bad, string alg
where
  bad.getValue().regexpMatch("(HS|RS)(256|384|512)(P)?") and
  alg = bad.getValue() and
  (
    bad.getFile().getRelativePath().matches("%sdk/%") or
    bad.getFile().getRelativePath().matches("%server/%")
  )
select bad,
    "Forbidden JOSE algorithm identifier " + alg + ": solid pins the profile to asymmetric elliptic-curve algorithms (RFC 8725 §3.1/§3.4; AGENTS.md: no HSxxx/RSxxx)."
