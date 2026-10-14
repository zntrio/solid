/**
 * @name Token value written into an error response body
 * @description A final token value flowing into the WithError helper
 *              would reflect a live credential (or phantom token) to
 *              the protocol caller in an error body.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id solid/token-value-in-error-response
 * @tags security
 *       privacy
 *       external/cwe/cwe-200
 *
 * RFC 6749 section 5.2: the error response carries error,
 * error_description and error_uri — never credentials. solid's
 * token-endpoint response builder (writeTokenResponse) is the only
 * sanctioned surface for token values, and introspection strips
 * Disclosures (draft-forten sd-jwt-at: "introspection responses MUST
 * NOT carry them"). This query flags any new path that reaches the
 * generic WithError helper with a token value.
 */

import go
import SolidModel

module TokenValueInErrorResponse {
  module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
      source instanceof SolidModel::TokenValueSource
    }

    predicate isSink(DataFlow::Node sink) {
      sink instanceof SolidModel::HttpErrorSink
    }
  }

  module Flow = TaintTracking::Global<Config>;
}

import TokenValueInErrorResponse::Flow::PathGraph

from
  TokenValueInErrorResponse::Flow::PathNode source,
  TokenValueInErrorResponse::Flow::PathNode sink
where TokenValueInErrorResponse::Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This HTTP response depends on a token value: error/introspection surfaces must not reflect credentials (RFC 6749 §5.2; draft-forten sd-jwt-at introspection MUST NOT carry disclosures)."
