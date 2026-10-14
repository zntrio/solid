/**
 * @name Token value written to a log
 * @description A final token value (access, refresh, ID token value,
 *              phantom token, or sd-token disclosure) flowing into a
 *              print/log call leaks a live credential into a channel
 *              an attacker with partial system access can read.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id solid/token-value-in-log
 * @tags security
 *       privacy
 *       external/cwe/cwe-532
 *
 * RFC 9700 section 4.9.3: "The resource server MUST treat access
 * tokens like other sensitive secrets and not store or transfer them
 * in plaintext" — log files are plaintext storage; section 4.9.2
 * names "read-only access to web server logs" as an attacker
 * capability this must survive. solid's posture (COMPLIANCE_REPORT
 * §4.15.2): grant services return sanitized error chains that carry
 * the failure cause, never the submitted token value. This query
 * guards that invariant: any new data-flow path from a token value
 * field into a logging sink is a degradation.
 */

import go
import SolidModel

module TokenValueInLog {
  module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
      source instanceof SolidModel::TokenValueSource
    }

    predicate isSink(DataFlow::Node sink) {
      sink instanceof SolidModel::LogSink
    }
  }

  module Flow = TaintTracking::Global<Config>;
}

import TokenValueInLog::Flow::PathGraph

from
  TokenValueInLog::Flow::PathNode source, TokenValueInLog::Flow::PathNode sink
where TokenValueInLog::Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This log entry depends on a token value (RFC 9700 §4.9.3: tokens are sensitive secrets and must not be stored or transferred in plaintext; log files are such a channel)."
