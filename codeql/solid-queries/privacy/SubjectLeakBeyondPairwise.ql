/**
 * @name Unmasked subject used outside token encoding
 * @description The end-user subject flows from httpkit.Subject at the
 *              presentation layer; by design it may only continue
 *              into pairwise encoding or a reactor request Subject
 *              field — every other consumer risks correlating a
 *              natural subject identifier across sectors.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id solid/subject-leak-beyond-pairwise
 * @tags privacy
 *       external/cwe/cwe-359
 *
 * solid is privacy-first (README: "the subject is referenced by a
 * jti-addressed, AS-only record and exposed as a pairwise subject
 * identifier"). OpenID pairwise subject semantics: the identifier
 * MUST differ per sector_identifier, so any use of the raw subject
 * that bypasses pairwiseEncoder.Encode before reaching logs or
 * response surfaces is a privacy degradation. This query tracks the
 * raw subject from its context read to a log or response sink that is
 * not behind the pairwise encoder.
 */

import go
import SolidModel

module SubjectLeak {
  /** A sanctioned continuation of the raw subject: the pairwise encoder input. */
  private class PairwiseBarrier extends DataFlow::Node {
    PairwiseBarrier() {
      exists(DataFlow::CallNode call |
        call.getACalleeIncludingExternals().asFunction().getName() = "Encode" and
        call.getACalleeIncludingExternals().asFunction().getPackage().getPath() =
          "zntr.io/solid/sdk/pairwise"
      |
        this = call.getArgument(1)
      )
    }
  }

  /** Any sink that emits the subject unsanitized. */
  private class LeakSink extends DataFlow::Node {
    LeakSink() {
      this instanceof SolidModel::LogSink
      or
      this instanceof SolidModel::HttpErrorSink
    }
  }

  module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
      source instanceof SolidModel::SubjectSource
    }

    predicate isSink(DataFlow::Node sink) {
      sink instanceof LeakSink
    }

    predicate isBarrier(DataFlow::Node barrier) {
      barrier instanceof PairwiseBarrier
    }
  }

  module Flow = TaintTracking::Global<Config>;
}

import SubjectLeak::Flow::PathGraph

from SubjectLeak::Flow::PathNode source, SubjectLeak::Flow::PathNode sink
where SubjectLeak::Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "The raw end-user subject reaches a log or response sink without pairwise encoding: OpenID pairwise semantics require per-sector identifiers; raw-subject persistence or emission is a privacy degradation."
