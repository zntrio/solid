/**
 * Provides the shared modeling of solid's protocol surfaces: the token
 * value objects that flow through grant services and presentation
 * layers, and the log sinks that RFC 9700 section 4.9.3 / RFC 6819
 * section 4.5.2.1 treat as an attacker-readable channel.
 *
 * Generated code (protobuf .pb.go, mock directories) is out of scope
 * everywhere: it is regenerated, never hand-edited, and its findings
 * cannot be actioned.
 */

import go

module SolidModel {
  /** A hand-written file in the solid module (not generated, not mock). */
  predicate isHandWritten(File f) {
    not f.getRelativePath().regexpMatch("api/.*\\.pb\\.go") and
    not f.getRelativePath().regexpMatch(".*/mock/.*")
  }

  /** A use of a string value that came from a token's final value. */
  abstract class TokenValueSource extends DataFlow::Node { }

  /** A read of the Value field on the tokenv1.Token protobuf struct. */
  private class TokenFieldValueRead extends TokenValueSource {
    Field f;

    TokenFieldValueRead() {
      f.hasQualifiedName("zntr.io/solid/api/oidc/token/v1", "Token", "Value") and
      this = f.getARead() and
      isHandWritten(this.asExpr().getFile())
    }
  }

  /** A read of the Phantom field (HPKE phantom token value). */
  private class TokenPhantomRead extends TokenValueSource {
    Field f;

    TokenPhantomRead() {
      f.hasQualifiedName("zntr.io/solid/api/oidc/token/v1", "Token", "Phantom") and
      this = f.getARead() and
      isHandWritten(this.asExpr().getFile())
    }
  }

  /** A read of a token Disclosures slice (draft-forten sd-jwt-at values). */
  private class TokenDisclosuresRead extends TokenValueSource {
    Field f;

    TokenDisclosuresRead() {
      f.hasQualifiedName("zntr.io/solid/api/oidc/token/v1", "Token", "Disclosures") and
      this = f.getARead() and
      isHandWritten(this.asExpr().getFile())
    }
  }

  /**
   * A logging sink: a Print/Println/Printf call from the fmt or log
   * package in a hand-written file. Generated protobuf String() methods
   * print struct contents through fmt; that is debug tooling, not a
   * log channel.
   */
  class LogSink extends DataFlow::Node {
    DataFlow::CallNode call;

    LogSink() {
      call.getACalleeIncludingExternals().asFunction().getPackage().getPath() = ["fmt", "log"] and
      call.getACalleeIncludingExternals().getName() = ["Print", "Println", "Printf"] and
      isHandWritten(call.asExpr().getFile()) and
      this = call.getAnArgument()
    }
  }

  /**
   * A write to an HTTP error body via the WithError helper. The
   * token-response builder (writeTokenResponse in server/httpkit)
   * is the sanctioned surface for token values; error bodies must
   * never carry them.
   */
  class HttpErrorSink extends DataFlow::Node {
    HttpErrorSink() {
      exists(DataFlow::CallNode call |
        call.getACalleeIncludingExternals().asFunction().getPackage().getPath() =
          "zntr.io/solid/server/httpkit" and
        call.getACalleeIncludingExternals().getName() = "WithError"
      |
        this = call.getAnArgument()
      )
    }
  }

  /**
   * A context-source read that carries the end-user subject: the
   * httpkit.Subject lookup is the single sanctioned subject accessor in
   * the presentation layer.
   */
  class SubjectSource extends DataFlow::Node {
    SubjectSource() {
      exists(DataFlow::CallNode call |
        call.getACalleeIncludingExternals().asFunction().getPackage().getPath() =
          "zntr.io/solid/server/httpkit" and
        call.getACalleeIncludingExternals().getName() = "Subject"
      |
        // Subject(ctx) returns (string, bool): each tuple element is a
        // distinct result node; taint enters at the string element.
        this = call.getAResult()
      )
    }
  }
}
