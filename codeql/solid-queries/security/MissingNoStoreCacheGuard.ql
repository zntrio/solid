/**
 * @name Response written without the no-store cache guard
 * @description Every presentation-layer HTTP response for the OAuth
 *              protocol surface must be written through a helper that
 *              sets Cache-Control: no-store; a direct
 *              WriteHeader/Write bypass leaks token and credential
 *              responses into caches.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id solid/missing-no-store-cache-guard
 * @tags security
 *       privacy
 *       external/cwe/cwe-524
 *
 * RFC 6749 section 5.1: "The authorization server MUST include the
 * HTTP 'Cache-Control' response header field with a value of 'no-store'
 * in any response containing tokens, credentials, or other sensitive
 * information" — with Pragma: no-cache as the legacy companion.
 * solid implements this once, centrally: WithError/WithJSON in
 * server/httpkit/respond.go set both headers, and every protocol
 * handler routes through them. This query is a degradation guard:
 * a direct ResponseWriter.Write/WriteHeader call in package httpkit
 * whose enclosing function neither sets Cache-Control nor routes
 * through the guarded helpers is a cache-guard bypass.
 */

import go

from CallExpr write, FuncDef enclosing
where
  write.getEnclosingFunction() = enclosing and
  write.getCalleeName() = ["Write", "WriteHeader"] and
  write.getTarget().(Method).getReceiverType().getQualifiedName() = "net/http.ResponseWriter" and
  enclosing.getFile().getRelativePath().regexpMatch("server/httpkit/.*") and
  // The function is guarded when it routes through the central helpers
  // or sets a response header itself (any header set precedes the body
  // write in solid's helpers by construction).
  not exists(
    CallExpr guarded |
      guarded.getEnclosingFunction() = enclosing and
      (
        guarded.getCalleeName() = ["WithError", "WithJSON"] and
        guarded.getTarget().getPackage().getPath() = "zntr.io/solid/server/httpkit"
        or
        guarded.getCalleeName() = "Set"
      )
  )
select write,
  "Direct response write without the no-store guard: RFC 6749 §5.1 requires Cache-Control: no-store on every sensitive response; route through httpkit WithError/WithJSON."
