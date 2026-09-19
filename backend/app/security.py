from __future__ import annotations

from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Methods that change server state. GET/HEAD/OPTIONS never do in this API, so they're not checked
# (and a CORS preflight is OPTIONS, which must stay untouched).
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None


class OriginVerificationMiddleware:
    """CSRF defense for cookie-authenticated, state-changing requests: verify *where they came from*.

    SameSite=Lax on the session cookie is not enough on its own. "Same site" ignores ports, so a
    page served from ANY other local port (another dev app, a stray static server) is same-site as
    this API, its requests carry the session cookie, and a "simple" cross-origin request -- a
    no-body POST, a form-encoded or multipart POST -- is sent without a CORS preflight. That was
    demonstrated against this API: a page on :5500 could log a signed-in user out of :5173.

    Browsers always attach an `Origin` header to a cross-origin POST (and to every same-origin
    non-GET), and page JavaScript cannot forge or remove it. So for every unsafe method:
      - Origin present  -> must be one of the allowed browser origins (the same list CORS trusts,
                           so any origin that works today keeps working) or this server's own
                           origin (e.g. the Swagger UI at /docs posting to its own API);
                           the literal "null" (sandboxed iframes, file://) is never allowed;
      - no Origin, but a Referer -> same test on the Referer's origin;
      - neither header   -> not a browser cross-site request at all (curl, the stream_simulator /
                           live_capture_feed scripts, test clients), and CSRF only exists because
                           a *browser* attaches the victim's cookie, so it is allowed through.
    """

    def __init__(self, app: ASGIApp, allowed_origins: frozenset[str]):
        self.app = app
        self.allowed_origins = allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in _UNSAFE_METHODS:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origin = headers.get("origin")
        referer = headers.get("referer")
        if origin is not None:
            source = origin
        elif referer is not None:
            source = _origin_of(referer) or referer  # unparsable Referer -> won't match -> blocked
        else:
            await self.app(scope, receive, send)
            return

        host = headers.get("host")
        own_origin = f"{scope.get('scheme', 'http')}://{host}" if host else None
        if source in self.allowed_origins or source == own_origin:
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=403,
            content={"detail": "Cross-origin request blocked: this origin isn't allowed to make state-changing requests."},
        )
        await response(scope, receive, send)


class SecurityHeadersMiddleware:
    """Adds standard hardening headers to every response.

    This is a JSON API, so its responses should never be rendered, framed, sniffed, or cached:
      - X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: no-referrer;
      - for /api/* only: a Content-Security-Policy that allows nothing (`default-src 'none'`) and
        forbids framing, plus Cache-Control: no-store (responses carry per-user data);
      - Strict-Transport-Security, only on responses actually served over HTTPS (browsers ignore
        it over plain http, and sending it there would just be noise).
    CSP is deliberately NOT applied outside /api/: FastAPI's /docs and /redoc pages load their
    JS/CSS from a CDN and a blanket 'none' policy would break them.

    Uses setdefault, so a route that sets one of these itself keeps its own value.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_api = scope["path"].startswith("/api/")
        is_https = scope.get("scheme") == "https"

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                if is_api:
                    headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
                    headers.setdefault("Cache-Control", "no-store")
                if is_https:
                    headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
