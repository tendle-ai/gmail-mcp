"""OAuth/PKCE for MCP clients, with Composio handling provider consent."""

import html
import secrets
import time
from urllib.parse import urlencode, urlsplit

from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.middleware.client_auth import (
    AuthenticationError,
    ClientAuthenticator,
)
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    JSONResponse,
    Response,
)
from starlette.routing import Route

from .backend import UpstreamError
from .store import digest

ACCESS_TTL = 3600
GRANT_TTL = 30 * 24 * 3600
FLOW_TTL = 900


class ConnectorOAuth(OAuthProvider):
    def __init__(self, base, config, store, backend):
        self.base = base
        self.config = config
        self.store = store
        self.backend = backend
        self.scope = f"{config['slug']}:tools"
        self.resource = base + "/mcp"
        super().__init__(
            base_url=base,
            required_scopes=[self.scope],
            service_documentation_url=base + "/mcp/docs",
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[self.scope], default_scopes=[self.scope]
            ),
            revocation_options=RevocationOptions(enabled=True),
        )

    async def get_client(self, client_id):
        data = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info):
        # Native loopback callbacks are supported; hosted callbacks require HTTPS.
        for uri in client_info.redirect_uris:
            parsed = urlsplit(str(uri))
            if (
                parsed.fragment
                or parsed.username
                or parsed.password
                or not (
                    parsed.scheme == "https"
                    or (
                        parsed.scheme == "http"
                        and parsed.hostname in ("127.0.0.1", "::1", "localhost")
                    )
                )
            ):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description="Use HTTPS or a loopback callback.",
                )
        if len(client_info.redirect_uris) > 10:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Too many redirect URIs.",
            )
        self.store.put(
            "client",
            client_info.client_id,
            client_info.model_dump(mode="json"),
            365 * 24 * 3600,
        )

    async def authorize(self, client, params):
        if params.resource and params.resource != self.resource:
            raise AuthorizeError(
                error="invalid_target",
                error_description="Resource must be this connector's MCP endpoint.",
            )
        if params.scopes and set(params.scopes) != {self.scope}:
            raise AuthorizeError(
                error="invalid_scope", error_description="Unsupported connector scope."
            )
        flow = secrets.token_urlsafe(32)
        self.store.cleanup()
        self.store.put(
            "flow",
            digest(flow),
            {
                "client_id": client.client_id,
                "client_name": client.client_name or "Your MCP client",
                "params": params.model_dump(mode="json"),
                "user_id": "tendle_" + secrets.token_urlsafe(24),
                "stage": "consent",
            },
            FLOW_TTL,
        )
        return self.base + "/connect?" + urlencode({"flow": flow})

    def _flow(self, request):
        flow = request.query_params.get("flow", "")
        return flow, self.store.get("flow", digest(flow)) if flow else None

    async def consent(self, request):
        flow, record = self._flow(request)
        if not record or record["stage"] != "consent":
            return PlainTextResponse(
                "This connection link expired. Start again from your agent.", 400
            )
        cookie = "tendle_flow_" + digest(flow)[:16]
        csrf = secrets.token_urlsafe(32)
        name = html.escape(self.config["name"])
        client = html.escape(record["client_name"])
        destination = html.escape(urlsplit(record["params"]["redirect_uri"]).netloc)
        response = HTMLResponse(
            f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect {name}</title><body style="font:18px system-ui;max-width:560px;margin:12vh auto;padding:24px"><p>Tendle</p><h1>Connect {name}</h1><p><strong>{client}</strong> is requesting access to the {name} account you connect.</p><p>{html.escape(self.config["consent_description"])}</p><p>Composio stores and refreshes your service credentials. Tendle issues this agent a separate, revocable connector token. No Tendle signup is needed.</p><p>You will return to <strong>{destination}</strong>. Continue only if this is the agent you intended to connect.</p><form method="post" action="/connect/start?{html.escape(urlencode({"flow": flow}))}"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" style="font:inherit;padding:12px 18px">Continue to {name}</button></form><p><a href="/mcp/docs">Tools and connection details</a></p></body></html>'''
        )
        response.set_cookie(
            cookie,
            csrf,
            max_age=FLOW_TTL,
            secure=self.base.startswith("https:"),
            httponly=True,
            samesite="lax",
            path="/",
        )
        self._private(response)
        # no-referrer makes ordinary browser form POSTs send Origin: null.
        # Preserve the same-origin POST signal without leaking the flow URL to
        # external destinations. Redirect responses still use no-referrer.
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    async def start(self, request):
        flow, record = self._flow(request)
        form = await request.form()
        cookie = "tendle_flow_" + digest(flow)[:16]
        csrf = request.cookies.get(cookie, "")
        if (
            not record
            or record["stage"] != "consent"
            or not csrf
            or not secrets.compare_digest(str(form.get("csrf", "")), csrf)
        ):
            return PlainTextResponse(
                "Invalid or expired connection. Start again from your agent.", 400
            )
        if request.headers.get("origin") not in (None, self.base):
            return PlainTextResponse("Invalid connection origin.", 400)
        with self.store.transaction() as db:
            fresh = self.store.get("flow", digest(flow), db)
            if not fresh or fresh["stage"] != "consent":
                return PlainTextResponse("Connection already started.", 400)
            fresh["stage"] = "starting"
            fresh["browser_binding"] = digest(csrf)
            self.store.put("flow", digest(flow), fresh, FLOW_TTL, db)
        try:
            connection = await self.backend.start(
                record["user_id"],
                self.base + "/auth/callback?" + urlencode({"flow": flow}),
            )
        except UpstreamError as exc:
            return PlainTextResponse(
                str(exc) + " Start a new connection from your agent.", 502
            )
        target = urlsplit(connection["redirect_url"])
        if (
            target.scheme != "https"
            or target.hostname != "connect.composio.dev"
            or target.username
        ):
            return PlainTextResponse(
                "Unexpected authorization destination. Contact support.", 502
            )
        fresh.update(
            {
                "stage": "connecting",
                "session_id": connection["session_id"],
                "account_id": connection["account_id"],
            }
        )
        self.store.put("flow", digest(flow), fresh, FLOW_TTL)
        response = RedirectResponse(connection["redirect_url"], status_code=303)
        self._private(response)
        return response

    async def callback(self, request):
        flow, record = self._flow(request)
        cookie = "tendle_flow_" + digest(flow)[:16]
        csrf = request.cookies.get(cookie, "")
        if (
            not record
            or record["stage"] != "connecting"
            or not csrf
            or not secrets.compare_digest(digest(csrf), record["browser_binding"])
        ):
            return PlainTextResponse("Invalid or expired connection callback.", 400)
        # The URL's success flag and account identifier are not proof of ownership.
        if (
            request.query_params.get("status") != "success"
            or request.query_params.get("connected_account_id") != record["account_id"]
        ):
            return PlainTextResponse(
                "Account connection was not completed. Start again from your agent.",
                400,
            )
        try:
            await self.backend.finish(
                record["user_id"], record["session_id"], record["account_id"]
            )
        except UpstreamError as exc:
            return PlainTextResponse(str(exc), 502)
        code = secrets.token_urlsafe(32)
        params = record["params"]
        with self.store.transaction() as db:
            current = self.store.get("flow", digest(flow), db)
            if not current or current["stage"] != "connecting":
                return PlainTextResponse("Connection callback already used.", 400)
            self.store.delete("flow", digest(flow), db)
            self.store.put(
                "code",
                digest(code),
                {**record, "expires_at": time.time() + 120},
                120,
                db,
            )
        query = {"code": code}
        if params["state"] is not None:
            query["state"] = params["state"]
        target = params["redirect_uri"]
        response = RedirectResponse(
            target + ("&" if "?" in target else "?") + urlencode(query), status_code=302
        )
        response.delete_cookie(cookie, path="/")
        self._private(response)
        return response

    @staticmethod
    def _private(response):
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://connect.composio.dev https://dashboard.composio.dev; frame-ancestors 'none'; base-uri 'none'",
            }
        )

    async def load_authorization_code(self, client, authorization_code):
        record = self.store.get("code", digest(authorization_code))
        if not record or record["client_id"] != client.client_id:
            return None
        params = record["params"]
        return AuthorizationCode(
            code=authorization_code,
            scopes=[self.scope],
            expires_at=record["expires_at"],
            client_id=client.client_id,
            code_challenge=params["code_challenge"],
            redirect_uri=params["redirect_uri"],
            redirect_uri_provided_explicitly=params["redirect_uri_provided_explicitly"],
            resource=self.resource,
            subject=record["user_id"],
        )

    def _issue(self, grant_id, grant, db):
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        remaining = max(1, int(grant["expires_at"] - time.time()))
        token_record = {
            "grant_id": grant_id,
            "generation": grant["generation"],
            "client_id": grant["client_id"],
        }
        self.store.put(
            "access",
            digest(access),
            {
                **token_record,
                "expires_at": int(time.time()) + min(ACCESS_TTL, remaining),
            },
            min(ACCESS_TTL, remaining),
            db,
        )
        self.store.put("refresh", digest(refresh), token_record, remaining, db)
        self.store.put("grant", grant_id, grant, remaining, db)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=min(ACCESS_TTL, remaining),
            refresh_token=refresh,
            scope=self.scope,
        )

    async def exchange_authorization_code(self, client, authorization_code):
        with self.store.transaction() as db:
            record = self.store.get("code", digest(authorization_code.code), db)
            if not record or record["client_id"] != client.client_id:
                raise TokenError(
                    error="invalid_grant",
                    error_description="Authorization code expired or already used.",
                )
            self.store.delete("code", digest(authorization_code.code), db)
            grant = {
                k: record[k]
                for k in ("user_id", "session_id", "account_id", "client_id")
            }
            grant.update(
                {
                    "generation": 0,
                    "expires_at": time.time() + GRANT_TTL,
                    "resource": self.resource,
                }
            )
            return self._issue(secrets.token_urlsafe(24), grant, db)

    def _resolve(self, kind, token, db=None):
        record = self.store.get(kind, digest(token), db)
        grant = self.store.get("grant", record["grant_id"], db) if record else None
        if (
            not grant
            or record["generation"] != grant["generation"]
            or grant["resource"] != self.resource
        ):
            return None, None
        return record, grant

    async def load_access_token(self, token):
        record, grant = self._resolve("access", token)
        if not grant:
            return None
        return AccessToken(
            token=token,
            client_id=grant["client_id"],
            scopes=[self.scope],
            expires_at=record["expires_at"],
            resource=self.resource,
            subject=grant["user_id"],
            claims={"grant_id": record["grant_id"]},
        )

    async def load_refresh_token(self, client, refresh_token):
        record, grant = self._resolve("refresh", refresh_token)
        if not grant or grant["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=[self.scope],
            expires_at=int(grant["expires_at"]),
            resource=self.resource,
            subject=grant["user_id"],
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        with self.store.transaction() as db:
            record, grant = self._resolve("refresh", refresh_token.token, db)
            if (
                not grant
                or grant["client_id"] != client.client_id
                or set(scopes) != {self.scope}
            ):
                raise TokenError(
                    error="invalid_grant",
                    error_description="Refresh token expired or already used.",
                )
            self.store.delete("refresh", digest(refresh_token.token), db)
            grant["generation"] += 1
            return self._issue(record["grant_id"], grant, db)

    async def revoke_token(self, token):
        with self.store.transaction() as db:
            for kind in ("access", "refresh"):
                record = self.store.get(kind, digest(token.token), db)
                if record:
                    self.store.delete("grant", record["grant_id"], db)

    def grant_for_token(self, token):
        _, grant = self._resolve("access", token)
        return grant

    async def revoke_request(self, request):
        # MCP 2.2's revocation model requires client_secret even for public
        # clients. Keep standard client authentication, but permit its omission.
        try:
            client = await ClientAuthenticator(self).authenticate_request(request)
        except AuthenticationError:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        form = await request.form()
        token = form.get("token")
        if not isinstance(token, str) or not token:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        with self.store.transaction() as db:
            for kind in ("access", "refresh"):
                record = self.store.get(kind, digest(token), db)
                if record and record["client_id"] == client.client_id:
                    self.store.delete("grant", record["grant_id"], db)
        return Response(status_code=200, headers={"Cache-Control": "no-store"})

    def get_routes(self, mcp_path=None):
        routes = super().get_routes(mcp_path)
        metadata = build_metadata(
            self.base_url,
            self.service_documentation_url,
            self.client_registration_options,
            self.revocation_options,
        )
        metadata.issuer = self.issuer_url
        metadata.token_endpoint_auth_methods_supported = [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ]
        metadata.revocation_endpoint_auth_methods_supported = [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ]
        return [
            *[
                r
                for r in routes
                if r.path not in ("/revoke", "/.well-known/oauth-authorization-server")
            ],
            Route(
                "/.well-known/oauth-authorization-server",
                cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            ),
            Route(
                "/revoke",
                cors_middleware(self.revoke_request, ["POST", "OPTIONS"]),
                methods=["POST", "OPTIONS"],
            ),
            Route("/connect", self.consent),
            Route("/connect/start", self.start, methods=["POST"]),
            Route("/auth/callback", self.callback),
        ]
