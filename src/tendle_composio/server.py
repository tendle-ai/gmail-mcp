"""One configurable service endpoint with native Composio tool schemas."""

import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.tools import Tool
from jsonschema import Draft202012Validator
from mcp.types import ToolAnnotations
from pydantic import PrivateAttr
from starlette.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)

from .auth import ConnectorOAuth
from .backend import Backend, UpstreamError
from .store import Store

ASSETS = Path(__file__).resolve().parent / "assets"
if not ASSETS.is_dir():
    ASSETS = Path(__file__).resolve().parents[2] / "assets"


class ServiceTool(Tool):
    _backend: Any = PrivateAttr()
    _auth: Any = PrivateAttr()
    _validator: Any = PrivateAttr()
    _public_grant: Any = PrivateAttr(default=None)

    def __init__(self, schema, backend, auth):
        tags = set(schema.get("tags", []))
        super().__init__(
            name=schema["slug"],
            title=schema["name"],
            description=schema["description"],
            parameters=schema["input_parameters"],
            annotations=ToolAnnotations(
                readOnlyHint="readOnlyHint" in tags,
                destructiveHint="destructiveHint" in tags,
                idempotentHint="idempotentHint" in tags,
                openWorldHint=True,
            ),
        )
        self._backend, self._auth = backend, auth
        self._validator = Draft202012Validator(self.parameters)

    async def run(self, arguments):
        token = get_access_token()
        grant = (
            self._auth.grant_for_token(token.token)
            if token and self._auth
            else self._public_grant
        )
        if not grant:
            raise ToolError(
                "authentication_required: Connect this service in your agent."
            )
        error = next(self._validator.iter_errors(arguments), None)
        if error:
            # JSON-schema error.message may contain private input values.
            raise ToolError(
                "invalid_arguments: Inputs do not match this tool's schema."
            )
        try:
            result = await self._backend.execute(grant, self.name, arguments)
        except UpstreamError as exc:
            raise ToolError(str(exc)) from None
        return self.convert_result(result)


def render_docs(config, base):
    lines = [
        f"{config['name']} MCP by Tendle",
        "",
        config["description"],
        "",
        "INSTALL",
        f"Add {config['name']} from {base}",
        f"MCP: {base}/mcp (Streamable HTTP)",
        f"Provider ID: {config['slug']}. Claim only {urlsplit(base).hostname} as api_hosts and issuer_domain.",
        "Use the client's managed OAuth registration and secure credential storage. No Composio API key or separate Tendle signup is required for users.",
        "Sign in through the browser consent flow. Each installation has a separate connection. To choose another account, reconnect and select it at the provider.",
        "Tendle tokens expire after one hour and rotate through refresh tokens for up to 30 days. After that reconnect. Revoking a token at /revoke disables its grant. Disconnect provider access in Composio or the provider to remove the upstream connection too.",
        "Composio stores and refreshes upstream credentials. Tendle stores encrypted installation mappings and hashed bearer-token references, not mailbox content. The Composio operator key never goes to the agent.",
        "",
        "USAGE",
        *config["usage_notes"],
        "Tools preserve Composio input schemas. Tool arguments cannot select another Tendle installation, Composio user, or connected account.",
        "Errors are errors, not empty results. Provider timeouts can leave writes uncertain; check the resulting state before retrying. There are no automatic write retries.",
        "Only the tools listed below are available. The connector fails closed when upstream schemas or versions differ from the published snapshot; an operator must validate and update it.",
        "",
        "TOOLS",
        f"{config['slug'].replace('-', '_')}_get_docs: returns exactly this document; no inputs.",
    ]
    if config.get("no_auth"):
        start = lines.index(
            "Use the client's managed OAuth registration and secure credential storage. No Composio API key or separate Tendle signup is required for users."
        )
        end = lines.index("USAGE")
        lines[start:end] = [
            "This service uses public data and requires no user credentials. The operator Composio key remains on the server.",
            "",
        ]
    for tool in config["tools"]:
        lines += [
            "",
            f"{tool['slug']} (version {tool['version']})",
            tool["description"],
            "Input JSON Schema:",
            json.dumps(tool["input_parameters"], indent=2, ensure_ascii=False),
        ]
    return "\n".join(lines) + "\n"


def create_app(*, config=None, base=None, store=None, backend=None, assets=None):
    assets = Path(assets or os.environ.get("CONNECTOR_ASSETS", ASSETS))
    config = config or json.loads((assets / "service.json").read_text())
    base = (
        base or os.environ.get("PUBLIC_URL", f"https://{config['slug']}.tendle.ai")
    ).rstrip("/")
    parsed = urlsplit(base)
    if (
        parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or not parsed.hostname
        or (
            parsed.scheme != "https"
            and not (
                parsed.scheme == "http"
                and parsed.hostname in ("localhost", "127.0.0.1", "::1")
            )
        )
    ):
        raise ValueError(
            "PUBLIC_URL must be a root HTTPS URL, or HTTP loopback for tests."
        )
    if not config["tools"] or len({x["slug"] for x in config["tools"]}) != len(
        config["tools"]
    ):
        raise ValueError("Tool configuration must be nonempty and unique.")
    for tool in config["tools"]:
        if tool["toolkit"]["slug"].lower() != config.get(
            "toolkit_slug", config["slug"]
        ):
            raise ValueError("Every tool must belong to this connector's toolkit.")
        if config.get("no_auth") and not tool.get("no_auth"):
            raise ValueError("Public connectors may only expose no-auth tools.")
        Draft202012Validator.check_schema(tool["input_parameters"])
    store = store or Store(
        Path(os.environ["STATE_PATH"]), os.environ["STATE_ENCRYPTION_KEY"]
    )
    backend = backend or Backend(os.environ["COMPOSIO_API_KEY"], config)
    auth = (
        None if config.get("no_auth") else ConnectorOAuth(base, config, store, backend)
    )
    mcp = FastMCP(
        config["name"],
        version="0.1.0",
        auth=auth,
        instructions=f"Read {config['slug'].replace('-', '_')}_get_docs for account setup, tool behavior and limits. Confirm intended changes with the user before writes.",
        mask_error_details=True,
    )
    docs = render_docs(config, base)

    @mcp.tool(
        name=f"{config['slug'].replace('-', '_')}_get_docs",
        annotations={"readOnlyHint": True, "openWorldHint": False},
    )
    def get_docs() -> str:
        """Get complete connection instructions, usage guidance, and current tool schemas."""
        return docs

    service_tools = []
    for schema in config["tools"]:
        tool = ServiceTool(schema, backend, auth)
        service_tools.append(tool)
        mcp.add_tool(tool)

    @mcp.custom_route("/", methods=["GET"])
    async def root(request):
        return RedirectResponse(
            f"https://tendle.ai/connectors/{config['slug']}", status_code=302
        )

    @mcp.custom_route("/mcp/docs", methods=["GET"])
    async def documentation(request):
        return PlainTextResponse(docs, headers={"Cache-Control": "no-store"})

    @mcp.custom_route("/manifest.json", methods=["GET"])
    async def manifest(request):
        return FileResponse(
            assets / "connector.json",
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @mcp.custom_route("/mcp/icon", methods=["GET"])
    async def icon(request):
        return FileResponse(assets / "icon.png", media_type="image/png")

    @mcp.custom_route("/healthz", methods=["GET"])
    async def health(request):
        return JSONResponse(
            {
                "status": "ok",
                "service": config["slug"],
                "tool_count": len(config["tools"]) + 1,
                "upstream_verified": False,
            }
        )

    app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        try:
            if config.get("no_auth"):
                grant = await backend.public_grant(store)
                for tool in service_tools:
                    tool._public_grant = grant
            async with original_lifespan(app):
                yield
        finally:
            await backend.close()

    app.router.lifespan_context = lifespan
    app.state.auth, app.state.mcp, app.state.backend = auth, mcp, backend
    return app


def main():
    os.umask(0o077)
    for logger in ("httpx", "httpx2", "composio", "composio_client"):
        logging.getLogger(logger).setLevel(logging.CRITICAL)
    uvicorn.run(
        create_app(),
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "8082")),
        access_log=False,
    )
