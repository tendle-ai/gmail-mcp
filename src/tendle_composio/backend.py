"""Composio sessions scoped to one installation, service, and account."""

import asyncio
import hashlib
import json
import secrets

from composio import Composio, SESSION_PRESET_DIRECT_TOOLS
from composio_client import APIError


class UpstreamError(Exception):
    """Safe error with no provider response bodies or credentials."""


class Backend:
    def __init__(self, key, config):
        self.sdk = Composio(api_key=key, max_retries=0, timeout=45)
        self.config = config
        self.slug = config.get("toolkit_slug", config["slug"])
        self.schemas = {t["slug"]: t for t in config["tools"]}
        self.limit = asyncio.Semaphore(12)

    async def _run(self, function, *args, **kwargs):
        async with self.limit:
            try:
                return await asyncio.to_thread(function, *args, **kwargs)
            except APIError as exc:
                status = getattr(exc, "status_code", None)
                if status == 429:
                    raise UpstreamError(
                        "provider_rate_limited: Try again later."
                    ) from None
                if status in (401, 403):
                    raise UpstreamError(
                        "provider_authorization_failed: Reconnect or check the connector configuration."
                    ) from None
                raise UpstreamError(
                    "provider_request_failed: The operation could not be verified. Check current state before repeating a write."
                ) from None

    def _new_session(self, user_id, account_id=None):
        kwargs = {}
        if self.config.get("auth_config_id"):
            kwargs["auth_configs"] = {self.slug: self.config["auth_config_id"]}
        if account_id:
            kwargs["connected_accounts"] = {self.slug: account_id}
        return self.sdk.sessions.create(
            user_id=user_id,
            toolkits=[self.slug],
            tools={self.slug: {"enable": list(self.schemas)}},
            session_preset=SESSION_PRESET_DIRECT_TOOLS,
            manage_connections=False,
            sandbox={"enable": False},
            instant=False,
            **kwargs,
        )

    async def start(self, user_id, callback):
        def start():
            session = self._new_session(user_id)
            connection = session.authorize(self.slug, callback_url=callback)
            return {
                "session_id": session.session_id,
                "account_id": connection.id,
                "redirect_url": connection.redirect_url,
            }

        return await self._run(start)

    async def finish(self, user_id, session_id, account_id):
        def finish():
            account = self.sdk.connected_accounts.get(account_id)
            if (
                account.user_id != user_id
                or account.toolkit.slug != self.slug
                or account.status != "ACTIVE"
                or account.is_disabled
            ):
                raise UpstreamError(
                    "connection_not_active: Complete authorization for this connection."
                )
            session = self.sdk.sessions.use(session_id)
            if session.config.user_id != user_id:
                raise UpstreamError("connection_mismatch: Start a new connection.")
            session.update(connected_accounts={self.slug: [account_id]})
            self._check_schema(session_id)

        await self._run(finish)

    def _check_schema(self, session_id):
        live = self.sdk.tools.get_raw_tool_router_meta_tools(session_id=session_id)
        current = {t.slug: t for t in live}
        if set(current) != set(self.schemas):
            raise UpstreamError(
                "tool_catalog_changed: This connector needs a catalog update."
            )
        for name, expected in self.schemas.items():
            if (
                current[name].input_parameters != expected["input_parameters"]
                or current[name].version != expected["version"]
            ):
                raise UpstreamError(
                    "tool_schema_changed: This connector needs a catalog update."
                )

    async def public_grant(self, store):
        fingerprint = hashlib.sha256(
            json.dumps(self.config, sort_keys=True).encode()
        ).hexdigest()
        grant = store.get("public_session", fingerprint)
        if grant:
            await self._run(self._check_schema, grant["session_id"])
            return grant
        user_id = "tendle_public_" + secrets.token_urlsafe(24)
        session = await self._run(self._new_session, user_id)
        await self._run(self._check_schema, session.session_id)
        grant = {
            "user_id": user_id,
            "session_id": session.session_id,
            "account_id": None,
        }
        store.put("public_session", fingerprint, grant, 30 * 24 * 3600)
        return grant

    async def execute(self, grant, name, arguments):
        if name not in self.schemas:
            raise UpstreamError("tool_not_available")

        def execute():
            session = self.sdk.sessions.use(grant["session_id"])
            if session.config.user_id != grant["user_id"]:
                raise UpstreamError("connection_mismatch")
            self._check_schema(grant["session_id"])
            # No caller-controlled session, account, or Composio user identifier.
            result = session.execute(
                name, arguments=arguments, account=grant.get("account_id")
            )
            if result.error:
                raise UpstreamError(
                    "tool_execution_failed: Check the account, permissions and inputs. A write may have taken effect; verify before repeating it."
                )
            return result.data

        return await self._run(execute)

    async def close(self):
        await asyncio.to_thread(self.sdk.client.close)
