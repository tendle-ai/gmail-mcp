from copy import deepcopy
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from tendle_composio.backend import Backend, UpstreamError
from tendle_composio.catalog import fetch_pages, generate, readiness
from tendle_composio.server import create_app, render_docs
from tendle_composio.store import Store
from test_connector import CONFIG, FakeBackend


def backend():
    b = Backend("test-key", CONFIG)
    b.sdk = Mock()
    b.sdk.tools.get_raw_tool_router_meta_tools.return_value = [NS(**CONFIG["tools"][0])]
    session = b.sdk.sessions.use.return_value
    session.config.user_id = "user-a"
    session.config.connected_accounts = {"gmail": ["account-a"]}
    session.execute.return_value = NS(error=None, data={"ok": True})
    b.sdk.connected_accounts.get.return_value = NS(
        user_id="user-a", toolkit=NS(slug="gmail"), status="ACTIVE", is_disabled=False
    )
    return b, session


@pytest.mark.asyncio
async def test_backend_binds_user_account_and_schema():
    b, session = backend()
    grant = {"user_id": "user-a", "session_id": "session-a", "account_id": "account-a"}
    await b.finish("user-a", "session-a", "account-a")
    session.update.assert_called_once_with(connected_accounts={"gmail": ["account-a"]})
    assert await b.execute(grant, "GMAIL_GET_PROFILE", {}) == {"ok": True}
    session.execute.assert_called_once_with("GMAIL_GET_PROFILE", arguments={})
    session.execute.reset_mock()
    session.config.user_id = "user-b"
    with pytest.raises(UpstreamError, match="connection_mismatch"):
        await b.execute(grant, "GMAIL_GET_PROFILE", {})
    session.config.user_id = "user-a"
    b.sdk.tools.get_raw_tool_router_meta_tools.return_value[0].version = "changed"
    with pytest.raises(UpstreamError, match="tool_schema_changed"):
        await b.execute(grant, "GMAIL_GET_PROFILE", {})
    session.execute.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"user_id": "other"},
        {"toolkit": NS(slug="other")},
        {"status": "INITIATED"},
        {"is_disabled": True},
    ],
)
async def test_backend_rejects_unverified_account(change):
    b, session = backend()
    account = b.sdk.connected_accounts.get.return_value
    for k, v in change.items():
        setattr(account, k, v)
    with pytest.raises(UpstreamError, match="connection_not_active"):
        await b.finish("user-a", "session-a", "account-a")
    session.update.assert_not_called()


def test_public_connector_no_credentials_and_rejects_private_tools(tmp_path):
    config = deepcopy(CONFIG)
    config["no_auth"] = True
    store = Store(tmp_path / "state.sqlite", Fernet.generate_key().decode())
    fake = FakeBackend()
    with pytest.raises(ValueError, match="no-auth"):
        create_app(config=config, store=store, backend=fake)
    config["tools"][0]["no_auth"] = True

    async def public_grant(store):
        return {"user_id": "public", "session_id": "public-session", "account_id": None}

    fake.public_grant = public_grant
    app = create_app(config=config, store=store, backend=fake)
    with TestClient(app, base_url="https://gmail.tendle.ai") as client:
        result = client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "GMAIL_GET_PROFILE", "arguments": {}},
            },
        )
        assert result.status_code == 200
        assert not result.json()["result"].get("isError")
        assert fake.calls[0][0]["user_id"] == "public"
    assert render_docs(config, "https://gmail.tendle.ai").count("USAGE") == 1


def test_catalog_pagination_and_readiness():
    response = Mock()
    response.json.return_value = {"items": [], "next_cursor": "repeated"}
    client = Mock()
    client.get.return_value = response
    with pytest.raises(ValueError, match="repeated"):
        fetch_pages(client, "/toolkits", {})
    assert readiness({"no_auth": True}) == "public_service"
    assert readiness({"auth_schemes": ["OAUTH2"]}) == "custom_oauth_app_required"
    assert readiness({"composio_managed_auth_schemes": ["OAUTH2"]}) == "managed_oauth"


def test_generator_preserves_toolkit_identity_and_refuses_overwrite(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text('name = "gmail-mcp"\n')
    toolkit = {
        "slug": "some_app",
        "name": "Some App",
        "meta": {"description": "Example", "logo": "https://example.com/icon.png"},
    }
    tools = deepcopy(CONFIG["tools"])
    tools[0]["toolkit"]["slug"] = "some_app"
    dest = tmp_path / "result"
    config = generate(source, dest, toolkit, tools)
    assert config["slug"] == "some-app"
    assert config["toolkit_slug"] == "some_app"
    with pytest.raises(ValueError, match="exists"):
        generate(source, dest, toolkit, tools)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "accounts", [None, {}, {"gmail": ["other"]}, {"gmail": ["account-a", "other"]}]
)
async def test_execution_rejects_unpinned_or_different_account(accounts):
    b, session = backend()
    session.config.connected_accounts = accounts
    grant = {"user_id": "user-a", "session_id": "session-a", "account_id": "account-a"}
    with pytest.raises(UpstreamError, match="connection_mismatch"):
        await b.execute(grant, "GMAIL_GET_PROFILE", {})
    session.execute.assert_not_called()
