import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from tendle_composio.backend import UpstreamError
from tendle_composio.server import create_app, render_docs
from tendle_composio.store import Store

BASE = "https://gmail.tendle.ai"
CONFIG = {
    "slug": "gmail",
    "name": "Gmail",
    "description": "Test connector",
    "consent_description": "Read test data.",
    "usage_notes": ["Follow pagination."],
    "tools": [
        {
            "slug": "GMAIL_GET_PROFILE",
            "name": "Profile",
            "description": "Read profile",
            "input_parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "version": "test",
            "tags": ["readOnlyHint"],
            "toolkit": {"slug": "gmail"},
        }
    ],
}


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.connections = {}
        self.fail = False

    async def start(self, user_id, callback):
        index = str(len(self.connections) + 1)
        self.connections["ca_" + index] = (user_id, callback)
        return {
            "account_id": "ca_" + index,
            "session_id": "s_" + index,
            "redirect_url": "https://connect.composio.dev/link/test",
        }

    async def finish(self, user_id, session_id, account_id):
        if self.fail or self.connections[account_id][0] != user_id:
            raise UpstreamError("connection_not_active")

    async def execute(self, grant, name, args):
        self.calls.append((grant, name, args))
        return {"account": grant["account_id"]}

    async def close(self):
        pass


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "state.sqlite", Fernet.generate_key().decode())
    backend = FakeBackend()
    app = create_app(
        config=CONFIG, base=BASE, store=store, backend=backend, assets=tmp_path
    )
    with TestClient(app, base_url=BASE, follow_redirects=False) as client:
        yield client, app, store, backend


def register(client, callback="https://agent.example/callback"):
    r = client.post(
        "/register",
        json={
            "redirect_uris": [callback],
            "client_name": "Test agent",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def begin(client, client_id, resource=BASE + "/mcp"):
    verifier = "a" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    r = client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": "https://agent.example/callback",
            "response_type": "code",
            "scope": "gmail:tools",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "client-state",
            "resource": resource,
        },
    )
    assert r.status_code == 302, r.text
    consent = r.headers["location"]
    page = client.get(consent)
    assert page.status_code == 200
    import re

    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
    flow = parse_qs(urlsplit(consent).query)["flow"][0]
    return flow, csrf, verifier


def authorize(client, backend, client_id):
    flow, csrf, verifier = begin(client, client_id)
    r = client.post(
        "/connect/start",
        params={"flow": flow},
        data={"csrf": csrf},
        headers={"origin": BASE},
    )
    assert r.status_code == 303, r.text
    account = next(reversed(backend.connections))
    r = client.get(
        "/auth/callback",
        params={"flow": flow, "status": "success", "connected_account_id": account},
    )
    assert r.status_code == 302, r.text
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["state"] == ["client-state"]
    return q["code"][0], verifier, flow, account


def exchange(client, cid, code, verifier):
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": cid,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://agent.example/callback",
            "resource": BASE + "/mcp",
        },
    )


def rpc(client, token, method, params=None):
    return client.post(
        "/mcp",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )


def test_public_surfaces_and_auth_required(setup):
    client, app, store, backend = setup
    assert client.get("/healthz").json()["upstream_verified"] is False
    assert client.get("/mcp/docs").text == render_docs(CONFIG, BASE)
    assert client.get("/").headers["location"] == "https://tendle.ai/connectors/gmail"
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == BASE + "/" or metadata["issuer"] == BASE
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert (
        client.get("/.well-known/oauth-protected-resource/mcp").json()["resource"]
        == BASE + "/mcp"
    )
    assert client.post("/mcp").status_code == 401


def test_pkce_replay_refresh_and_revocation(setup):
    client, app, store, backend = setup
    cid = register(client)
    code, verifier, flow, account = authorize(client, backend, cid)
    assert exchange(client, cid, code, "wrong").json()["error"] == "invalid_grant"
    response = exchange(client, cid, code, verifier)
    assert response.status_code == 200, response.text
    token = response.json()
    assert exchange(client, cid, code, verifier).json()["error"] == "invalid_grant"
    assert (
        client.get(
            "/auth/callback",
            params={"flow": flow, "status": "success", "connected_account_id": account},
        ).status_code
        == 400
    )
    r = rpc(
        client,
        token["access_token"],
        "tools/call",
        {"name": "GMAIL_GET_PROFILE", "arguments": {}},
    )
    assert r.status_code == 200, r.text
    assert "ca_1" in r.text
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": cid,
            "refresh_token": token["refresh_token"],
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert rpc(client, token["access_token"], "tools/list").status_code == 401
    assert (
        client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": cid,
                "refresh_token": token["refresh_token"],
            },
        ).json()["error"]
        == "invalid_grant"
    )
    new = refreshed.json()
    r = client.post(
        "/revoke",
        data={
            "token": new["refresh_token"],
            "client_id": cid,
            "token_type_hint": "refresh_token",
        },
    )
    assert r.status_code == 200, r.text
    assert rpc(client, new["access_token"], "tools/list").status_code == 401


def test_two_users_are_isolated_and_docs_match(setup):
    client, app, store, backend = setup
    cid = register(client)
    tokens = []
    for _ in range(2):
        code, verifier, _, _ = authorize(client, backend, cid)
        tokens.append(exchange(client, cid, code, verifier).json()["access_token"])
    for index, token in enumerate(tokens, 1):
        r = rpc(
            client, token, "tools/call", {"name": "GMAIL_GET_PROFILE", "arguments": {}}
        )
        assert f"ca_{index}" in r.text
    assert backend.calls[0][0]["user_id"] != backend.calls[1][0]["user_id"]
    r = rpc(
        client, tokens[0], "tools/call", {"name": "gmail_get_docs", "arguments": {}}
    )
    assert r.json()["result"]["content"][0]["text"] == client.get("/mcp/docs").text
    r = rpc(
        client,
        tokens[0],
        "tools/call",
        {"name": "GMAIL_GET_PROFILE", "arguments": {"account": "ca_2"}},
    )
    assert r.json()["result"]["isError"] is True
    assert len(backend.calls) == 2


def test_callback_cannot_substitute_account_or_browser(setup):
    client, app, store, backend = setup
    cid = register(client)
    flow, csrf, _ = begin(client, cid)
    assert (
        client.post(
            "/connect/start", params={"flow": flow}, data={"csrf": "bad"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/connect/start",
            params={"flow": flow},
            data={"csrf": csrf},
            headers={"origin": "https://evil.example"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/connect/start", params={"flow": flow}, data={"csrf": csrf}
        ).status_code
        == 303
    )
    assert (
        client.get(
            "/auth/callback",
            params={
                "flow": flow,
                "status": "success",
                "connected_account_id": "someone_else",
            },
        ).status_code
        == 400
    )
    client.cookies.clear()
    assert (
        client.get(
            "/auth/callback",
            params={"flow": flow, "status": "success", "connected_account_id": "ca_1"},
        ).status_code
        == 400
    )


def test_provider_must_confirm_active_connection(setup):
    client, app, store, backend = setup
    cid = register(client)
    flow, csrf, _ = begin(client, cid)
    client.post("/connect/start", params={"flow": flow}, data={"csrf": csrf})
    backend.fail = True
    r = client.get(
        "/auth/callback",
        params={"flow": flow, "status": "success", "connected_account_id": "ca_1"},
    )
    assert r.status_code == 502
    assert "location" not in r.headers


def test_client_and_audience_binding(setup):
    client, app, store, backend = setup
    c1 = register(client)
    c2 = register(client)
    code, verifier, _, _ = authorize(client, backend, c1)
    assert exchange(client, c2, code, verifier).json()["error"] == "invalid_grant"
    assert exchange(client, c1, code, verifier).status_code == 200
    verifier = "a" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    r = client.get(
        "/authorize",
        params={
            "client_id": c1,
            "redirect_uri": "https://agent.example/callback",
            "response_type": "code",
            "scope": "gmail:tools",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://other.example/mcp",
        },
    )
    assert "invalid_target" in r.headers.get("location", r.text)


def test_registration_rejects_unsafe_redirect(setup):
    client, *_ = setup
    for uri in [
        "http://evil.example/callback",
        "https://user:password@evil.example/callback",
        "https://agent.example/cb#fragment",
    ]:
        r = client.post(
            "/register",
            json={
                "redirect_uris": [uri],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert r.status_code == 400


def test_persistence_is_encrypted(setup):
    client, app, store, backend = setup
    cid = register(client)
    code, verifier, _, _ = authorize(client, backend, cid)
    token = exchange(client, cid, code, verifier).json()["access_token"]
    raw = store.path.read_bytes()
    assert token.encode() not in raw
    assert b"ca_1" not in raw
    assert b"https://agent.example" not in raw
