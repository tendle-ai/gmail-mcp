"""Import the live catalog and generate independently deployable connectors."""

import argparse
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import httpx

API = "https://backend.composio.dev/api/v3.1"


def fetch_pages(client, route, params):
    items, cursor, seen = [], None, set()
    while True:
        query = dict(params)
        if cursor:
            query["cursor"] = cursor
        response = client.get(route, params=query)
        response.raise_for_status()
        data = response.json()
        items.extend(data["items"])
        cursor = data.get("next_cursor")
        if not cursor:
            return items
        if cursor in seen:
            raise ValueError("Provider repeated a pagination cursor.")
        seen.add(cursor)


def readiness(toolkit):
    if toolkit.get("is_local_toolkit"):
        return "requires_local_runtime"
    if toolkit.get("no_auth"):
        return "public_service"
    if "OAUTH2" in toolkit.get("composio_managed_auth_schemes", []):
        return "managed_oauth"
    if "OAUTH2" in toolkit.get("auth_schemes", []):
        return "custom_oauth_app_required"
    return "user_credentials_required"


def manifest(config):
    slug, name = config["slug"], config["name"]
    base = f"https://{slug}.tendle.ai"
    return {
        "schema_version": 1,
        "connector_name": name,
        "product_website": f"https://tendle.ai/connectors/{slug}",
        "description": config["description"],
        "example_prompts": config.get("example_prompts", []),
        "connector_icon": base + "/mcp/icon",
        "payments": False,
        "company": "Tendle",
        "developer": "Nathaniel Angafor",
        "your_name": "Nathaniel Angafor",
        "work_email": "nate@tendle.ai",
        "support_email_or_url": "hello@tendle.ai",
        "privacy_policy": "https://tendle.ai/privacy",
        "terms_of_service": "https://tendle.ai/tos",
        "anything_else": "Built by Tendle with Composio. Provider permissions and quotas apply. Listing generation does not establish deployment or client verification.",
        "technical_specs": {
            "protocol": "MCP",
            "transport": "Streamable HTTP",
            "endpoint": base + "/mcp",
            "docs_url": base + "/mcp/docs",
            "health_endpoint": base + "/healthz",
            "authentication": {
                "type": "none" if config.get("no_auth") else "OAuth 2.1",
                "credential": "None"
                if config.get("no_auth")
                else "Connector-scoped bearer token issued after provider connection",
                "configuration": "Use native client OAuth; Composio holds the upstream service credentials.",
                "public_operations": ["documentation", "manifest", "icon", "health"]
                + (["all tools"] if config.get("no_auth") else []),
                "note": "Never distribute the operator Composio API key.",
            },
            "discovery": {"documentation": base + "/mcp/docs", "tools": "tools/list"},
        },
    }


def generate(source, destination, toolkit, tools):
    slug = toolkit["slug"].replace("_", "-")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", slug):
        raise ValueError("Toolkit needs an explicit valid DNS slug mapping.")
    if destination.exists():
        raise ValueError(
            "Destination exists; review updates instead of overwriting a connector."
        )
    if toolkit.get("is_local_toolkit"):
        raise ValueError("Local toolkits cannot be generated as hosted connectors.")
    if not tools or len(tools) > 1000:
        raise ValueError("Choose 1 to 1000 tools for direct-tool sessions.")
    for tool in tools:
        if tool["toolkit"]["slug"].lower() != toolkit["slug"]:
            raise ValueError("Tool belongs to another toolkit.")
    destination.mkdir(parents=True)
    for filename in [
        "src",
        "tests",
        "pyproject.toml",
        "uv.lock",
        ".gitignore",
        ".env.example",
        "LICENSE",
    ]:
        path = source / filename
        if path.is_dir():
            shutil.copytree(
                path,
                destination / filename,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        elif path.exists():
            shutil.copy2(path, destination / filename)
    config = {
        "slug": slug,
        "toolkit_slug": toolkit["slug"],
        "name": toolkit["name"],
        "no_auth": toolkit.get("no_auth", False),
        "description": toolkit["meta"]["description"] + " Powered by Composio.",
        "consent_description": f"Allow the selected {toolkit['name']} tools listed in the connector documentation to act on the account you connect.",
        "usage_notes": [
            "Read the tool descriptions and required inputs before use. Follow pagination to establish coverage.",
            "Confirm externally visible changes with the user. Verify write outcomes before repeating an uncertain request.",
        ],
        "example_prompts": [],
        "tools": tools,
    }
    assets = destination / "assets"
    assets.mkdir()
    (assets / "service.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    )
    (assets / "connector.json").write_text(
        json.dumps(manifest(config), indent=2, ensure_ascii=False) + "\n"
    )
    (assets / "icon-source.json").write_text(
        json.dumps(
            {
                "url": toolkit["meta"]["logo"],
                "note": "Fetch and inspect this service logo, then save a 512x512 PNG as icon.png before publication.",
            },
            indent=2,
        )
        + "\n"
    )
    (destination / "README.md").write_text(
        f"# {toolkit['name']} MCP\n\n{config['description']}\n\n## Agent quickstart\n\n```text\nAdd {toolkit['name']} from https://{slug}.tendle.ai\n```\n\nGenerated candidate. Deployment, icon verification, provider setup and live client tests remain required.\n\n## Run locally\n\nSet the variables described in `.env.example`, then run `uv lock` followed by `uv sync --frozen` and `uv run tendle-connector`.\n\nSee `assets/service.json` for the complete selected tool schemas.\n"
    )
    project = destination / "pyproject.toml"
    text = project.read_text()
    text = re.sub(r'name = "gmail-mcp"', f'name = "{slug}-mcp"', text, count=1)
    text = re.sub(
        r'description = "Gmail MCP connector by Tendle, backed by Composio"',
        'description = "MCP connector by Tendle, backed by Composio"',
        text,
        count=1,
    )
    project.write_text(text)
    # A copied lock contains the pilot's root name. Regenerate it before release.
    (destination / "uv.lock").unlink(missing_ok=True)
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--output", type=Path, required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("toolkit")
    gen.add_argument("--output", type=Path, required=True)
    gen.add_argument("--tool", action="append")
    gen.add_argument("--source", type=Path, default=Path.cwd())
    args = parser.parse_args()
    key = os.environ.get("COMPOSIO_API_KEY")
    if not key:
        parser.error("Set COMPOSIO_API_KEY securely in the environment.")
    with httpx.Client(
        base_url=API, headers={"x-api-key": key}, timeout=45, follow_redirects=False
    ) as client:
        catalog = fetch_pages(
            client,
            "/toolkits",
            {"managed_by": "composio", "include_deprecated": "false", "limit": 1000},
        )
        if args.command == "scan":
            candidates = [
                {
                    "slug": t["slug"],
                    "service_slug": t["slug"].replace("_", "-"),
                    "name": t["name"],
                    "setup": readiness(t),
                    "tool_count": t["meta"]["tools_count"],
                    "description": t["meta"]["description"],
                    "logo": t["meta"]["logo"],
                    "status": "candidate",
                    "deployed": False,
                    "client_verified": False,
                }
                for t in catalog
            ]
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(
                    {
                        "retrieved_at": datetime.now(timezone.utc).isoformat(),
                        "count": len(candidates),
                        "connectors": candidates,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
            print(
                f"Imported {len(candidates)} candidates; no deployment or verification claims added."
            )
        else:
            toolkit = next((t for t in catalog if t["slug"] == args.toolkit), None)
            if toolkit is None:
                parser.error("Toolkit not found in the current catalog.")
            tools = fetch_pages(
                client, "/tools", {"toolkit_slug": args.toolkit, "limit": 1000}
            )
            tools = [
                t
                for t in tools
                if not t.get("is_deprecated") and "deprecated" not in t.get("tags", [])
            ]
            if args.tool:
                tools = [t for t in tools if t["slug"] in args.tool]
                if set(t["slug"] for t in tools) != set(args.tool):
                    parser.error("Some selected tools are unavailable.")
            config = generate(args.source, args.output, toolkit, tools)
            print(
                f"Generated {config['name']} with {len(tools)} tools. Provider setup and validation remain required."
            )
