<img src="assets/icon.png" width="80" height="80" alt="Gmail">

# Gmail MCP

Gmail MCP connector by Tendle, backed by Composio. Connect an individual Gmail account to search mail, inspect threads and attachments, manage drafts and labels, and send or reply to messages through an MCP agent.

[Documentation](https://gmail.tendle.ai/mcp/docs) · [Manifest](https://gmail.tendle.ai/manifest.json) · [Tendle](https://tendle.ai)

## Agent quickstart

```text
Add Gmail from https://gmail.tendle.ai
```

## Example prompts

- Find unread messages from this week and summarize what needs my attention.
- Draft a reply to the selected thread for my review.
- List my Gmail labels.

## Status

The Gmail HTTPS service is deployed. Tendle catalog publication and native client authorization are still pending verification.

## Connection

Use your agent's browser sign-in flow and select the Gmail account to connect. Users do not need a Composio key. Each installation has a separate account connection.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/mcp` | Streamable HTTP MCP with OAuth |
| `/mcp/docs` | Complete plain-text installation and tool reference |
| `/mcp/icon` | 512 by 512 PNG |
| `/manifest.json` | Tendle connector metadata |
| `/healthz` | Process health; does not prove Gmail connectivity |
| `/` | Redirect to the Tendle catalog listing |

The `gmail_get_docs` tool returns exactly the HTTP documentation. The service exposes 25 selected Gmail tools with original Composio input schemas, plus this documentation tool. See `assets/service.json` for the complete versioned selection. Sending, editing, labeling and trash operations change the connected mailbox. Permanent deletion and account-setting tools are excluded. There is no local-file attachment upload helper.

<details>
<summary>Local development and self-hosting</summary>

## Run locally

Python 3.13 or newer and uv are required.

```sh
uv sync --frozen
uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Keep that encryption key and a scoped Composio project API key in a private environment file outside this repository. Set the variables described in `.env.example` using your process manager. Use an absolute private state path. For local protocol development, `PUBLIC_URL=http://127.0.0.1:8082` is supported; production OAuth needs its final HTTPS hostname.

```sh
uv run tendle-connector
uv run pytest -q
uv run ruff check src tests
```

The process binds only to loopback. Put it behind a verified HTTPS reverse proxy with request-size and rate limits. Use one worker per encrypted SQLite state file. Back up the state and its encryption key securely; losing the key requires users to reconnect. Do not log authorization query strings, bearer tokens, tool inputs, provider responses, or mailbox contents.

</details>

## Authentication and account isolation

The connector implements OAuth authorization codes with PKCE, browser-bound consent, exact redirect validation and resource binding. Authorization codes are single-use. Access tokens last one hour; refresh tokens rotate within a 30-day installation grant. Refresh rotation invalidates earlier access tokens. `/revoke` invalidates the installation grant. Revocation does not delete the upstream Composio connection; remove provider access separately when needed.

Composio holds upstream credentials. Tendle persists encrypted client registrations, consent state and installation mappings. Bearer tokens are indexed by hashes. Tool arguments cannot choose the internal Composio user, session or connected account. Callback success is checked against the server-side connected-account owner, toolkit, active status and disabled flag before tokens are issued.

The connector checks the upstream tool names, input schemas and versions against its selected snapshot before execution. A mismatch fails closed until the operator reviews and updates the release. There are no automatic write retries. A provider timeout can leave a write uncertain; inspect the resulting state before retrying.

## Generate more connectors

The same runtime can wrap another Composio toolkit while preserving a separate hostname, account scope and repository. With the project key securely set in the environment:

```sh
uv run tendle-catalog scan --output /absolute/path/catalog.json
uv run tendle-catalog generate hackernews --output /absolute/path/hackernews-mcp
```

Use repeated `--tool TOOL_SLUG` arguments for an explicit subset. Each generated candidate includes source, tests, selected schemas and a manifest. Run `uv lock` in the new project, provide its inspected 512 by 512 service logo, configure provider authentication, and verify deployment and real client access before publishing. Local-only toolkits are rejected. Public connectors reject tools that require authentication. Catalog imports label every entry as a candidate; they do not claim that generated entries are live.

Some toolkits require a custom OAuth app or credentials from each user. Resale permission does not supply those credentials. Configure any required Composio auth config ID in `service.json`; never place its secrets there. The operator API key stays server-side.

## Project

- `src/tendle_composio/`: configurable MCP runtime, OAuth, encrypted state, Composio adapter and catalog CLI.
- `assets/`: service definition, listing metadata and icon.
- `tests/`: protocol, authorization, isolation and generator checks using test data.

<details>
<summary>Publisher and provenance</summary>

Published by Tendle. Support: hello@tendle.ai. [Privacy](https://tendle.ai/privacy) · [Terms](https://tendle.ai/tos).

The Gmail name and logo identify the upstream service. Tool schemas and descriptions originate from Composio. This connector is provided by Tendle and is not an official Google product.

</details>
