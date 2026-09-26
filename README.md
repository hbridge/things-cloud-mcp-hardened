# Things Cloud MCP

An MCP server that connects AI assistants to Things 3 via Things Cloud. This hardened fork is intended for self-hosting; connect your MCP client only to the instance you control.

## Features

- Streamable HTTP transport with OAuth 2.1 and Basic authentication
- Required single-account allowlist with credential-bound sessions and serialized operations
- 23 tools for reading and managing tasks, projects, headings, areas, tags, and checklists
- Real-time sync with Things 3 apps on Mac, iPhone, and iPad
- MCP output schemas and structured content for every tool
- Fail-closed cursor/schema validation, uncertain-write reconciliation without automatic retry, and explicit confirmation for permanent deletion

## Self-hosting

If you prefer to host your own instance:

```bash
go build -o things-mcp .
PUBLIC_BASE_URL=http://127.0.0.1:8080 \
ALLOWED_THINGS_EMAIL=you@example.com \
./things-mcp
```

The server listens on port 8080 by default (set `PORT` to override). `PUBLIC_BASE_URL` is required and must be an HTTPS origin such as `https://my-app.fly.dev` (`http://localhost` is accepted for local development). `ALLOWED_THINGS_EMAIL` is also required so this personal server cannot be used with another Things account.

Set `JWT_SECRET` for stable tokens across restarts. Things passwords stored for OAuth are encrypted with AES-GCM; set a durable high-entropy `CREDENTIALS_SECRET`, or persist the generated `DATA_DIR/credentials.key` alongside `oauth.db`. Refresh tokens are stored as hashes.

`things_diagnose` returns a redacted report to the authenticated caller. Public diagnostic links are disabled by default. To opt in, set `ENABLE_DIAGNOSTIC_SHARING=true`; redacted links remain unauthenticated and expire after seven days.

- OAuth clients (Claude.ai, ChatGPT) authenticate via the built-in OAuth 2.1 flow
- CLI clients (Claude Code, Cursor, Windsurf) use Basic auth headers

### Deploy to Fly.io

The included `Dockerfile` stores OAuth state and generated keys under `/data`. To deploy on [Fly.io](https://fly.io), create a `fly.toml` for the app and mount the volume at `/data`:

```bash
brew install flyctl
fly auth login

cp fly.toml.example fly.toml
# Replace the app name in both `app` and `PUBLIC_BASE_URL` before continuing.
fly apps create <app-name>
fly volumes create data --size 1 --region ewr
fly secrets set JWT_SECRET=$(openssl rand -hex 32)
fly secrets set CREDENTIALS_SECRET=$(openssl rand -hex 32)
fly secrets set ALLOWED_THINGS_EMAIL='you@example.com'
fly deploy
```

**Important:** The persistent volume is required. Without it, OAuth state and any generated credential-encryption key are stored on ephemeral disk. Losing the encryption key makes persisted credentials intentionally unreadable. Back up `oauth.db` and the matching key together before deployment or migration.

Do not set `PROXY_URLS` unless you deliberately trust that proxy with Things Cloud traffic. `THINGS_DEBUG` logs only request method, destination host, and response status; it never logs authorization headers, history identifiers, URLs, or bodies.

This project writes through a reverse-engineered, unofficial Things Cloud protocol. Keep a restorable Things for Mac backup and use a disposable account for write validation. Production health checks should remain read-only unless a real write is explicitly intended.

Your endpoint will normally be `https://<app-name>.fly.dev`; verify current Fly configuration and pricing before deployment.

Built with [things-cloud-sdk](https://github.com/arthursoares/things-cloud-sdk) and [mcp-go](https://github.com/mark3labs/mcp-go).
