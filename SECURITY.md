# Security notes for the hardened self-hosted fork

This branch is designed for one person's Things account. It minimizes credential exposure, but it cannot make an unofficial cloud protocol or an AI client risk-free.

## Deployment requirements

- Set `PUBLIC_BASE_URL` to the exact HTTPS origin clients will use.
- Set `ALLOWED_THINGS_EMAIL` to the one account this instance may access.
- Store independent, high-entropy `JWT_SECRET` and `CREDENTIALS_SECRET` values as Fly secrets.
- Keep `/data` on a persistent volume and back up `oauth.db` together with its matching encryption secret or key.
- Leave `ENABLE_DIAGNOSTIC_SHARING=false` unless you deliberately need temporary, unauthenticated diagnostic URLs.
- Leave `PROXY_URLS` unset unless you control and trust the proxy; a proxy can observe Things Cloud traffic.

## Data handling

- The server sends Things credentials and task sync traffic only to Cultured Code's Things Cloud endpoint, unless an operator explicitly configures a proxy.
- OAuth passwords are encrypted at rest with AES-GCM. Refresh tokens are hashed at rest. Credentials necessarily exist in process memory while the service is running.
- Normal and debug logs omit credentials, authorization headers, request and response bodies, history identifiers, task titles, and bearer tokens.
- Diagnostic reports omit history identifiers and task titles. Public report persistence and the `/d/` route are disabled by default.
- The web UI's content security policy blocks automatic third-party image, script, and connection loads. Clicking an external documentation link is still an intentional navigation.

## Residual risks

- Any MCP client you authorize can read and modify the Things data exposed by these tools. Only connect clients you trust and review destructive calls.
- Dynamic OAuth client registration is public for MCP compatibility. Do not submit credentials on an authorization page naming a client you did not initiate.
- The Things Cloud protocol is reverse engineered and can change without notice. Keep a restorable Things backup.
- A process or host compromise can read live credentials from memory. Keep the Fly organization, deploy token, volume snapshots, and machine access locked down.
