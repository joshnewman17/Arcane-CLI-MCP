# arcane-mcp

A small, self-hosted **remote MCP server** that lets Claude manage a Docker homelab through
[Arcane](https://getarcane.app). It wraps the official `arcane-cli` (pinned and baked into the
image) instead of calling the REST API endpoint by endpoint. It exposes four generic tools, and the
safe operational workflows live in [skills](#skills).

```
Claude (claude.ai connector / Claude Code)
   │  MCP over Streamable HTTP (or stdio)
   ▼
arcane-mcp container ── Python MCP server ── policy table ── subprocess (argv list, no shell)
   │                                                         └─ arcane-cli v2.17.0
   │  HTTP(S) + X-Api-Key
   ▼
Arcane instance (LAN)
```

## Tools

| Tool | What it does |
|---|---|
| `arcane_run(args, env_id?, confirm=false, compact=true)` | Runs `arcane-cli <args> --env <id> --json`. Policy-checked. Returns `{ok, exit_code, data, stderr_tail, command}`. With `compact=true`, list commands return one short summary per item ([`compact.py`](src/arcane_mcp/compact.py)), so 85 containers come to about 18K characters instead of 197K. |
| `arcane_help(command=[])` | `arcane-cli <command> --help`, so Claude can discover flags instead of guessing. |
| `arcane_api_get(path, query?)` | Read-only `GET /api/...` escape hatch for data the CLI doesn't expose. The spec lives at `/api/openapi.json`. |
| `arcane_environments()` | `{id, name, status}` for each environment, so Claude can pick an `env_id`. |

### Safety model (enforced in code: [`policy.py`](src/arcane_mcp/policy.py))

- **Confirmation only via `confirm=true`.** `--yes`, `-y`, `--force` (and `-f` where it means force),
  `--json` and `--output` are stripped from `args`. The server appends `--json`, plus `--yes` only when
  `confirm=true`.
- **Blocked entirely, even with `confirm=true`:** `auth login/logout/refresh/password/api-keys/federated/oidc`,
  `self-update *`, `system upgrade` (but `--check` / `--status` are allowed), `generate *`,
  `admin users|roles|federated|oidc|api-keys`, `admin backups restore|recovery`, settings and
  notification-settings writes, `config set|show|init|backup`, and commands that read or write the MCP
  container's own filesystem (`images upload|export`, `* workspace download|put`,
  `volumes backups download|upload`, `templates download`).
- **Need `confirm=true`:** `projects destroy|down`, `system prune`, `system containers stop`,
  `images prune|remove`, `volumes delete|prune`, `volumes backups restore`, `containers delete|kill`,
  `networks delete|prune`, `activities clear`, `podman secrets create|update`, and any other command
  whose last word is `delete/remove/prune/destroy/clear/restore`. Without `confirm`, nothing runs and the
  result is `{ok:false, needs_confirmation:true, command}`. If the CLI itself asks for confirmation
  (`confirmation required: re-run with --yes`), the result is the same.
- **Read-only mode** (`ARCANE_MCP_READONLY=true`): an explicit allowlist of `list/get/status/updates/
  sizes/usage/history/summary/image/me/test/doctor/version/...` commands, plus `--help`.
  Anything else is denied by default.
- **Rejected flags:** `--config`/`-c` (the server owns the CLI config), `--env` (use `env_id`), and
  local-file flags (`--file`/`-f`, `--env-file`, `--dockerfile-inline`, ...). Bundled short flags
  (`-yf`) and control characters are rejected too.
- **Secrets:** the API key is written to a `0600` CLI config file on a tmpfs and passed with
  `--config`. The CLI child process gets a minimal environment (no key, no MCP token). All tool
  output and audit lines go through a redactor that removes the key, the MCP token, and anything
  shaped like `X-Api-Key:` / `Authorization:` / `apiKey`.

Note that `--force` on `containers delete` / `volumes delete` also means "remove even if running or in use".
Because it's always stripped, Claude has to stop a container before deleting it. That's deliberate.

## How the CLI is authenticated

The arcane-cli has **no documented environment variables** for the server URL or API key
([config docs](https://getarcane.app/docs/reference/cli/config)). It reads a YAML file
(`~/.config/arcanecli.yml` by default) with `server_url`, `api_key` and `default_environment`, and
takes `--config <path>`. When an `api_key` is set, the CLI ignores saved sessions and sends it as
`X-Api-Key`. At startup, arcane-mcp writes `$ARCANE_MCP_STATE_DIR/arcanecli.yml` (default
`/tmp/arcane-mcp`, a tmpfs in the compose file) from `ARCANE_URL` / `ARCANE_API_KEY` and passes
`--config` on every call.

## Configuration

| Var | Purpose | Default |
|---|---|---|
| `ARCANE_URL` | Arcane URL as seen from the container | **required** |
| `ARCANE_API_KEY` | API key for a scoped, non-admin user | **required** (or `ARCANE_API_KEY_FILE`) |
| `ARCANE_API_KEY_FILE` | Read the key from a file (Docker secret) | – |
| `ARCANE_DEFAULT_ENV` | Default environment id | `0` |
| `MCP_HOST` / `MCP_PORT` | Listen address | `0.0.0.0` / `8080` |
| `MCP_PATH` | MCP endpoint path | `/mcp` |
| `MCP_AUTH_TOKEN` | Required `Authorization: Bearer` token. A loud warning is logged if unset. | – |
| `ARCANE_MCP_READONLY` | Only allow read-only commands | `false` |
| `MAX_OUTPUT_CHARS` | Truncation limit for tool results | `40000` |
| `DEFAULT_TIMEOUT_S` / `LONG_TIMEOUT_S` | Normal / streaming-op timeouts | `120` / `1800` |
| `AUDIT_LOG_PATH` | JSONL audit log (empty disables the file; stdout always gets it) | `/data/audit.log` |
| `ARCANE_VERIFY_TLS` | TLS verification for `arcane_api_get` | `true` |
| `ARCANE_CLI_PATH` / `ARCANE_MCP_STATE_DIR` | Set by the image; override for local dev | – |

`/healthz` (unauthenticated) runs `arcane-cli doctor --json`, caches the result for 60s, and returns 200 or 503.

## 1. Create a scoped Arcane user and API key

Don't give Claude an admin key.

1. In Arcane, open **Settings → Roles & Permissions** and create a role, e.g. `claude-operator`.
   Grant it only what you want Claude to do: read access to environments, containers, projects,
   images, volumes, networks, activities and vulnerabilities, plus write access to the operations you
   want it to perform (container update/restart, project up/down/redeploy, image pull, GitOps sync,
   prune...). Leave out user, role, settings, OIDC and backup permissions.
   For a look-but-don't-touch setup, grant read-only permissions *and* set `ARCANE_MCP_READONLY=true`.
2. Create a user (e.g. `claude`) and assign it that role (optionally only on specific environments).
3. Sign in as that user, open **Settings → API Keys**, and create a key. Copy it now, because it's shown once.

   Alternative: an admin can mint a permission-scoped key directly, with no extra user. Each grant
   is `resource:action[:envId]`, and a key can't exceed its creator's permissions. Run this from your
   own machine (it's deliberately blocked through MCP):

   ```bash
   arcane-cli admin api-keys create claude-mcp --description "arcane-mcp" -p <resource:action> -p <resource:action:envId>
   ```

   Run `arcane-cli admin api-keys create --help` and `arcane-cli admin roles permissions` to see the available permission names.
4. Check it: `ARCANE_URL=... ARCANE_API_KEY=... arcane-mcp --transport stdio` and call `arcane_run`
   with `["auth","me"]`, or just watch `/healthz` after starting the container.

The Arcane role is the real security boundary. This server's policy layer is defence in depth on top of it.

## 2. Run with Docker Compose

```bash
cp .env.example .env    # fill in ARCANE_URL, ARCANE_API_KEY, MCP_AUTH_TOKEN
```

```bash
openssl rand -hex 32    # a good MCP_AUTH_TOKEN
```

```bash
mkdir -p data && sudo chown 99:100 data   # the container runs as 99:100 (Unraid nobody:users)
```

```bash
docker compose up -d --build
```

```bash
curl -s localhost:8080/healthz
```

The compose file runs the container with a read-only root filesystem, a tmpfs `/tmp` (where the CLI
config with the key lives), no capabilities, and `no-new-privileges`.

## 3. Deploy on Unraid

Either use the compose file with the Compose Manager plugin, or add a container by hand
(**Docker → Add Container**):

| Field | Value |
|---|---|
| Repository | `arcane-mcp:latest` (build it on the server: `docker build -t arcane-mcp:latest .` from a clone in `/mnt/user/appdata/arcane-mcp-src`), or your registry image |
| Network | `bridge` (or the custom network Arcane is on) |
| Port | container `8080` → host `8080` (or any free port) |
| Path | container `/data` → host `/mnt/user/appdata/arcane-mcp` (audit log) |
| Variables | `ARCANE_URL`, `ARCANE_API_KEY`, `MCP_AUTH_TOKEN`, optionally `ARCANE_DEFAULT_ENV`, `ARCANE_MCP_READONLY` |
| Extra parameters | `--read-only --tmpfs /tmp:mode=1777,size=16m --cap-drop ALL --security-opt no-new-privileges:true` |

The image runs as `99:100` (`nobody:users`), so appdata permissions work as usual. The Docker
`HEALTHCHECK` shows up as healthy/unhealthy in the Unraid UI. If Arcane runs on the same Unraid
box, `ARCANE_URL` is usually `http://<unraid-ip>:3552` (or the container name if both containers
share a custom network).

## 3b. Deploy through Arcane itself (GitOps)

[`deploy/arcane/compose.yaml`](deploy/arcane/compose.yaml) is meant for an Arcane **Git Sync (pull)**.
GitHub Actions ([`.github/workflows/image.yml`](.github/workflows/image.yml)) runs the tests and pushes
`ghcr.io/joshnewman17/arcane-mcp:latest` (amd64 + arm64) on every push to `main`. Arcane then only pulls
the image, so nothing is built on the host.

1. In Arcane, under **Customization → Git Repositories**, add this repo (HTTP auth with a token that can read it).
   Make sure the `ghcr.io` registry credential in Arcane can read this repo's package.
2. Create the sync, either in the UI or through arcane-mcp:
   `gitops create --name arcane-cli-mcp --project-name arcane-cli-mcp --repo-id <id> --branch main --compose-path deploy/arcane/compose.yaml --auto-sync --interval 5`
3. In the project's **.env** in Arcane, set `ARCANE_URL`, `ARCANE_API_KEY` and `MCP_AUTH_TOKEN`.
   Non-secret defaults come from [`deploy/arcane/.env.git`](deploy/arcane/.env.git).
4. Start the project (`projects up arcane-cli-mcp`) and check `http://<host>:8090/healthz`.

## 4. Connect Claude

### claude.ai custom connector

claude.ai connects from Anthropic's cloud, so the server must be reachable over **public HTTPS**,
e.g. through a reverse proxy (SWAG/NPM/Caddy/Traefik) or a Cloudflare Tunnel pointing at
`http://<unraid-ip>:8080`. Then **Settings → Connectors → Add custom connector** with URL
`https://mcp.example.com/mcp`.

Authentication: the server checks `Authorization: Bearer $MCP_AUTH_TOKEN`. If your client can't
send a static header, either:
- put an authenticating proxy in front (e.g. Cloudflare Access, or an OAuth proxy the connector supports), or
- as a weaker fallback, unset `MCP_AUTH_TOKEN`, set `MCP_PATH` to a long random path
  (`/mcp-3f9c...`), and only expose it over HTTPS. Uvicorn access logging is disabled, so the
  path isn't logged here, but your proxy may log it.

Never expose this server to the internet without one of these. It can stop and delete your containers.

### Claude Code (local)

Over HTTP:

```bash
claude mcp add --transport http arcane https://mcp.example.com/mcp --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

Or over stdio from a checkout (needs `arcane-cli` on PATH):

```bash
claude mcp add arcane --env ARCANE_URL=http://192.168.1.10:3552 --env ARCANE_API_KEY=arc_... --env AUDIT_LOG_PATH=./audit.log -- uv run --directory /path/to/arcane-mcp arcane-mcp --transport stdio
```

In stdio mode, logs and audit lines go to stderr so stdout stays clean for the protocol.

## Skills

[`skills/`](skills/) holds Claude skills that encode safe workflows on top of the tools:

| Skill | Use |
|---|---|
| [`arcane-safe-updates`](skills/arcane-safe-updates/SKILL.md) | Find image updates, update one container at a time, verify health + activities |
| [`arcane-project-triage`](skills/arcane-project-triage/SKILL.md) | Diagnose a broken stack, propose a fix, redeploy only after confirmation |
| [`arcane-vuln-review`](skills/arcane-vuln-review/SKILL.md) | Prioritise critical/high CVEs, recommend update/accept/ignore |
| [`arcane-disk-cleanup`](skills/arcane-disk-cleanup/SKILL.md) | Measure volumes/images before pruning anything |
| [`arcane-gitops`](skills/arcane-gitops/SKILL.md) | Inspect and trigger GitOps syncs, follow the activity to completion |
| [`arcane-github-deploy`](skills/arcane-github-deploy/SKILL.md) | Deploy a GitHub repo as a GitOps-synced project: CI builds to GHCR, Arcane pulls. Includes templates and GHCR `denied` troubleshooting |

To install them: in claude.ai, upload each folder as a zip under **Settings → Capabilities → Skills**.
In Claude Code, copy them to `~/.claude/skills/` (or a project's `.claude/skills/`).

All of them resolve `env_id` first, treat `needs_confirmation` as "stop and ask", and suggest
recording significant changes in your Obsidian homelab docs.

## Audit log

Every tool call is one JSON line on stdout and in `/data/audit.log`:

```json
{"ts":"2026-10-22T03:52:32.589+00:00","tool":"arcane_run","argv":["projects","destroy","foo","--env","0","--json"],"env_id":"0","confirm":false,"outcome":"needs_confirmation","exit_code":null,"duration_ms":0}
```

`outcome` is one of `ok`, `error`, `blocked`, `rejected` or `needs_confirmation`. The log isn't rotated,
so rotate it with logrotate or the Unraid CA tooling if it grows.

## Development and testing

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"
```

```bash
.venv/bin/pytest -q
```

The unit tests cover every blocked, confirm and read-only rule, argument sanitisation, timeout
selection, JSON parsing and truncation, `needs_confirmation` detection, API path validation, and
redaction. They mock `subprocess.run` with canned output. `tests/test_server.py` runs a real MCP
client against the server in-process, with `tests/fake_arcane_cli.py` standing in for the binary.
It covers bearer auth, `/healthz`, and the stdio transport.

Integration tests are opt-in and read-only (`doctor`, `environments list`, `containers list`, `containers updates`):

```bash
ARCANE_IT=1 ARCANE_URL=http://192.168.1.10:3552 ARCANE_API_KEY=arc_... .venv/bin/pytest -m integration
```

### MCP Inspector

stdio:

```bash
npx @modelcontextprotocol/inspector -e ARCANE_URL=http://192.168.1.10:3552 -e ARCANE_API_KEY=arc_... -e AUDIT_LOG_PATH=./audit.log .venv/bin/arcane-mcp --transport stdio
```

HTTP: start the container (or `.venv/bin/arcane-mcp`), run `npx @modelcontextprotocol/inspector`,
choose **Streamable HTTP**, URL `http://localhost:8080/mcp`, and add the header
`Authorization: Bearer <MCP_AUTH_TOKEN>`.

## Upgrading the pinned CLI

The CLI is in early development and renames flags between releases (e.g. `--env` → `--env-var`,
`--disabled` → `--enabled=false`, `templates download --output` → `--output-file`; the old names go
away in v3). To upgrade:

1. Check the [release notes](https://github.com/getarcaneapp/arcane/releases).
2. Bump `ARCANE_CLI_VERSION` in the `Dockerfile` and `docker-compose.yml`. Optionally set
   `ARCANE_CLI_SHA256` to the tarball's checksum.
3. Dump the new command tree (`arcane-cli <group> --help` for every group, or ask Claude to walk
   `arcane_help`) into `tests/fixtures/cli-commands.txt`. `test_known_commands_match_pinned_cli` fails until
   `KNOWN_COMMANDS` in `policy.py` matches it exactly.
   Review every new path: look for destructive verbs, credential- or settings-related commands (block them),
   and anything that reads a local file, whether as a flag or a positional argument (block it).
4. Update `policy.py` and the tests, run `pytest`, then push. CI publishes the image, and Arcane picks it up.

Also check the scan in Arcane afterwards (`images vulnerabilities image ghcr.io/joshnewman17/arcane-mcp:latest`).
CLI releases are the usual fix for Go standard-library CVEs, since each release is built with a newer Go.

The image downloads the release tarball (`arcane-cli_linux_<arch>.tar.gz`) directly rather than
piping `install-cli.sh` to `sh`. Current releases ship tarballs, while the install script
downloads a bare binary name.

## Known gaps

- Podman commands that take a local file (`kube play|down`, `quadlets install`) and podman secret
  create/update are blocked. Use the Arcane UI for those.
- Swarm workflows, webhook creation, and REST writes are out of scope.
- Re-check `/healthz` and a `containers list` after any CLI bump. The JSON shapes can change.
