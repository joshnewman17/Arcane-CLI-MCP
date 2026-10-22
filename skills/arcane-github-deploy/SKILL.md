---
name: arcane-github-deploy
description: Deploy a GitHub repository to an Arcane environment as a GitOps-synced compose project, with the image built by GitHub Actions and pulled from GHCR. Use when the user wants to deploy, host, or run one of their GitHub repos (or a new service) through Arcane, set up Git Sync, or debug a GHCR pull that returns "denied".
---

# Deploy a GitHub repo through Arcane (GitOps + GHCR)

Tools: `arcane_environments`, `arcane_run`, `arcane_help`, `arcane_api_get` (arcane-mcp server).
Templates: `templates/` next to this file.

This pattern has GitHub Actions build the image and push it to GHCR. Arcane **Git Sync** pulls a compose file
from the repo, and the project pulls the image. Nothing is built on the Docker host. Arcane's docs don't
cover how `build:` directives work for git-synced projects, and by default a sync copies only the compose
file, so a `build: .` context isn't there.

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists, and confirm the target host with the user.
- **Secrets never pass through you.** Don't ask the user to paste tokens or keys into chat, and don't put them in `arcane_run` args (e.g. `variables create`, `repos create --token`). The user enters them in the Arcane UI.
- `needs_confirmation: true` means stop and ask. Never auto-retry with `confirm=true`.
- Pick a **new project name**. Check it doesn't collide with an existing project, and never reuse or modify an unrelated project with a similar name without asking.

## Phase 1: Repo prep (in the user's repo)
1. Add a CI workflow that tests, then builds and pushes `ghcr.io/<owner>/<repo>` (`latest` + `sha-<short>`, amd64 + arm64).
   Start from `templates/github-workflow.yml`. It uses only `GITHUB_TOKEN`.
2. Add `deploy/arcane/compose.yaml` from `templates/compose.yaml`:
   - `image: ghcr.io/<owner>/<repo>:latest`. No `build:`.
   - `env_file: .env`. The project `.env` must exist before `up`.
   - A host port that's free on the target. Check with `["containers", "list", "--all"]`, which in compact mode lists each container's `ports`. Many Unraid containers use macvlan networks (`br0.x`) and bind no host ports.
   - Named volumes for state, plus the image's own hardening (read_only, tmpfs, cap_drop) where it supports it.
3. Optional: `deploy/arcane/.env.git` with non-secret defaults (`templates/env.git`). Arcane merges it into the project `.env`, but only when it's synced, and the default sync copies just the compose file. So put defaults in compose (`${VAR:-default}`) too.
4. Validate locally with `docker compose -f deploy/arcane/compose.yaml config`, using a placeholder `.env`. Commit and push, then confirm CI is green and the image was pushed.

## Phase 2: Arcane setup (user does this in the UI; tell them exactly what to do)
The arcane-mcp key normally can't create git repos or test registries, and these steps involve credentials anyway.

1. **Customization → Git Repositories → Add Repository.** HTTPS URL, auth **HTTP (Username/Token)**. A
   fine-grained token with **Contents: Read-only** on the repo is enough. Have them click Test.
2. **Customization → Container Registries → ghcr.io.** This must be a **classic** PAT with **`read:packages`**:
   - GHCR does **not** accept fine-grained tokens.
   - A classic token with only `repo` **passes Arcane's registry Test** (login succeeds) but **fails every private pull** with `denied`.
   - Adding a scope to an existing classic token keeps its value, so nothing needs re-entering in Arcane.
   - Best practice: a separate pull-only token (`read:packages` only) for the registry entry.
   - The registry's "Repository Names" field only matters for pushing from the build page. It doesn't affect pulls.
   - "Pull usage" counts successful pulls only. Public images succeed with any token, so a non-zero count doesn't prove private access works.

## Phase 3: Deploy (through arcane-mcp)
1. Find the repo id: `["repos", "list"]`. Check for an existing sync: `["gitops", "list"]`.
2. Create the sync:
   `["gitops", "create", "--name", "<project>", "--project-name", "<project>", "--repo-id", "<id>", "--branch", "main", "--compose-path", "deploy/arcane/compose.yaml", "--auto-sync", "--interval", "5"]`
   Arcane syncs immediately and creates the project **stopped**. Check `lastSyncStatus: success` and `syncedFiles` in the result, or with `["gitops", "status", "<project>"]`.
3. **Pause for secrets.** Ask the user to open **Projects → <project> → .env** in Arcane and add the secret values. You can't read the project's compose or `.env` through MCP (`workspace cat` returns 403 "project configuration is not part of the workspace"). That's by design, so don't try to work around it.
4. Verify registry access before starting: `["images", "pull", "ghcr.io/<owner>/<repo>:latest"]`. It should finish with a digest that matches the CI run.
5. Start the project: `["projects", "up", "<project>"]`. The progress frames should end with `Container <name> Healthy` (if the image has a healthcheck) and `{"done": true}`.
6. Verify:
   - `["containers", "list", "--all", "--label", "com.docker.compose.project=<project>"]`: running, `health: healthy`, the expected port.
   - The service's own health endpoint or a smoke test from the LAN (host IP + published port).
   - `["activities", "list", "--limit", "5"]`: no failed `image_pull` / `project_deploy` entries.

## Troubleshooting `denied` on pull
- `Error response from daemon: denied` comes from **GHCR**, not Arcane. If the arcane-mcp key lacked an Arcane permission, Arcane would answer 403 before contacting the registry.
- Arcane automatically uses the stored registry credential for any `ghcr.io/...` pull, CLI and API included. To see what it sent, read Arcane's own container logs:
  find the Arcane container in `["containers", "list", "--all"]`, then
  `arcane_api_get {"path": "/api/environments/<env>/containers/<arcane-container-id>/logs/download"}`
  and look for `Docker ImagePull failed`:
  - `hasAuth=true retriedWithoutAuth=false` + `denied`: the token is valid but lacks access. Missing `read:packages`, a fine-grained token, or the wrong account.
  - `retriedWithoutAuth=true`: the credential was rejected (`unauthorized`), so Arcane retried anonymously.
  - `hasAuth=false`: no matching enabled registry entry, or it couldn't be decrypted.
- Confirm the image and tag actually exist from the CI log ("pushing manifest for ghcr.io/...:latest").
- Last resort, if the user agrees: make the GHCR package public. The repo stays private, but anyone can pull the image and read its contents.

## Other gotchas
- `projects create -f <file>` and other local-file flags are blocked through arcane-mcp. Use Git Sync instead.
- The server's `ARCANE_URL` must be the instance base URL. A URL copied from the browser (`/dashboard`) hits the web UI.
- Auto-sync redeploys after a compose change only if the project is already running. New images on the same tag are picked up by Arcane's image update checks / auto-update, not by the sync.

## Finish
- Report the project name, host:port, image digest, sync interval, and how updates flow (push → CI → GHCR → Arcane).
- Mention anything left: public exposure (reverse proxy / tunnel), and backups for named volumes.
- Suggest recording the deployment (repo, project, port, tokens' purposes and expiry dates, but **not** the token values) in the user's Obsidian homelab docs.
