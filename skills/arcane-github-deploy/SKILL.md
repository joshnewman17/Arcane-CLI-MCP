---
name: arcane-github-deploy
description: Deploy a GitHub repository to an Arcane environment as a regular compose project, with the image built by GitHub Actions and pulled from GHCR (including private images). Use when the user wants to deploy, host, or run one of their GitHub repos (or a new service) through Arcane, update such a deployment, or debug a GHCR pull that returns "denied".
---

# Deploy a GitHub repo through Arcane (CI + GHCR)

Tools: `arcane_environments`, `arcane_run`, `arcane_project_compose`, `arcane_cli_help`, `arcane_api_get` (arcane-cli-mcp server).
Templates: `templates/` next to this file.

This pattern has GitHub Actions build the image and push it to GHCR. The project is a normal Arcane
project whose compose file pulls that image, so nothing is built on the Docker host and nothing about
the deployment lives in git except the CI workflow.

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists, and confirm the target host with the user.
- **Secrets never pass through you.** Don't ask the user to paste tokens or keys into chat, and don't put them in `arcane_run` args (e.g. `variables create`). The user enters them in the Arcane UI.
- `needs_confirmation: true` means stop and ask. Never auto-retry with `confirm=true`.
- Pick a **new project name**. Check it doesn't collide with an existing project (`["projects", "list", "--all"]`), and never reuse or modify an unrelated project with a similar name without asking.

## Phase 1: Repo prep (in the user's repo)
1. Add a CI workflow that tests, then builds and pushes `ghcr.io/<owner>/<repo>` (`latest` + `sha-<short>`, amd64 + arm64).
   Start from `templates/github-workflow.yml`. It uses only `GITHUB_TOKEN`.
2. Push, then confirm CI is green and the image was pushed. The run log has "pushing manifest for ghcr.io/<owner>/<repo>:latest@sha256:...". Note the digest.

## Phase 2: Compose file (you draft it, the user pastes it)
Fill in `templates/compose.yaml`:
- `image: ghcr.io/<owner>/<repo>:latest`. No `build:`.
- `env_file: .env`. The project `.env` must exist before `up`.
- A host port that's free on the target. Check with `["containers", "list", "--all"]`, which in compact mode lists each container's `ports`. Many Unraid containers use macvlan networks (`br0.x`) and bind no host ports.
- Named volumes for state, plus the image's own hardening (read_only, tmpfs, cap_drop) where it supports it.
- Validate it locally with `docker compose -f <file> config`, using a placeholder `.env`.

Show the user the final compose file and the list of `.env` keys they need. Values stay with them.

## Phase 3: Arcane setup (user does this in the UI; tell them exactly what to do)
`projects create -f <file>` is blocked through arcane-cli-mcp because it reads a local file, and registry
credentials shouldn't pass through you. So these steps happen in the UI:

1. **Customization → Container Registries → ghcr.io** (only needed for private images). This must be a **classic** PAT with **`read:packages`**:
   - GHCR does **not** accept fine-grained tokens.
   - A classic token with only `repo` **passes Arcane's registry Test** (login succeeds) but **fails every private pull** with `denied`.
   - Adding a scope to an existing classic token keeps its value, so nothing needs re-entering in Arcane.
   - Best practice: a separate pull-only token (`read:packages` only) for the registry entry.
   - The registry's "Repository Names" field only matters for pushing from the build page. It doesn't affect pulls.
   - "Pull usage" counts successful pulls only. Public images succeed with any token, so a non-zero count doesn't prove private access works.
2. **Projects → Create:** the project name, the compose file from Phase 2, and the `.env` with the secret values.
   Creating a project needs the UI. After that, compose changes can go through `arcane_project_compose`
   (diff → user approval → `confirm=true`), while the `.env` always stays in the UI.

## Phase 4: Deploy (through arcane-cli-mcp)
1. Check the project exists: `["projects", "get", "<project>"]` (status `stopped`, `serviceCount` as expected).
2. Verify registry access before starting: `["images", "pull", "ghcr.io/<owner>/<repo>:latest"]`. It should finish with the digest from the CI run.
3. Start the project: `["projects", "up", "<project>"]`. The progress frames should end with `Container <name> Healthy` (if the image has a healthcheck) and `{"done": true}`.
4. Verify:
   - `["containers", "list", "--all", "--label", "com.docker.compose.project=<project>"]`: running, `health: healthy`, the expected port.
   - The service's own health endpoint or a smoke test from the LAN (host IP + published port).
   - `["activities", "list", "--limit", "5"]`: no failed `image_pull` / `project_deploy` entries.

## Updating later
- After CI publishes a new image: `["projects", "redeploy", "<project>"]` pulls `:latest` and recreates the container. Check the `Digest:` frame against the CI run, then re-verify as in Phase 4.
- Arcane's image-update checks flag new `latest` digests (`["containers", "updates"]`), and Arcane auto-update can redeploy automatically if the user enabled it.
- To change the compose file: read it with `arcane_project_compose {"project": "<project>"}`, write the full new
  file (show the user the returned diff, apply with `confirm=true` after they approve), then `redeploy`.
  `.env` changes are made by the user in the Arcane UI.
- If a compose save in the Arcane UI doesn't stick (e.g. a project that used to be Git-synced), check
  `["admin", "events", "list", "--all"]` for the `project.update` event: its metadata shows `composeUpdated` /
  `envUpdated`. Writing through `arcane_project_compose` works around a stuck editor.
- After an update, `["images", "prune", "--dangling"]` (needs confirm) removes the replaced image. Show its scope first, because it also removes other services' unused untagged images.

## Troubleshooting `denied` on pull
- `Error response from daemon: denied` comes from **GHCR**, not Arcane. If the arcane-cli-mcp key lacked an Arcane permission, Arcane would answer 403 before contacting the registry.
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
- You can't read a project's compose or `.env` through MCP (`workspace cat` returns 403 "project configuration is not part of the workspace"). That's by design, so don't try to work around it. Ask the user if you need to know what's in them.
- The server's `ARCANE_URL` must be the instance base URL. A URL copied from the browser (`/dashboard`) hits the web UI.

## Finish
- Report the project name, host:port, image digest, and how updates flow (push → CI → GHCR → `redeploy`).
- Mention anything left: public exposure (reverse proxy / tunnel), and backups for named volumes.
- Suggest recording the deployment (repo, project, port, tokens' purposes and expiry dates, but **not** the token values) in the user's Obsidian homelab docs.
