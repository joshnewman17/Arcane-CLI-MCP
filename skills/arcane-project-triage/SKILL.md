---
name: arcane-project-triage
description: Diagnose a misbehaving Docker Compose stack (Arcane "project") - work out which containers are unhealthy, why, and propose a fix. Use when the user says a service or stack is down, broken, restarting, slow, or "not working".
---

# Project (stack) triage with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_help`, `arcane_api_get` (read-only fallback).

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists.
- Triage is read-only. Make no changes until the user agrees to a specific fix.
- `needs_confirmation: true` means stop and ask. Never auto-retry with `confirm=true`.

## Steps
1. **Find the project.** `["projects", "list", "--all"]`. Match the user's description to a project name. Ask if it's ambiguous.
2. **Project details.** `["projects", "get", "<project>"]`. Note its status, services, and compose/env file locations.
3. **Container states.** `["containers", "list", "--all"]`, filtered to the project's containers (`--label com.docker.compose.project=<project>` works when the label is present). For each container that isn't running and healthy: `["containers", "get", "<name>"]`. Look at the state, exit code, restart count, health check output, and ports.
4. **Recent activity.** Start with failures and drop the routine noise (Git compose syncs fire every few minutes as
   `job_run`, image checks as `image_update_check`):
   `{"args": ["activities", "list", "--status", "failed", "--limit", "10"], "exclude_types": ["job_run", "image_update_check"]}`,
   then `{"args": ["activities", "list", "--limit", "20"], "exclude_types": ["job_run", "image_update_check"]}`.
   Compact output folds repeated entries into one with `repeated`/`firstAt`/`lastAt`. Open relevant ones with
   `["activities", "get", "<id>"]` (use `compact=false` if you need an id that was folded away).
5. **Context if needed:**
   - Compose file: `arcane_project_compose {"project": "<project>"}`. The project's `.env` isn't available through MCP; ask the user if a value matters.
   - Pending image updates: `["projects", "updates"]`.
   - **Where the compose file comes from.** A project can be synced from git in two ways, and `gitops list` only shows
     one of them. Check `["gitops", "list", "--all"]` **and** `["repos", "list"]`, plus `["projects", "get", "<project>"]`
     for a project-level repository/sync setting. If the project is git-backed, an edit made in the Arcane UI or with
     `arcane_project_compose` will be overwritten by the next sync: change the file in the repo instead.
   - Disk pressure: `["volumes", "sizes"]`, `["system", "info"]`.
   - Network problems: `["networks", "topology"]`.
6. **Diagnose.** Give the most likely cause with the evidence (quote the exact error lines), plus alternatives if it's uncertain.
7. **Propose a fix** and say exactly which command(s) you'd run, e.g. `["containers", "restart", "<name>"]`, `["projects", "restart", "<project>"]`, or `["projects", "redeploy", "<project>"]` (redeploy pulls images and recreates containers). If the fix is a compose change, write the full new file with `arcane_project_compose`: it returns a diff to show the user, and only applies with `confirm=true` after they approve. Then redeploy.
8. **Only after the user confirms**, run the fix. Redeploy can take several minutes and returns progress frames. Then re-check the container states and activities to verify the stack is healthy.

## Finish
- Summarise the root cause, the fix, and the current state.
- Suggest writing the incident (symptom, cause, fix) into the user's Obsidian homelab docs.
