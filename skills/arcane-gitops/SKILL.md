---
name: arcane-gitops
description: Inspect and trigger Arcane GitOps syncs (git-backed compose projects) and follow the resulting deployment to completion. Use when the user asks to sync, deploy from git, check GitOps status, or why a git change hasn't deployed.
---

# GitOps syncs with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_help`.

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists.
- A sync deploys whatever is on the configured branch. Confirm with the user before triggering one.
- `needs_confirmation: true` means stop and ask. Never auto-retry with `confirm=true`.

## Steps
1. **List syncs.** `["gitops", "list", "--all"]`. Identify the sync the user means (by name, repo, or project).
   An empty list doesn't mean nothing is git-backed: projects can also sync their compose file from a repository
   directly. Check `["repos", "list"]` and `["projects", "get", "<project>"]`, and look for `job_run` activities like
   "Successfully synced compose file from … to project …" (`["activities", "list", "--type", "job_run", "--limit", "5"]`).
2. **Status.** `["gitops", "status", "<sync>"]`. Report the last synced commit, last result, any error, and whether the remote is ahead. `["gitops", "get", "<sync>"]` shows configuration (repo, branch, compose path).
3. **Ask** whether to sync now. Mention which project it will redeploy.
4. **Sync.** `["gitops", "sync", "<sync>"]`.
5. **Follow the activity to completion:**
   - `["activities", "list", "--limit", "10"]` to find the matching activity (type `project_deploy` / `project_redeploy` / `project_pull`, most recent).
   - Poll `["activities", "get", "<id>"]` until the status is `success`, `failed`, or `cancelled`. Space the checks out sensibly, and stop after about 15 minutes and report if it's still running.
6. **Verify.** `["gitops", "status", "<sync>"]` should show the new commit. Check the project with `["projects", "get", "<project>"]` and its containers with `["containers", "list", "--all"]`.
7. **On failure**, quote the error lines from the activity and hand off to the arcane-project-triage workflow.

## Finish
- Summarise which commit was deployed and the outcome.
- Suggest noting significant deployments or failures in the user's Obsidian homelab docs.
