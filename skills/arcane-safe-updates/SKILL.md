---
name: arcane-safe-updates
description: Check Docker containers managed by Arcane for newer images and update them one at a time with verification. Use when the user asks to update containers, check for image updates, or "what needs updating" on their homelab.
---

# Safe container updates with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_cli_help` (arcane-cli-mcp server).

## Ground rules
- If more than one environment might exist, call `arcane_environments` first, confirm which one with the user, and pass `env_id` on every call.
- Never bulk-update. One container per approval, one at a time.
- A result with `needs_confirmation: true` means stop and ask the user. Never retry with `confirm=true` on your own.
- If a flag is unclear, check `arcane_cli_help` instead of guessing.
- **Never update the MCP server's own deployment** (project `arcane-cli-mcp` and its tunnel container): it would drop
  this conversation's connection mid-call. Those calls return `self_target: true`. List it as "update from the Arcane
  UI" and move on. Never set `allow_self=true` yourself.
- **Don't assume anything updates itself.** A container's `autoUpdate: true` only means it's *eligible*. Whether Arcane
  actually auto-updates depends on the **Auto Update** job: check `["jobs", "list"]`. If that job is disabled or has
  `unmetPrerequisites`, nothing is updated automatically; say so.

## Steps
1. **Find updates.** `arcane_run {"args": ["containers", "updates", "--all"]}`
   (or `{"args": ["containers", "list", "--all"], "filter_has_update": true}`).
   For background, check `["jobs", "list"]` (is the Auto Update job enabled?), `["updater", "status"]` and
   `["updater", "history", "-n", "10"]`.
   Containers with `image_untagged: true` run an image Arcane only knows by its sha256 id, so they have no update
   status at all. Mention them separately rather than reporting them as up to date.
2. **Summarise** in a short table: container, current image/tag, project (if any), and a risk note. Flag as higher risk:
   - **Moving tags**: `:latest`, `:nightly`, `:dev`, `:edge`, `main-*`/`develop-*`. The update can be any amount of
     upstream change (e.g. a `mealie:nightly` update is an unreviewed snapshot). Prefer pinning a release tag.
   - **Databases** (postgres, mysql/mariadb, mongo, redis with persistence). For **postgres**, only digest or minor
     updates within the same major version (`postgres:14` → newer `14.x`) are routine. A major bump (14 → 15+) needs
     a dump/restore or `pg_upgrade` and will not start on the old data directory: never propose it as a plain
     update, warn explicitly, and suggest a backup and a separate migration plan.
   - Core infrastructure: reverse proxy, DNS, auth/SSO, tunnels, anything other services depend on.
3. **Ask** which containers to update, and in what order. Suggest leaf services first and core infrastructure (proxy, DNS, databases) last.
4. **For each approved container, one at a time:**
   1. `["containers", "update", "<name>"]` (this can take minutes while the image pulls).
   2. Verify: `["containers", "get", "<name>"]`. The state should be running, and the health should be healthy if a healthcheck exists.
   3. Check for errors: `["activities", "list", "--status", "failed", "--limit", "10"]`, and `["activities", "list", "--limit", "5"]` to see the update's own activity. Use `["activities", "get", "<id>"]` for details.
   4. Report the result. If anything failed or the container isn't healthy, **stop**, show the error, and ask how to proceed before touching the next container.
5. For containers that belong to a compose project, it's often better to update the whole stack. Offer `["projects", "upgrade", "<project>"]` or `["projects", "redeploy", "<project>"]`, but only with explicit approval for that project.

## Finish
- Summarise what was updated, what was skipped, and anything that failed.
- Suggest recording significant changes (major version bumps, failures, rollbacks) in the user's homelab notes or documentation.
