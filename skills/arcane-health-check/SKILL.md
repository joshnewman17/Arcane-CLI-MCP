---
name: arcane-health-check
description: One read-only pass over a homelab managed by Arcane - environment status, failed activities and jobs in the last 24 hours, unhealthy or stopped containers, and pending updates - summarised as a short morning report. Use when the user asks "is everything OK", for a health check, a status report, or a scheduled/morning check of their Docker hosts.
---

# Homelab health check with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_cli_help` (arcane-cli-mcp server).

## Ground rules
- **Read-only.** Make no changes. If something needs fixing, report it and name the skill that handles it
  (arcane-project-triage, arcane-safe-updates, arcane-disk-cleanup, arcane-vuln-review).
- Keep calls compact (the default). Use the server-side filters instead of pulling full lists.
- Report problems first. A healthy item is one line in the summary, not a paragraph.

## Steps
1. **Environments.** `arcane_environments`. Note any environment that isn't `online`, and skip it for the rest.
   Run steps 2-6 for each online environment, passing `env_id` (the id or the name).
2. **Failed activity, last 24h, without the noise.**
   `{"args": ["activities", "list", "--status", "failed", "--limit", "20"], "exclude_types": ["job_run", "image_update_check"]}`.
   Keep entries whose `startedAt`/`lastAt` is within 24 hours. Group repeats (compact output already folds
   consecutive duplicates into `repeated`).
3. **Jobs.** `["jobs", "list"]`. Report any job whose `lastRun.status` is `failed` or `partial`, with its message and
   `failures` (e.g. an image-update check that's `partial` because one registry denied access: name the image).
   Also list jobs that are disabled by `unmetPrerequisites` **only** where it matters for this report, chiefly
   **Auto Update** (when it's off, nothing updates automatically even though containers show `autoUpdate: true`).
4. **Containers.**
   - Unhealthy: `{"args": ["containers", "list", "--all"], "filter_state": "running"}` and pick out `health: unhealthy`
     or `health: starting` that has been starting for long.
   - Stopped unexpectedly: `{"args": ["containers", "list", "--all"], "filter_state": "exited"}`. Note which belong to a
     project whose other services are running (likely a real failure) versus whole stopped projects (likely intentional).
   - Restarting: `"filter_state": "restarting"`.
5. **Pending updates.** `{"args": ["containers", "list", "--all"], "filter_has_update": true}`. Count them and name the
   notable ones (databases, moving tags like `:latest`/`:nightly`, the reverse proxy). Mention containers with
   `image_untagged: true`: Arcane can't tell whether they're current.
6. **Arcane itself.** `["version"]`: `updateAvailable` says whether a newer Arcane release exists. (Don't use
   `system upgrade --check`; its `canUpgrade` only means the upgrade mechanism works.)

## Report
A compact report, worst first:

```
Homelab health — <date>
⚠ Needs attention
- <env>: <container> unhealthy for 3h (project <p>) → arcane-project-triage
- <env>: job "Image Update Watcher" partial: registry denied for <image>
- <env>: 2 failed deploys since 06:10 (<project>)
ℹ FYI
- 14 containers have updates (2 databases, 3 on :latest); Auto Update job is disabled
- Arcane v2.17.0, no newer release
✓ OK: 3 environments online, no other failures
```

If everything is fine, say so in two or three lines. Offer the follow-up skill for each problem rather than acting.
For a scheduled run, keep the same format so day-to-day changes stand out.
