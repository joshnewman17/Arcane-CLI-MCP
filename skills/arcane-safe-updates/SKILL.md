---
name: arcane-safe-updates
description: Check Docker containers managed by Arcane for newer images and update them one at a time with verification. Use when the user asks to update containers, check for image updates, or "what needs updating" on their homelab.
---

# Safe container updates with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_help` (arcane-mcp server).

## Ground rules
- If more than one environment might exist, call `arcane_environments` first, confirm which one with the user, and pass `env_id` on every call.
- Never bulk-update. One container per approval, one at a time.
- A result with `needs_confirmation: true` means stop and ask the user. Never retry with `confirm=true` on your own.
- If a flag is unclear, check `arcane_help` instead of guessing.

## Steps
1. **Find updates.** `arcane_run {"args": ["containers", "updates", "--all"]}`.
   For background, also check `["updater", "status"]` and `["updater", "history", "-n", "10"]`. If the Arcane auto-updater already handles some containers, say so.
2. **Summarise** in a short table: container, current image/tag, project (if any), and anything notable (databases, reverse proxy, auth, or anything other services depend on). Flag the risky ones.
3. **Ask** which containers to update, and in what order. Suggest leaf services first and core infrastructure (proxy, DNS, databases) last.
4. **For each approved container, one at a time:**
   1. `["containers", "update", "<name>"]` (this can take minutes while the image pulls).
   2. Verify: `["containers", "get", "<name>"]`. The state should be running, and the health should be healthy if a healthcheck exists.
   3. Check for errors: `["activities", "list", "--status", "failed", "--limit", "10"]`, and `["activities", "list", "--limit", "5"]` to see the update's own activity. Use `["activities", "get", "<id>"]` for details.
   4. Report the result. If anything failed or the container isn't healthy, **stop**, show the error, and ask how to proceed before touching the next container.
5. For containers that belong to a compose project, it's often better to update the whole stack. Offer `["projects", "upgrade", "<project>"]` or `["projects", "redeploy", "<project>"]`, but only with explicit approval for that project.

## Finish
- Summarise what was updated, what was skipped, and anything that failed.
- Suggest recording significant changes (major version bumps, failures, rollbacks) in the user's Obsidian homelab docs.
