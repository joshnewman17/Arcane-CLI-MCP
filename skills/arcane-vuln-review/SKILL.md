---
name: arcane-vuln-review
description: Review container image vulnerabilities reported by Arcane, prioritise critical and high CVEs, and recommend updating, accepting, or ignoring each one. Use when the user asks about CVEs, image security, vulnerability scans, or "is anything vulnerable".
---

# Vulnerability review with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_help`.

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists.
- Only call `images vulnerabilities ignore` after the user explicitly approves that specific CVE, and always record their reason.
- `needs_confirmation: true` means stop and ask. Never auto-retry with `confirm=true`.

## Steps
1. **Overview.** `["images", "vulnerabilities", "summary"]`. Expect big totals on a homelab (hundreds of criticals,
   thousands of highs across dozens of images); the totals alone aren't actionable, so don't lead with them.
   Note how many images are **not scanned** and say so. Check `["images", "vulnerabilities", "status"]` if results look
   stale, and offer a scan of specific images with `["images", "vulnerabilities", "scan", "<image>"]` (slow).
2. **Rank by image, running first.** Get the running containers with
   `{"args": ["containers", "list", "--all"], "filter_state": "running"}` and the per-image counts from
   `["images", "list", "--all"]` (compact shows `vulns: {critical, high}`). Rank images that back a **running**
   container first, by critical then high count; unused images come last (removing them is often the fix, see the
   arcane-disk-cleanup workflow). If the API exposes CISA KEV or EPSS data (the "Vulnerability Risk" job refreshes
   it), rank known-exploited (KEV) and high-EPSS CVEs above raw counts; check with `arcane_api_get` on
   `/api/openapi.json` for vulnerability/risk paths before assuming it's missing.
   Show a short table: image, critical, high, KEV (if known), and which running containers or projects use it.
   Cap the drill-down at the top 5 or so images unless the user wants more.
3. **Drill in** for each image with critical/high findings: `["images", "vulnerabilities", "image", "<image>", "--severity", "critical,high", "--all"]`. For each CVE note the package, installed version, fixed version (if any), and whether a fix exists.
4. **Recommend an action per CVE (or group):**
   - **Update image.** A fixed version exists, or the upstream image has a newer tag. Check `["containers", "updates"]` / `["images", "updates", "summary"]`. Hand off to the arcane-safe-updates workflow.
   - **Patch in place.** Arcane has an "Image Auto Patch" job (Copacetic) for fixable OS-package CVEs. Check
     `["jobs", "list"]`: if it's disabled (`unmetPrerequisites`), mention it as an option the user can enable in
     Settings → Security. Don't try to enable it.
   - **Accept / monitor.** No fix yet, or low real-world exposure (e.g. the vulnerable package isn't reachable, or the service is LAN-only). Explain why.
   - **Ignore.** A false positive or accepted risk, and only on request. Show the exact command first:
     `["images", "vulnerabilities", "ignore", "<CVE>", "--image", "<image>", "--package", "<pkg>", "--version", "<ver>", "--reason", "<user's reason>"]`
     Run it only after the user approves that command and gives the reason.
5. Show already-ignored items with `["images", "vulnerabilities", "ignored"]` if the user asks. `unignore` reverses an ignore.

## Finish
- Summarise: images reviewed, CVEs by action, and what was ignored (with reasons).
- Suggest recording accepted risks and ignore decisions in the user's Obsidian homelab docs so they can be revisited.
