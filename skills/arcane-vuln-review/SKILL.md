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
1. **Overview.** `["images", "vulnerabilities", "summary"]`. If results look stale or missing, check `["images", "vulnerabilities", "status"]`. Offer a fresh scan of specific images with `["images", "vulnerabilities", "scan", "<image>"]`, which can be slow.
2. **Rank images** by critical count, then high count. Show a short table: image, critical, high, and which containers or projects use it (`["containers", "list", "--all"]`).
3. **Drill in** for each image with critical/high findings: `["images", "vulnerabilities", "image", "<image>", "--severity", "critical,high", "--all"]`. For each CVE note the package, installed version, fixed version (if any), and whether a fix exists.
4. **Recommend an action per CVE (or group):**
   - **Update image.** A fixed version exists, or the upstream image has a newer tag. Check `["containers", "updates"]` / `["images", "updates", "summary"]`. Hand off to the arcane-safe-updates workflow.
   - **Accept / monitor.** No fix yet, or low real-world exposure (e.g. the vulnerable package isn't reachable, or the service is LAN-only). Explain why.
   - **Ignore.** A false positive or accepted risk, and only on request. Show the exact command first:
     `["images", "vulnerabilities", "ignore", "<CVE>", "--image", "<image>", "--package", "<pkg>", "--version", "<ver>", "--reason", "<user's reason>"]`
     Run it only after the user approves that command and gives the reason.
5. Show already-ignored items with `["images", "vulnerabilities", "ignored"]` if the user asks. `unignore` reverses an ignore.

## Finish
- Summarise: images reviewed, CVEs by action, and what was ignored (with reasons).
- Suggest recording accepted risks and ignore decisions in the user's Obsidian homelab docs so they can be revisited.
