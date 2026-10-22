---
name: arcane-disk-cleanup
description: Free disk space on Docker hosts managed by Arcane by measuring volumes and images first, then pruning only what the user approves. Use when the user mentions low disk space, cleanup, pruning, or unused images/volumes.
---

# Disk cleanup with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_help`.

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists.
- Measure before removing anything. Deleted volume data can't be recovered.
- Every prune or delete returns `needs_confirmation: true` first. Show the user what it will remove and wait for an explicit yes before retrying with `confirm=true`.
- Never pass `--remove-volumes` to `projects destroy` without explicit approval naming the volumes. Data in volumes is usually the thing the user cares about most.

## Steps
1. **Measure.**
   - `["system", "info"]` for host disk and Docker usage, if available.
   - `["volumes", "sizes"]` to find the largest volumes.
   - `["images", "list", "--all"]` and `["images", "counts"]` for images. Note dangling or unused images.
2. **Check before touching volumes.** For every volume you might suggest removing: `["volumes", "usage", "<volume>"]` to see which containers use it. If it's in use, or its name suggests real data (db, postgres, media, config, data), recommend keeping it.
3. **Present options** with the expected impact, smallest risk first:
   1. `["images", "prune", "--dangling"]`: dangling images only (safest).
   2. `["images", "prune"]`: all unused images. They'll be re-pulled when needed.
   3. `["networks", "prune"]`: unused networks.
   4. `["volumes", "delete", "<volume>"]` for specific unused volumes the user names.
   5. `["volumes", "prune"]`: all unused volumes. Warn clearly that this deletes data.
   6. `["system", "prune"]`: broad cleanup (unused containers, images, networks, build cache).
4. **Run only what the user approves**, one command at a time. When you get `needs_confirmation`, restate the exact command and impact, and ask again if the earlier approval wasn't for exactly that command.
5. **Re-measure** with `["volumes", "sizes"]` / `["system", "info"]` and report the space reclaimed.

## Finish
- Summarise what was removed and how much space was freed.
- Suggest noting any removed volumes or projects in the user's Obsidian homelab docs.
