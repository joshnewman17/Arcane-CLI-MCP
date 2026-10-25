---
name: arcane-disk-cleanup
description: Free disk space on Docker hosts managed by Arcane by measuring volumes and images first, then pruning only what the user approves. Use when the user mentions low disk space, cleanup, pruning, or unused images/volumes.
---

# Disk cleanup with Arcane

Tools: `arcane_environments`, `arcane_run`, `arcane_cli_help`.

## Ground rules
- Resolve `env_id` first with `arcane_environments` when more than one environment exists.
- Measure before removing anything. Deleted volume data can't be recovered.
- Every prune or delete returns `needs_confirmation: true` first. Show the user what it will remove and wait for an explicit yes before retrying with `confirm=true`.
- Never pass `--remove-volumes` to `projects destroy` without explicit approval naming the volumes. Data in volumes is usually the thing the user cares about most.
- Stopped and "Created" containers are **candidates for review, never for automatic removal**. A leftover `Created`
  container next to a running project of the same name (e.g. an old `LiteLLM` beside the running `litellm` project)
  is a likely duplicate, but list it and let the user decide.
- Leave the MCP server's own project (`arcane-cli-mcp`) and its volumes alone.

## Steps
1. **Measure.**
   - `["system", "info"]` for host disk and Docker usage, if available.
   - `["volumes", "sizes"]` (compact): a `summary` (`total`, `anonymous_count`, `unreferenced_count`,
     `unreferenced_size`, `zero_size_count`, `anonymous_unreferenced_empty`), then the largest `named` and `anonymous`
     volumes with human-readable sizes and `refCount`. `refCount: 0` means no container uses it.
   - `{"args": ["containers", "list", "--all"], "filter_state": "exited"}` and again with `"filter_state": "created"`
     for stopped containers (they keep their anonymous volumes referenced).
   - `["images", "list", "--all"]` and `["images", "counts"]` for images. Note dangling or unused images.
2. **Check before touching volumes.** For every volume you might suggest removing: `["volumes", "usage", "<volume>"]` to see which containers use it. If it's in use, or its name suggests real data (db, postgres, media, config, data), recommend keeping it.
3. **Present volumes the right way:**
   - **Named volumes with `refCount: 0`**: one line each with name and size (e.g. a 1.3 GB `*_shared_volume` nobody
     uses). Each is its own decision; the name often tells you whose data it was.
   - **Anonymous (64-hex) volumes that are empty and unreferenced**: group them as one proposal, "prune N empty
     anonymous volumes (0 B)". Don't list the hashes.
   - Non-empty anonymous volumes: list the few largest with size; they're usually caches or a removed container's data.
   - Large volumes that are in use (e.g. a scanner's cache) are not cleanup candidates; mention them only as context.
4. **Present options** with the expected impact, smallest risk first:
   1. `["images", "prune", "--dangling"]`: dangling images only (safest).
   2. `["images", "prune"]`: all unused images. They'll be re-pulled when needed.
   3. `["networks", "prune"]`: unused networks.
   4. `["volumes", "delete", "<volume>"]` for specific unused volumes the user names.
   5. `["volumes", "prune"]`: all unused volumes. Warn clearly that this deletes data.
   6. `["system", "prune"]`: broad cleanup (unused containers, images, networks, build cache).
5. **Run only what the user approves**, one command at a time. When you get `needs_confirmation`, restate the exact command and impact, and ask again if the earlier approval wasn't for exactly that command.
6. **Re-measure** with `["volumes", "sizes"]` / `["system", "info"]` and report the space reclaimed.

## Finish
- Summarise what was removed and how much space was freed.
- Suggest noting any removed volumes or projects in the user's Obsidian homelab docs.
