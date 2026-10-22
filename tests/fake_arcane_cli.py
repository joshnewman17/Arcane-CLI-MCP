"""A stand-in for arcane-cli used by the end-to-end tests.

It records its argv and environment to $HOME/calls.jsonl and emits canned
output shaped like the real CLI's JSON mode.
"""

import json
import os
import sys

argv = sys.argv[1:]
home = os.environ.get("HOME", ".")
with open(os.path.join(home, "calls.jsonl"), "a") as fh:
    fh.write(json.dumps({"argv": argv, "env": dict(os.environ)}) + "\n")

# Drop global flags to find the command words.
words, skip = [], False
for a in argv:
    if skip:
        skip = False
        continue
    if a in ("--config", "--env", "--output"):
        skip = True
        continue
    if a.startswith("-"):
        continue
    words.append(a)
cmd = " ".join(words[:2])

if "--help" in argv:
    print(f"\x1b[1mUSAGE\x1b[0m\n  arcane-cli {' '.join(words)} [--flags]\n\nFLAGS\n  -h --help  Help")
    sys.exit(0)

if cmd == "environments list":
    print(json.dumps({"success": True, "data": [
        {"id": "0", "name": "local", "status": "online", "apiUrl": "http://localhost:3552", "extra": "x" * 100},
        {"id": "2", "name": "nas", "status": "offline", "apiUrl": "http://nas:3553"},
    ], "pagination": {"totalItems": 2}}))
elif cmd == "doctor":
    print(json.dumps({"healthy": True, "checks": [{"name": "api_connection", "status": "ok"}]}))
elif cmd == "containers list":
    print(json.dumps({"success": True, "data": [{"id": f"c{i}", "name": f"svc-{i}", "state": "running"}
                                                for i in range(500)], "pagination": {"totalItems": 500}}))
elif cmd == "projects redeploy":
    print(json.dumps([{"status": f"step {i}"} for i in range(5)] + [{"status": "done"}]))
elif cmd in ("projects destroy", "system prune") and "--yes" not in argv:
    sys.stderr.write("\n  Error\n  confirmation required: re-run with --yes\n")
    sys.exit(1)
elif cmd == "leak test":
    print(json.dumps({"apiKey": os.environ.get("LEAK", ""), "note": "header X-Api-Key: abc123secret"}))
elif cmd == "text out":
    print("not json at all")
else:
    print(json.dumps({"success": True, "data": {"argv": argv}}))
