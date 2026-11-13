# Security policy

arcane-cli-mcp can start, stop, update and delete containers on the Docker hosts your Arcane instance
manages. Treat a deployment of it like any other admin interface.

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(the **Report a vulnerability** button on this repository's **Security** tab), not in a public issue or pull
request. Include the version or commit, how to reproduce it, and what an attacker could do with it.

Things that are in scope include, for example:

- a way to run a command the policy layer should block, or to skip `confirm=true`;
- secrets (the Arcane API key, the MCP token, values from a project `.env`, credentials in container
  environments or logs) leaking through tool output or the audit log;
- authentication bypasses in bearer-token or Cloudflare Access mode;
- reading or writing files inside the MCP container through a tool argument.

This is a personal project maintained in spare time, so responses are best effort.

## Supported versions

Only the latest commit on `main` and the `latest` image built from it receive fixes.

## Deploying it safely

- Give it a **scoped, non-admin** Arcane API key. The Arcane role is the real security boundary; this server's
  policy layer is defence in depth on top of it (see the README's safety model).
- Never expose the HTTP endpoint without authentication: set `MCP_AUTH_TOKEN`, or use Cloudflare Access mode
  (`CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`).
- Keep the hardening from the example compose file: read-only root filesystem, tmpfs `/tmp`, all capabilities
  dropped, `no-new-privileges`.
- Use `ARCANE_MCP_READONLY=true` for a look-but-don't-touch setup, and `LOGS_ENABLED=false` or `LOGS_EXCLUDE`
  if container logs could hold secrets that redaction can't recognise.
- Keep secrets in your Arcane project `.env` or a Docker secret (`ARCANE_API_KEY_FILE`), never in git.
