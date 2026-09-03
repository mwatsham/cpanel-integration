---
name: cpanel-integration
description: Safely administer individual cPanel accounts through documented UAPI operations for domains, files and directories, SSL certificates, MySQL or MariaDB databases, email, FTP accounts, diagnostics, security controls, PHP/runtime operations, guarded Git repository deployments, and backups. Use when Codex needs to inspect or change website resources, directory privacy/indexing, mailboxes, FTP users, quotas, resource usage, IP blocks, ModSecurity, PHP versions/configuration, cPanel Git repositories, backups, passwords, routing, SPF, or DKIM in cPanel. Do not use for WHM, root, reseller, account provisioning, server-wide administration, browser automation, anonymous FTP changes, restore execution, shell Git commands, or arbitrary UAPI calls.
---

# Administer an individual cPanel account

Use the `cpanel-admin` CLI as the execution and safety boundary. Do not construct direct cPanel
requests or substitute deprecated API 2, WHM, shell, raw FTP clients, or browser automation.

## Prepare

1. Confirm the request concerns one individual cPanel account, not WHM or server administration.
2. Read [references/capabilities.md](references/capabilities.md) and
   [references/operations.md](references/operations.md) to select an exact supported command.
3. Ask for the named profile only when it cannot be inferred safely.
4. Check that the Fernet key is available from `CPANEL_ADMIN_FERNET_KEY` or the protected key file.
5. Never ask the user to paste an API token, Fernet key, database password, or private key into
   chat. Direct secret input to standard input or a protected local file as documented.

## Execute

- Run read-only commands directly when they match the user's request.
- Use read-only diagnostics commands to inspect quota, resource usage, bandwidth, features, logs,
  and account/server variables before risky changes.
- Use account security commands only for reviewed IP blocking, ModSecurity, ClamAV status,
  notification preference reads, known-host verification, SSH port reads, and task queue reads.
- Use files commands for reviewed file content operations plus directory autocomplete, indexing, and
  directory privacy administration.
- Use runtime commands only for reviewed PHP/runtime reads and writes, NGINX cache controls,
  Passenger app listing, guarded cPanel Git repository management, and deployment status/task
  management.
- Use backup commands only for reviewed backup listing, home-directory full-backup initiation, and
  backup metadata reads. Do not execute restores or remote-destination backups.
- Run `--dry-run` before every mutation so the target, normalized parameters, impact, and recovery
  guidance can be reviewed.
- For Git repository create/update commands, provide `source_repository` through a local JSON file
  with `--source-repository`; never paste repository tokens, private keys, or deploy credentials
  into chat or command arguments.
- For directory privacy users, provide passwords only with `--password-stdin`.
- For PHP directive and php.ini mutations, provide content only through protected `0600` local files
  with `--directive-file` or `--content-file`; do not echo PHP configuration content in summaries.
- For non-destructive mutations, present the dry-run and execute only within the user's authority.
- For destructive operations, read [references/safety.md](references/safety.md), run `--dry-run`,
  present the returned plan, and obtain explicit user approval immediately before execution.
- After approval, rerun the exact command with both `--confirm DIGEST` and
  `--expires-at TIMESTAMP` from that plan. Never reuse a digest for changed parameters.
- Treat any nonzero exit as failure. Report its concise error and exit-code category without
  exposing environment values or request headers.
- Verify mutations with the corresponding read command when the API offers one.
- For mailbox passwords, FTP passwords, database passwords, directory privacy passwords, PHP
  configuration payloads, private keys, certificate material, and other secrets, use only the
  approved `--*-stdin`, `--*-file`, or protected profile mechanisms.

## Guardrails

- Keep TLS verification enabled and use only cPanel HTTPS port 2083.
- Never add raw module/function passthrough or broaden the operation allowlist ad hoc.
- Never run arbitrary local or remote shell Git commands as a substitute for the reviewed cPanel
  `runtime git-*` and `runtime deployment-*` commands.
- Do not expose command input, environment secrets, encrypted tokens, password values, certificate
  bodies, private keys, or authorization headers in output or summaries.
- Explain capability errors plainly. Do not propose deprecated or broader fallbacks.
- Stop if the profile or target is ambiguous, a dry-run differs from the intended action, recovery
  is inadequate, or a destructive confirmation expires.

## Configure a profile

Generate a Fernet key locally and inject it through the operator's secret manager or install it in
the protected default file described in `README.md`:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Pipe a cPanel account API token to standard input without placing it in the command line:

```bash
printf '%s' "$CPANEL_API_TOKEN" | cpanel-admin profiles add staging \
  --host cpanel.example.com --username account --api-token-stdin
```

Do not print either environment variable. Never commit the environment values or protected key file
to source control.

For unattended local Codex sessions, prefer the separate `~/.config/cpanel-admin/fernet.key` file
with mode `0600`. Never store the Fernet key inside `profiles.json`.
