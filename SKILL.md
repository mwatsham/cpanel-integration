---
name: cpanel-integration
description: Administer individual cPanel accounts through reviewed UAPI operations and narrow API 2 Fileman/Cron fallbacks. Use for domains, files and permissions, archives, cron jobs, SSL, databases, email, FTP, diagnostics, account security, PHP settings, Passenger application lifecycle and npm/pip/gem dependencies, cPanel Git deployments, and backups. Uses encrypted named profiles, dry-run plans, protected secret input, and confirmation for high-impact changes. Excludes WHM, root/reseller administration, account provisioning, browser automation, restore execution, shell Git, standalone package installers, arbitrary UAPI calls, and arbitrary API 2 calls.
---

# Administer an individual cPanel account

Use the `cpanel-admin` CLI as the execution and safety boundary. Do not construct direct cPanel
requests or substitute WHM, shell, raw FTP clients, or browser automation. Use cPanel API 2 only
through the fixed Fileman and Cron fallback commands documented here.

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
- Use files commands for reviewed file content operations, directory creation/deletion/renaming,
  permissions, compression/extraction, directory autocomplete, indexing, and directory privacy
  administration.
- Use runtime commands only for reviewed PHP/runtime reads and writes, NGINX cache controls,
  Passenger app listing, guarded cPanel Git repository management, and deployment status/task
  management.
- Use backup commands only for reviewed backup listing, home-directory full-backup initiation, and
  backup metadata reads. Do not execute restores or remote-destination backups.
- Use [software commands](references/capabilities/software.md) for Passenger application
  registration, edits, enable/disable, unregistration, and npm/pip/gem dependencies. Every mutation
  requires confirmation. Environment updates use `--environment-file` with a protected `0600`
  JSON file and replace all existing environment variables. Report dependency jobs as started,
  not completed, until their outcome has been checked.
- Use cron commands only for reviewed job listing, notification email, and job add/edit/remove
  operations. Do not use them for arbitrary local shell execution or WHM/root crontabs.
- Run `--dry-run` before every mutation so the target, normalized parameters, impact, and recovery
  guidance can be reviewed.
- Treat `files create-directory`, `files delete-path`, `files rename-path`, `files copy-path`,
  `files move-path`, `files chmod-path`, `files compress`, and `files extract` as the only approved
  Fileman cPanel API 2 fallback commands. Treat `cron list`, `cron get-email`, `cron set-email`,
  `cron add`, `cron edit`, and `cron remove` as the only approved Cron cPanel API 2 fallback
  commands. Do not generalize them into arbitrary API 2 calls.
- For Git repository create/update commands, provide `source_repository` through a local JSON file
  with `--source-repository`; never paste repository tokens, private keys, or deploy credentials
  into chat or command arguments.
- For directory privacy users, provide passwords only with `--password-stdin`.
- For PHP directive and php.ini mutations, provide content only through protected `0600` local files
  with `--directive-file` or `--content-file`; do not echo PHP configuration content in summaries.
- For cron add/edit commands, provide command text only through `--command-stdin` or a protected
  `0600` file with `--command-file`; plans and audit records must show only the fingerprint.
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
- Never add raw module/function passthrough or broaden the UAPI/API 2 operation allowlists ad hoc.
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
