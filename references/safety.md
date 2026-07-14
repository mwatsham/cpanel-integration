# Safety policy

Read this file before any cPanel mutation.

## Risk classes

| Class | Behavior | Examples |
|---|---|---|
| Read | Execute when requested | list domains, read a file, list certificates |
| Mutate | Dry-run first; execute within approved scope | add subdomain, create database, grant privileges |
| Destructive | Dry-run, explicit user approval, exact confirmation | overwrite file, install/remove SSL, purge trash, delete database or profile |

## Destructive workflow

1. Verify the named profile and exact target.
2. Run the full command with `--dry-run`.
3. Review the plan's operation, parameters, preflight state, impact, recovery, and expiry.
4. Tell the user when no automatic backup or recovery artifact exists.
5. Obtain explicit approval for that plan immediately before execution.
6. Rerun the identical command with `--confirm` and `--expires-at` from the plan.
7. Stop when the digest is rejected or expired. Generate and approve a new plan; never bypass it.
8. Verify the result with a read-only command when available.

The confirmation is an HMAC digest bound to the exact safe plan. Changing a profile, operation,
path, domain, database name, secret content, file content, preflight state, or expiry invalidates it.

## Secrets

- Inject `CPANEL_ADMIN_FERNET_KEY` through an operating-system or CI secret manager, or use the
  separate protected key file for unattended local Codex sessions. Environment variables can be
  inherited by child processes, so run only trusted children.
- Keep the default key file at `~/.config/cpanel-admin/fernet.key`, or override it with
  `CPANEL_ADMIN_FERNET_KEY_FILE`. It must be owned by the current user, be a regular non-symlink
  file, and have mode `0600`.
- Never store the Fernet master key in `profiles.json`; separation is what protects encrypted tokens.
- Supply cPanel API tokens and database passwords through standard input.
- Supply SSL certificates and private keys through protected local files.
- Never place secrets in arguments, chat, source, committed `.env` files, fixtures, logs,
  screenshots, shell tracing, or issue reports.
- Treat profile configuration as sensitive even though tokens are Fernet encrypted.
- Rotate the master key with `CPANEL_ADMIN_FERNET_KEY_NEW`; update the active secret-manager value
  only after successful atomic rotation.

## Recovery constraints

- File write/upload can overwrite remote content. The CLI records target preflight metadata but does
  not create a backup. Confirm an independent backup exists when recovery matters.
- Emptying trash and deleting a database have no automatic rollback. Verify an independent backup.
- SSL removal can interrupt HTTPS. Keep the previous certificate, private key, and CA bundle in a
  secure location before replacement or removal.
- Subdomain removal is not implemented because no reviewed current UAPI replacement is available.

## Hard boundaries

Never use this skill for WHM, port 2087, root/reseller actions, account lifecycle, server services,
arbitrary UAPI, deprecated cPanel API 2, browser automation, shell access, raw FTP clients,
anonymous FTP configuration, or production live testing. Report an unsupported capability instead of
widening the method.
