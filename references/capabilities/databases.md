# Databases capability

## Use when

Use this capability to inspect and administer MySQL/MariaDB databases, database users, and user
grants within one individual cPanel account.

Do not use it for server-level MySQL administration, phpMyAdmin automation, root database access,
database restore execution, or cross-account operations. See `references/operation-support.md` for
the exact included and excluded database operations.

## Representative commands

```bash
cpanel-admin --profile production databases list
cpanel-admin --profile production databases users
cpanel-admin --profile production databases create --name account_app --dry-run
cpanel-admin --profile production databases create-user --name account_appuser --password-stdin --dry-run
cpanel-admin --profile production databases grant --database account_app --user account_appuser --privileges ALL --dry-run
cpanel-admin --profile production databases remove --name account_app --dry-run
```

## Safety notes

- Database creation, user creation, and grants mutate account state. Run `--dry-run` first.
- Database and database-user removal are destructive and require expiring confirmation.
- Supply passwords through standard input only; never place them in shell history or chat.
- Use cPanel-valid account-prefixed names and verify quota before creating resources.
- The authoritative support matrix is `references/operation-support.md`.
