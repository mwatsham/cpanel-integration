# FTP capability

## Use when

Use this capability to list FTP accounts, create or delete reviewed FTP users, update FTP passwords
or quotas, inspect account disk use, view sessions, and read FTP server information.

Do not use it as a raw FTP client, for anonymous FTP configuration changes, server daemon
administration, shell access, or remote backup destinations. See `references/operation-support.md`
for the exact included and excluded FTP operations.

## Representative commands

```bash
cpanel-admin --profile production ftp accounts
cpanel-admin --profile production ftp sessions
cpanel-admin --profile production ftp quota --account deploy --domain example.com
cpanel-admin --profile production ftp create --user deploy --domain example.com --password-stdin --dry-run
cpanel-admin --profile production ftp set-quota --account deploy --domain example.com --quota 1024 --dry-run
cpanel-admin --profile production ftp delete --account deploy --domain example.com --dry-run
```

## Safety notes

- FTP creation, password changes, quota changes, and welcome-message changes mutate account state.
  Run `--dry-run` first.
- FTP account deletion is destructive and requires expiring confirmation.
- Supply FTP passwords through standard input only.
- Anonymous FTP reads may exist for discovery, but anonymous FTP configuration changes are excluded.
- The authoritative support matrix is `references/operation-support.md`.
