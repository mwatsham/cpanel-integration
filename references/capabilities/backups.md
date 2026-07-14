# Backups capability

## Use when

Use this capability for local cPanel backup inventory, home-directory backup initiation, backup
metadata reads, and backup user/directory discovery for one individual cPanel account.

Do not use it for restore execution, remote FTP/SCP backup destinations, destination credentials,
server-wide backups, WHM backups, or arbitrary archive manipulation. See
`references/operation-support.md` for the exact included and excluded backup operations.

## Representative commands

```bash
cpanel-admin --profile production backups list
cpanel-admin --profile production backups users
cpanel-admin --profile production backups directory
cpanel-admin --profile production backups file-info --path public_html/index.html
cpanel-admin --profile production backups full-to-home --dry-run
```

## Safety notes

- `backups full-to-home` is a mutation because it starts backup generation. Run `--dry-run` first.
- Local backup creation can consume disk quota. Check `diagnostics quota` before starting.
- Restore operations are excluded until archive preflight, overwrite handling, and rollback guidance
  are designed.
- Remote backup destinations are excluded because they require additional protected secret handling.
- The authoritative support matrix is `references/operation-support.md`.
