# Files capability

## Use when

Use this capability to list, inspect, and read account files; write file content; upload local files;
inspect and manage directory indexing; inspect and manage directory privacy users/protection; or
empty cPanel trash through reviewed UAPI operations.

Do not use it for shell access, raw FTP clients, browser file manager automation, undocumented file
operations, or server-level filesystem changes. See `references/operation-support.md` for the exact
included and excluded file operations.

## Representative commands

```bash
cpanel-admin --profile production files list --path public_html
cpanel-admin --profile production files inspect --path public_html/index.html
cpanel-admin --profile production files read --directory public_html --filename index.html
cpanel-admin --profile production files write --directory public_html --filename index.html --content-stdin --dry-run
cpanel-admin --profile production files upload --directory public_html --source ./index.html --dry-run
cpanel-admin --profile production files autocomplete --path public_html --dirsonly 1
cpanel-admin --profile production files directory-indexing --dir public_html
cpanel-admin --profile production files directory-indexing-list --dir public_html
cpanel-admin --profile production files set-directory-indexing --dir public_html --type disabled --dry-run
cpanel-admin --profile production files directory-privacy-status --dir public_html/private
cpanel-admin --profile production files directory-privacy-list --dir public_html
cpanel-admin --profile production files directory-privacy-users --dir public_html/private
cpanel-admin --profile production files directory-protection-list --dir public_html
cpanel-admin --profile production files protect-directory --dir public_html/private --authname Members --enabled 1 --dry-run
printf '%s' "$DIRECTORY_PASSWORD" | cpanel-admin --profile production files add-directory-user \
  --dir public_html/private --user admin --password-stdin --dry-run
cpanel-admin --profile production files delete-directory-user --dir public_html/private --user admin --dry-run
cpanel-admin --profile production files empty-trash --older-than 30 --dry-run
```

## Safety notes

- File writes and uploads can overwrite content. The CLI records preflight metadata but does not
  create an automatic backup.
- Directory protection can lock visitors out of a site path. Inspect current protection before
  changing it.
- Directory privacy user passwords must be supplied through standard input.
- Trash cleanup is destructive and requires expiring confirmation.
- Supply file content through standard input or local files; do not paste secrets into chat.
- Verify independent backups before overwriting production files.
- The authoritative support matrix is `references/operation-support.md`.
