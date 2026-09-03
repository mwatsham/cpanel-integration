# Files capability

## Use when

Use this capability to list, inspect, and read account files; write file content; upload local files;
create directories; trash, rename, copy, or move paths; inspect and manage permissions; compress
and extract archives; inspect and manage directory indexing; inspect and manage directory privacy
users/protection; or empty cPanel trash through reviewed UAPI operations plus the narrow cPanel API
2 Fileman fallback.

Do not use it for shell access, raw FTP clients, browser file manager automation, undocumented file
operations, arbitrary API 2 calls, or server-level filesystem changes. See
`references/operation-support.md` for UAPI support and this file for the fixed API 2 fallback.

## Representative commands

```bash
cpanel-admin --profile production files list --path public_html
cpanel-admin --profile production files inspect --path public_html/index.html --include-permissions 1
cpanel-admin --profile production files read --directory public_html --filename index.html
cpanel-admin --profile production files write --directory public_html --filename index.html --content-stdin --dry-run
cpanel-admin --profile production files create-file --directory public_html --filename index.html --content-stdin --dry-run
cpanel-admin --profile production files update-file --directory public_html --filename index.html --content-stdin --dry-run
cpanel-admin --profile production files upload --directory public_html --source ./index.html --dry-run
cpanel-admin --profile production files create-directory --directory public_html --name assets --permissions 0755 --dry-run
cpanel-admin --profile production files delete-path --source public_html/old.html --dry-run
cpanel-admin --profile production files rename-path --source public_html/old.html --destination public_html/new.html --dry-run
cpanel-admin --profile production files copy-path --source public_html/index.html --destination public_html/index-copy.html --dry-run
cpanel-admin --profile production files move-path --source public_html/tmp.html --destination public_html/archive/tmp.html --dry-run
cpanel-admin --profile production files chmod-path --source public_html/index.php --permissions 0644 --dry-run
cpanel-admin --profile production files compress --source public_html/assets --destination public_html/assets.zip --archive-type zip --dry-run
cpanel-admin --profile production files extract --source public_html/assets.zip --destination public_html/assets --dry-run
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
- `create-file` and `update-file` are safer aliases for the UAPI `files write` operation.
- Directory creation and path operations use the reviewed cPanel API 2 fallback because cPanel does
  not expose UAPI equivalents for those Fileman actions.
- `delete-path` moves the target to `.trash`; it is still destructive because later trash cleanup
  makes recovery unavailable.
- Permission changes, compression, and extraction can break a site or overwrite expanded files.
  Inspect permissions and confirm backups before execution.
- Directory protection can lock visitors out of a site path. Inspect current protection before
  changing it.
- Directory privacy user passwords must be supplied through standard input.
- Trash cleanup is destructive and requires expiring confirmation.
- Supply file content through standard input or local files; do not paste secrets into chat.
- Verify independent backups before overwriting production files.
- The authoritative support matrix is `references/operation-support.md`.
