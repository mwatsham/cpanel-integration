# Cron capability

## Use when

Use this capability to list cPanel cron jobs, read or set the cron notification email, and add,
edit, or remove cron entries for one individual cPanel account through a reviewed cPanel API 2 Cron
fallback.

Do not use it for arbitrary shell execution, WHM/root crontabs, server-wide cron administration,
browser automation, or arbitrary cPanel API 2 calls. cPanel documents these Cron functions as API 2
functions with no UAPI equivalents, so this skill exposes only the reviewed commands below. See
`references/operation-support.md` for the UAPI support matrix and this file for the fixed Cron API 2
fallback.

## Representative commands

```bash
cpanel-admin --profile production cron list
cpanel-admin --profile production cron get-email
cpanel-admin --profile production cron set-email --email admin@example.com --dry-run
printf '%s' '/usr/local/bin/php /home/account/public_html/artisan schedule:run' | \
  cpanel-admin --profile production cron add \
    --minute '*/15' --hour '*' --day '*' --month '*' --weekday '*' \
    --command-stdin --dry-run
printf '%s' '/usr/local/bin/php /home/account/public_html/artisan schedule:run' | \
  cpanel-admin --profile production cron edit \
    --linekey f32e3d460c179443e5f772359c7954ec \
    --minute '0' --hour '2' --day '*' --month '*' --weekday '1-5' \
    --command-stdin --dry-run
cpanel-admin --profile production cron remove \
  --linekey f32e3d460c179443e5f772359c7954ec --dry-run
```

For unattended runs, place the cron command in a protected `0600` file and pass
`--command-file ./cron-command.txt` instead of `--command-stdin`.

## Safety notes

- Cron administration uses a fixed cPanel API 2 Cron fallback because cPanel does not expose UAPI
  equivalents for these actions.
- Cron command text can contain credentials or sensitive paths. Plans and audit events include only
  a byte count and SHA-256 fingerprint, never the command text.
- Provide cron command text through standard input or a protected `0600` file. Do not put command
  text in chat or shell arguments.
- Schedule fields are validated individually: minute, hour, day, month, and weekday.
- Edit and remove operations target cPanel `linekey` values returned by `cron list`; line-number
  targeting is intentionally unsupported.
- Removing a cron entry is destructive. Editing is elevated-impact because it can disable scheduled
  maintenance or backups. Run `--dry-run` first and use the expiring confirmation flow when required.
- Confirm how to recreate a job before removing it. This CLI does not automatically back up the
  previous crontab.
- The authoritative UAPI support matrix is `references/operation-support.md`.
