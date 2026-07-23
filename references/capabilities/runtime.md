# Runtime capability

## Use when

Use this capability to inspect PHP versions and configuration, manage reviewed NGINX cache controls,
list Passenger apps, manage reviewed cPanel Git repository mappings, and inspect or manage Git
deployment tasks for one cPanel account.

Do not use it for PHP configuration writes, Passenger app lifecycle changes, arbitrary shell Git
commands, cron administration, WordPress Toolkit, Sitejet, or server runtime administration. See
`references/operation-support.md` for the exact included and excluded runtime operations.

## Representative commands

```bash
cpanel-admin --profile production runtime php-installed
cpanel-admin --profile production runtime php-default
cpanel-admin --profile production runtime php-directives --version ea-php82
cpanel-admin --profile production runtime passenger-apps
cpanel-admin --profile production runtime version-control
cpanel-admin --profile production runtime git-create \
  --repository-root /home/account/repositories/site --name site \
  --type git --source-repository ./source-repository.json --dry-run
cpanel-admin --profile production runtime git-update \
  --repository-root /home/account/repositories/site --name site --branch main \
  --source-repository ./source-repository.json --dry-run
cpanel-admin --profile production runtime git-delete \
  --repository-root /home/account/repositories/site --dry-run
cpanel-admin --profile production runtime deployment-create \
  --repository-root /home/account/repositories/site --dry-run
cpanel-admin --profile production runtime deployment-delete --deploy-id deploy-123 --dry-run
cpanel-admin --profile production runtime deployments
cpanel-admin --profile production runtime nginx-clear-cache --dry-run
```

## Safety notes

- NGINX cache operations mutate runtime/cache state. Run `--dry-run` first.
- Git repository roots must be absolute paths inside the target cPanel account's home directory.
- PHP reads can guide troubleshooting, but PHP writes are excluded until a safer adapter exists.
- Git repository and deployment mutations must be planned with `--dry-run` first.
- For Git create/update, pass `source_repository` as a local JSON file, for example:
  `{"url": "https://github.com/example/site.git", "remote_name": "origin"}` for create, or
  `{"remote_name": "origin"}` for update. Pass the checked-out branch with `--branch` on update.
- Do not paste repository credentials into chat. If a private repository needs credentials, use a
  provider-side deploy key or cPanel-supported credential mechanism outside this skill.
- Passenger support is intentionally read-oriented in this skill.
- Confirm cache impact before clearing or toggling cache on busy sites.
- The authoritative support matrix is `references/operation-support.md`.
