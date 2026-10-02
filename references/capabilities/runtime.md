# Runtime capability

## Use when

Use this capability to inspect PHP versions and configuration, change reviewed PHP virtual-host
versions and user PHP configuration, manage reviewed NGINX cache controls, list Passenger apps,
manage reviewed cPanel Git repository mappings, and inspect or manage Git deployment tasks for one
cPanel account.

Use [software.md](software.md) for Passenger app lifecycle and dependency changes.
For provider-disabled MultiPHP INI Editor or 123 Reg domain isolation, consult the
[PHP Selector provider limitation](php-selector.md#provider-limitation-123-reg-domain-isolation).
Do not treat account-global Selector changes as a substitute for a requested site-only change.
Do not use it for arbitrary shell Git commands, cron
administration, WordPress Toolkit, Sitejet, or server runtime administration. See
`references/operation-support.md` for the exact included and excluded runtime operations.

## Representative commands

```bash
cpanel-admin --profile production runtime php-installed
cpanel-admin --profile production runtime php-default
cpanel-admin --profile production runtime php-directives --version ea-php82
cpanel-admin --profile production runtime php-set-vhost-version \
  --vhost example.com --version ea-php83 --dry-run
cpanel-admin --profile production runtime php-set-directives \
  --type vhost --vhost example.com --directive-file ./directives.json --dry-run
cpanel-admin --profile production runtime php-set-ini-content \
  --type vhost --vhost example.com --content-file ./php.ini --dry-run
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
- PHP version changes can affect application compatibility and require elevated-impact confirmation.
- PHP directive and php.ini writes must use protected local files with mode `0600`. Plans and audit
  records include only fingerprints, not PHP configuration content.
- Git repository and deployment mutations must be planned with `--dry-run` first.
- For Git create/update, pass `source_repository` as a local JSON file, for example:
  `{"url": "https://github.com/example/site.git", "remote_name": "origin"}` for create, or
  `{"remote_name": "origin"}` for update. Pass the checked-out branch with `--branch` on update.
- Do not paste repository credentials into chat. If a private repository needs credentials, use a
  provider-side deploy key or cPanel-supported credential mechanism outside this skill.
- Passenger mutations are available through the separate `software` commands.
- Confirm cache impact before clearing or toggling cache on busy sites.
- The authoritative support matrix is `references/operation-support.md`.
