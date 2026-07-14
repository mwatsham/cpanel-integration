# Runtime capability

## Use when

Use this capability to inspect PHP versions and configuration, manage reviewed NGINX cache controls,
list Passenger apps, list Git repositories, and inspect deployment status for one cPanel account.

Do not use it for PHP configuration writes, Passenger app lifecycle changes, Git repository
mutation, shell deployment, cron administration, WordPress Toolkit, Sitejet, or server runtime
administration. See `references/operation-support.md` for the exact included and excluded runtime
operations.

## Representative commands

```bash
cpanel-admin --profile production runtime php-installed
cpanel-admin --profile production runtime php-default
cpanel-admin --profile production runtime php-directives --version ea-php82
cpanel-admin --profile production runtime passenger-apps
cpanel-admin --profile production runtime git-repositories
cpanel-admin --profile production runtime deployments
cpanel-admin --profile production runtime nginx-clear-cache --dry-run
```

## Safety notes

- NGINX cache operations mutate runtime/cache state. Run `--dry-run` first.
- PHP reads can guide troubleshooting, but PHP writes are excluded until a safer adapter exists.
- Git and Passenger support is intentionally read-oriented in this skill.
- Confirm cache impact before clearing or toggling cache on busy sites.
- The authoritative support matrix is `references/operation-support.md`.
