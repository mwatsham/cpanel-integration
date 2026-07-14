# Diagnostics capability

## Use when

Use this capability to inspect quota, resource usage, bandwidth, account features, log settings,
statistics, account/server variables, and other read-only state before planning changes.

Do not use it to alter diagnostics settings, server monitoring configuration, log retention, or WHM
state. See `references/operation-support.md` for the exact included and excluded diagnostics
operations.

## Representative commands

```bash
cpanel-admin --profile production diagnostics quota
cpanel-admin --profile production diagnostics resource-usage
cpanel-admin --profile production diagnostics bandwidth
cpanel-admin --profile production diagnostics features
cpanel-admin --profile production diagnostics site-errors --domain example.com --maxlines 50
cpanel-admin --profile production diagnostics stats
```

## Safety notes

- Diagnostics commands are read-only, but output may reveal account structure and domain names.
- Use diagnostics before risky operations to check quota, feature availability, and current state.
- Do not treat diagnostics reads as permission to bypass capability checks.
- `--dry-run` is not needed for read-only diagnostics, but it remains required before mutations in
  other capability packs.
- The authoritative support matrix is `references/operation-support.md`.
