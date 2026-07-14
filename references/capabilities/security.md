# Security capability

## Use when

Use this capability for reviewed account security controls and reads: IP blocking, ModSecurity
status/toggles, ClamAV status reads, notification preference reads, known-host verification, SSH
port reads, and task queue reads.

Do not use it for malware disinfection, long-running scan starts, contact email changes, private
token extraction, firewall/server security administration, or WHM security features. See
`references/operation-support.md` for the exact included and excluded security operations.

## Representative commands

```bash
cpanel-admin --profile production security modsec-installed
cpanel-admin --profile production security modsec-domains
cpanel-admin --profile production security clam-scan-status
cpanel-admin --profile production security known-host-verify --host-name example.com
cpanel-admin --profile production security block-ip --ip 203.0.113.9 --dry-run
cpanel-admin --profile production security unblock-ip --ip 203.0.113.9 --dry-run
```

## Safety notes

- IP blocks and ModSecurity toggles mutate security posture. Run `--dry-run` first.
- Disabling ModSecurity may increase exposure. Prefer narrow domain-specific changes where
  available.
- ClamAV disinfection and scan starts are excluded until a task-safe remediation adapter exists.
- Do not export or display private third-party access tokens.
- The authoritative support matrix is `references/operation-support.md`.
