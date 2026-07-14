# Capability references

Use these focused references to choose safe `cpanel-admin` commands without reading the full
generated matrix first. The authoritative operation list remains
`references/operation-support.md`; mutation handling remains governed by `references/safety.md`.

| Capability | Reference | Primary use |
| --- | --- | --- |
| Backups | [capabilities/backups.md](capabilities/backups.md) | Local backup inventory and guarded home-directory backup starts |
| Databases | [capabilities/databases.md](capabilities/databases.md) | MySQL/MariaDB databases, users, and grants |
| Diagnostics | [capabilities/diagnostics.md](capabilities/diagnostics.md) | Quota, bandwidth, features, logs, stats, and account state |
| Domains | [capabilities/domains.md](capabilities/domains.md) | Domain discovery and reviewed subdomain creation |
| Email | [capabilities/email.md](capabilities/email.md) | Mailboxes, routing, forwarders, autoresponders, filters, spam, SPF, DKIM, and DMARC |
| Files | [capabilities/files.md](capabilities/files.md) | Account file reads, writes, uploads, and trash cleanup |
| FTP | [capabilities/ftp.md](capabilities/ftp.md) | FTP account and session administration |
| Runtime | [capabilities/runtime.md](capabilities/runtime.md) | PHP reads, NGINX cache controls, Passenger apps, Git deployment reads, and runtime status |
| Security | [capabilities/security.md](capabilities/security.md) | IP blocks, ModSecurity, ClamAV status, known-host checks, SSH port reads, and task queues |
| SSL | [capabilities/ssl.md](capabilities/ssl.md) | Certificate inventory, installation, and removal |

Always run mutating commands with `--dry-run` first. Destructive operations require the expiring
confirmation flow in `references/safety.md`.
