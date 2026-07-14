# cPanel Account Administration Skill

A production-oriented Agent Skill and Python CLI for administering individual cPanel accounts with
AI assistance. It uses a fixed cPanel UAPI allowlist, verified HTTPS on port 2083, Fernet-encrypted
named profiles, structured JSON, and operation-bound confirmation for destructive actions.

## Scope

The skill supports domains, account files, SSL certificates, MySQL/MariaDB databases, reviewed
email administration, reviewed FTP account administration, read-only account diagnostics, reviewed
cPanel account security controls, reviewed runtime/site operations, and guarded backup operations.
Email support covers mailbox accounts, quotas, passwords, forwarders, autoresponders, filter state,
spam controls, MX routing, SPF, and DKIM. FTP support covers account listing, creation, deletion,
passwords, quotas, home directories, sessions, server information, and welcome messages.
Diagnostics support covers quota, resource usage, bandwidth, stats, features, login IP, log
settings, and account/server variables exposed to the cPanel account. Security support covers IP
blocking, ModSecurity status/toggles, ClamAV status reads, notification preference reads,
known-host verification, SSH port reads, and task queue reads. Runtime support covers PHP
version/config reads, NGINX cache controls, Passenger app listing, Git repository listing, and
deployment status reads. Backup support covers backup listing, home-directory full-backup
initiation, and backup file metadata reads. It does not support WHM, root or reseller
administration, account provisioning, server settings, browser automation, deprecated API 2,
anonymous FTP configuration changes, diagnostics setting changes, malware disinfection, secret
token export, PHP config writes, Passenger app lifecycle changes, Git repository mutation, remote
backup destinations, restore execution, or arbitrary UAPI calls.

## Install

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/cpanel-admin --help
```

Runtime uses Python's standard library plus `cryptography`. Pytest, coverage, and Ruff are optional
development dependencies.

## Configure encrypted profiles

Generate a Fernet master key once. For interactive or CI use, inject it from a secret manager:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
export CPANEL_ADMIN_FERNET_KEY='value-injected-by-your-secret-manager'
```

The key must be available from the environment or protected key file for unattended profile use.
Environment variables can be inherited by child processes; do not log the environment or execute
untrusted child processes.

For local Codex sessions, store the existing key in a separate protected file. Do not put the
master key in `profiles.json` because that would defeat token encryption:

```bash
mkdir -p ~/.config/cpanel-admin
chmod 700 ~/.config/cpanel-admin
umask 077
printf '%s\n' "$CPANEL_ADMIN_FERNET_KEY" > ~/.config/cpanel-admin/fernet.key
chmod 600 ~/.config/cpanel-admin/fernet.key
unset CPANEL_ADMIN_FERNET_KEY
```

The CLI automatically reads `${XDG_CONFIG_HOME:-~/.config}/cpanel-admin/fernet.key` when the direct
environment value is absent. Set `CPANEL_ADMIN_FERNET_KEY_FILE` to use another location. The file
must be a regular, non-symlink file owned by the current user with permissions exactly `0600`.

Create a cPanel account API token in cPanel, then pipe it from a protected source:

```bash
printf '%s' "$CPANEL_API_TOKEN" | .venv/bin/cpanel-admin profiles add production \
  --host cpanel.example.com --username account --api-token-stdin
```

Profiles default to `${XDG_CONFIG_HOME:-~/.config}/cpanel-admin/profiles.json`. Override this with
`CPANEL_ADMIN_CONFIG` or global `--config`. Tokens are encrypted at rest; list/show output excludes
both ciphertext and plaintext. Do not commit the Fernet key, tokens, passwords, or profile store.

Profile rotation is atomic. Supply the replacement through the environment, then replace the key
file only after the command succeeds:

```bash
export CPANEL_ADMIN_FERNET_KEY_NEW='new-secret-manager-value'
.venv/bin/cpanel-admin profiles rotate-key
```

Keep the old key active until the command succeeds, then promote the new key.

## Use

Global options precede the capability group:

```bash
.venv/bin/cpanel-admin --profile production domains list
.venv/bin/cpanel-admin --profile production files list --path public_html
.venv/bin/cpanel-admin --profile production ssl hosts
.venv/bin/cpanel-admin --profile production databases list
.venv/bin/cpanel-admin --profile production email accounts
.venv/bin/cpanel-admin --profile production email accounts-disk --domain example.com
.venv/bin/cpanel-admin --profile production email forwarders --domain example.com
.venv/bin/cpanel-admin --profile production email domain-forwarders --domain example.com
.venv/bin/cpanel-admin --profile production email mx-list --domain example.com
.venv/bin/cpanel-admin --profile production email routing-mode --domain example.com --mxcheck auto --dry-run
.venv/bin/cpanel-admin --profile production email mailbox-status --account admin@example.com
.venv/bin/cpanel-admin --profile production email validate-dmarc --domain example.com
.venv/bin/cpanel-admin --profile production email greylisting-domains
.venv/bin/cpanel-admin --profile production ftp accounts
.venv/bin/cpanel-admin --profile production ftp sessions
.venv/bin/cpanel-admin --profile production ftp quota --account deploy --domain example.com
.venv/bin/cpanel-admin --profile production diagnostics quota
.venv/bin/cpanel-admin --profile production diagnostics resource-usage
.venv/bin/cpanel-admin --profile production diagnostics site-errors --domain example.com --maxlines 50
.venv/bin/cpanel-admin --profile production security modsec-domains
.venv/bin/cpanel-admin --profile production security block-ip --ip 203.0.113.9 --dry-run
.venv/bin/cpanel-admin --profile production security known-host-verify --host-name example.com
.venv/bin/cpanel-admin --profile production runtime php-installed
.venv/bin/cpanel-admin --profile production runtime passenger-apps
.venv/bin/cpanel-admin --profile production runtime nginx-clear-cache --dry-run
.venv/bin/cpanel-admin --profile production backups list
.venv/bin/cpanel-admin --profile production backups full-to-home --dry-run
.venv/bin/cpanel-admin --profile production backups file-info --path public_html/index.html
```

Non-destructive mutations support a review step:

```bash
.venv/bin/cpanel-admin --profile staging databases create \
  --name account_demo --dry-run
```

Mailbox passwords are protected inputs. Pipe them through standard input rather than placing them on
the command line:

```bash
printf '%s' "$MAILBOX_PASSWORD" | .venv/bin/cpanel-admin --profile staging email create-account \
  --email admin --domain example.com --password-stdin --dry-run
```

Password verification also uses standard input and does not echo the password in JSON output:

```bash
printf '%s' "$MAILBOX_PASSWORD" | .venv/bin/cpanel-admin --profile staging email verify-password \
  --email admin@example.com --password-stdin
```

FTP account passwords are also protected inputs:

```bash
printf '%s' "$FTP_PASSWORD" | .venv/bin/cpanel-admin --profile staging ftp create \
  --user deploy --domain example.com --password-stdin --dry-run
```

DKIM private-key imports must use a protected `0600` file:

```bash
.venv/bin/cpanel-admin --profile staging email install-dkim-key \
  --domain example.com --key-file ./dkim-private.pem --dry-run
```

Destructive actions require two commands. First request a five-minute plan:

```bash
.venv/bin/cpanel-admin --profile staging databases remove \
  --name account_demo --dry-run
```

After reviewing the exact plan and approving its impact and recovery requirements, rerun the same
command using the returned fields:

```bash
.venv/bin/cpanel-admin --profile staging databases remove \
  --name account_demo --confirm 8f13c2d1b7e4 \
  --expires-at '2026-07-13T12:05:00+00:00'
```

Changing the profile, operation, parameters, secret/file content, or file preflight state invalidates
the digest. See the [capability references](references/capabilities.md),
[supported operations](references/operations.md), and the [safety policy](references/safety.md).

## Output and failures

Success writes one JSON document to stdout. Expected failures write a safe message to stderr and use
stable exit codes:

| Code | Meaning |
|---:|---|
| 2 | command usage or parameter validation |
| 3 | local profile, Fernet, or configuration failure |
| 4 | confirmation missing, expired, or mismatched |
| 5 | network, TLS, HTTP, timeout, or response-format failure |
| 6 | cPanel UAPI application failure |
| 7 | unsupported capability |

## Test and validate

The default suite uses mocked transports and never accesses cPanel:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/check_generated.py
.venv/bin/agentskills validate "$PWD"
```

Live tests are opt-in and must use a disposable cPanel account. See
[disposable live testing](references/live-testing.md) for the required gates, representative
read-only command matrix, optional redacted report, and isolated database lifecycle test.

## Architecture

`SKILL.md` supplies the AI workflow. `cpanel-admin` is the deterministic security boundary. It
validates inputs, selects a fixed UAPI module/function, classifies risk, verifies confirmations,
performs TLS-verified requests, checks the UAPI application status, and redacts sensitive data.

Authoritative API references:

- [Agent Skills specification](https://agentskills.io/specification)
- [OpenAPI maintenance workflow](references/openapi-maintenance.md)
- [cPanel UAPI introduction](https://api.docs.cpanel.net/cpanel/introduction)
- [cPanel API tokens](https://api.docs.cpanel.net/cpanel/tokens)
- [File upload tutorial](https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-use-uapis-fileman-upload-files-function-in-custom-code)
- [SSL installation](https://api.docs.cpanel.net/specifications/cpanel.openapi/ssl-certificate-management/install_ssl)
- [MySQL database creation](https://api.docs.cpanel.net/specifications/cpanel.openapi/database-management/create_database)
