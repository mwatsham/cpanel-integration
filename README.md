# cPanel Account Administration Skill

A production-oriented Agent Skill and Python CLI for administering individual cPanel accounts with
AI assistance. It uses a fixed cPanel UAPI allowlist, a narrow reviewed cPanel API 2 Fileman
fallback for file operations missing from UAPI, verified HTTPS on port 2083, Fernet-encrypted named
profiles, structured JSON, and operation-bound confirmation for destructive actions.

## Scope

The skill supports domains, account files and directories, SSL certificates, MySQL/MariaDB
databases, reviewed email administration, reviewed FTP account administration, read-only account
diagnostics, reviewed cPanel account security controls, reviewed runtime/site operations, and
guarded backup operations.
Email support covers mailbox accounts, quotas, passwords, forwarders, autoresponders, filter state,
spam controls, MX routing, SPF, and DKIM. FTP support covers account listing, creation, deletion,
passwords, quotas, home directories, sessions, server information, and welcome messages.
Diagnostics support covers quota, resource usage, bandwidth, stats, features, login IP, log
settings, and account/server variables exposed to the cPanel account. Security support covers IP
blocking, ModSecurity status/toggles, ClamAV status reads, notification preference reads,
known-host verification, SSH port reads, and task queue reads. Runtime support covers PHP
version/config reads and guarded PHP administration, NGINX cache controls, Passenger app listing,
guarded cPanel Git repository management, and Git deployment task reads/mutations. Backup support covers backup listing, home-directory full-backup
initiation, and backup file metadata reads. The only deprecated API 2 support is the fixed Fileman
fallback for create-directory, delete-path, rename/copy/move, chmod, compress, and extract. It does
not support WHM, root or reseller administration, account provisioning, server settings, browser
automation, other deprecated API 2 calls, anonymous FTP configuration changes, diagnostics setting
changes, malware disinfection, secret token export, Passenger app lifecycle changes, arbitrary shell
Git commands, remote backup destinations, restore execution, or arbitrary UAPI/API calls.

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
.venv/bin/cpanel-admin --profile production files inspect --path public_html/index.html --include-permissions 1
.venv/bin/cpanel-admin --profile production files autocomplete --path public_html --dirsonly 1
.venv/bin/cpanel-admin --profile production files create-file \
  --directory public_html --filename index.html --content-stdin --dry-run
.venv/bin/cpanel-admin --profile production files update-file \
  --directory public_html --filename index.html --content-stdin --dry-run
.venv/bin/cpanel-admin --profile production files create-directory \
  --directory public_html --name assets --permissions 0755 --dry-run
.venv/bin/cpanel-admin --profile production files delete-path --source public_html/old.html --dry-run
.venv/bin/cpanel-admin --profile production files rename-path \
  --source public_html/old.html --destination public_html/new.html --dry-run
.venv/bin/cpanel-admin --profile production files chmod-path \
  --source public_html/index.php --permissions 0644 --dry-run
.venv/bin/cpanel-admin --profile production files compress \
  --source public_html/assets --destination public_html/assets.zip --archive-type zip --dry-run
.venv/bin/cpanel-admin --profile production files extract \
  --source public_html/assets.zip --destination public_html/assets --dry-run
.venv/bin/cpanel-admin --profile production files directory-indexing --dir public_html
.venv/bin/cpanel-admin --profile production files directory-indexing-list --dir public_html
.venv/bin/cpanel-admin --profile production files set-directory-indexing --dir public_html --type disabled --dry-run
.venv/bin/cpanel-admin --profile production files directory-privacy-status --dir public_html/private
.venv/bin/cpanel-admin --profile production files directory-privacy-list --dir public_html
.venv/bin/cpanel-admin --profile production files directory-privacy-users --dir public_html/private
.venv/bin/cpanel-admin --profile production files directory-protection-list --dir public_html
.venv/bin/cpanel-admin --profile production files protect-directory \
  --dir public_html/private --authname Members --enabled 1 --dry-run
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
.venv/bin/cpanel-admin --profile production runtime php-set-vhost-version \
  --vhost example.com --version ea-php83 --dry-run
.venv/bin/cpanel-admin --profile production runtime passenger-apps
.venv/bin/cpanel-admin --profile production runtime version-control
.venv/bin/cpanel-admin --profile production runtime deployments
.venv/bin/cpanel-admin --profile production runtime nginx-clear-cache --dry-run
.venv/bin/cpanel-admin --profile production backups list
.venv/bin/cpanel-admin --profile production backups full-to-home --dry-run
.venv/bin/cpanel-admin --profile production backups file-info --path public_html/index.html
```

For cPanel Git repository creation, put the clone source in
`source-repository-create.json`:

```json
{
  "url": "https://github.com/example/site.git",
  "remote_name": "origin"
}
```

Updates use a separate `source-repository-update.json` because cPanel accepts only the remote name
in the update descriptor. Pass the branch through `--branch`:

```json
{
  "remote_name": "origin"
}
```

Then dry-run and execute through the reviewed runtime commands:

```bash
.venv/bin/cpanel-admin --profile production runtime git-create \
  --repository-root /home/account/repositories/site --name site --type git \
  --source-repository ./source-repository-create.json --dry-run

.venv/bin/cpanel-admin --profile production runtime git-update \
  --repository-root /home/account/repositories/site --name site --branch main \
  --source-repository ./source-repository-update.json --dry-run

.venv/bin/cpanel-admin --profile production runtime deployment-create \
  --repository-root /home/account/repositories/site --dry-run
```

Repository deletion and deployment-task deletion are elevated-impact mutations. Use the digest and
expiry returned by `--dry-run`:

```bash
.venv/bin/cpanel-admin --profile production runtime git-delete \
  --repository-root /home/account/repositories/site --dry-run

.venv/bin/cpanel-admin --profile production runtime deployment-delete \
  --deploy-id deploy-123 --dry-run
```

Do not paste private repository credentials, deploy keys, or personal access tokens into chat or
command arguments. Configure private repository access through cPanel/provider-supported credential
mechanisms outside the skill, then use this skill to manage the cPanel Git repository mapping.

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

Directory privacy passwords use the same standard-input pattern:

```bash
printf '%s' "$DIRECTORY_PASSWORD" | .venv/bin/cpanel-admin --profile staging files add-directory-user \
  --dir public_html/private --user admin --password-stdin --dry-run
```

PHP directive and php.ini mutations must use protected `0600` local files. Plans and audits include
only file fingerprints, not directive or php.ini contents:

```bash
umask 077
printf '%s\n' '{"memory_limit":"256M","display_errors":"Off"}' > ./directives.json
printf '%s\n' 'memory_limit=256M' > ./php.ini

.venv/bin/cpanel-admin --profile staging runtime php-set-directives \
  --type vhost --vhost example.com --directive-file ./directives.json --dry-run

.venv/bin/cpanel-admin --profile staging runtime php-set-ini-content \
  --type vhost --vhost example.com --content-file ./php.ini --dry-run
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
.venv/bin/python scripts/validate_skill_bundle.py "$PWD"
.venv/bin/agentskills validate "$PWD"
```

Live tests are opt-in and must use a disposable cPanel account. See
[disposable live testing](references/live-testing.md) for the required gates, representative
read-only command matrix, optional redacted report, and isolated database lifecycle test.
Track live execution boundaries in the [release scope](references/release-scope.md) and release
evidence in the [requirement-by-requirement audit](references/release-audit.md).

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
