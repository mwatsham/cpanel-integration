# CloudLinux PHP Selector

## Use when

Manage the account's CloudLinux **Select PHP Version** settings: available/current PHP versions,
PHP extensions, and reviewed PHP options. This is separate from cPanel MultiPHP (`runtime php-*`).
The UAPI inventory in `references/operation-support.md` does not cover this SSH capability.

Requirements: OpenSSH on the local computer, account SSH key access, a trusted server host key,
and `/usr/bin/selectorctl` available to the account. CloudLinux documents end-user execution inside
CageFS from version **7.6.17** onward. Older or restricted hosts may require provider assistance.
No sudo or root fallback is provided.

## Provider limitation: 123 Reg domain isolation

When the account's PHP Selector reports that site isolation has been denied by the server
administrator, report: **Per-domain PHP isolation is unavailable on this account. PHP Selector
versions, extensions, and supported options are managed globally for the cPanel account.**
This is the confirmed configuration of the user's current 123 Reg account, not a claim about
every 123 Reg plan. Reassess only when fresh account evidence or the provider confirms a change.

- For a site-only request, explain the shared scope before proposing any change. Do not silently
  substitute account-wide extension or option changes. Obtain explicit approval for that broader
  impact and the normal mutation confirmation.
- A provider-documented `.htaccess` handler can select an interpreter for a directory; it does not
  establish independent PHP extensions or configuration. Do not offer it as a workaround for
  dependency isolation, or change `.htaccess` merely to satisfy an isolation request.
- Composer libraries can remain project-local, but their PHP runtime and extension requirements
  still depend on the hosting configuration. Do not describe project-local libraries as isolated
  PHP runtimes.
- A `multiphp_ini_editor` feature denial is separate from PHP Selector isolation. Report it as a
  provider-controlled capability restriction, not an authentication or file-permission failure.
- Independent per-domain PHP environments require provider-enabled isolation or a separate
  hosting account/environment. The CLI currently supports only account-level Selector commands;
  provider enablement alone does not add domain-scoped commands to this skill.

Sources: [CloudLinux per-domain isolation](https://docs.cloudlinux.com/cloudlinuxos/isolates/),
[123 Reg per-directory PHP handlers](https://www.123-reg.co.uk/help/set-up-multiple-php-versions-for-linux-hosting-42229).

## Configure SSH

```bash
cpanel-admin profiles configure-ssh staging --port 22 \
  --identity-file ~/.ssh/id_ed25519
```

The SSH username is always the cPanel profile's username. The hostname defaults to the profile's
cPanel host; use `--host ssh.example.com` if your provider supplies a different SSH hostname.
Port and key path are stored in the existing protected profile file. Private key contents and SSH
passwords are never stored there. Omit `--identity-file` to use your SSH agent or default keys.
Explicit key files must be owned regular files with mode `0400` or `0600`.

Confirm the SSH server fingerprint with your hosting provider and install its verified host key
in OpenSSH's known-hosts file before using this capability. Unknown or changed keys are rejected;
the skill does not automatically accept keys. An encrypted private key must already be unlocked
in your SSH agent because connections run without prompts.

Connections ignore SSH configuration files, disable password prompts and forwarding, and use only
fixed selectorctl commands. ProxyCommand, jump-host configuration, arbitrary SSH flags, and shell
commands are not supported. Replacing a cPanel profile with `profiles add --replace` clears its SSH
settings; configure them again if needed. API-token rotation preserves them.

## Representative commands

```bash
cpanel-admin --profile staging php-selector versions
cpanel-admin --profile staging php-selector current
cpanel-admin --profile staging php-selector extensions --version 8.3
cpanel-admin --profile staging php-selector options --version 8.3
cpanel-admin --profile staging php-selector set-version --version 8.3 --dry-run
cpanel-admin --profile staging php-selector enable-extensions \
  --version 8.3 --extensions intl,mbstring --dry-run
cpanel-admin --profile staging php-selector disable-extensions \
  --version 8.3 --extensions xdebug --dry-run
cpanel-admin --profile staging php-selector set-option \
  --version 8.3 --option memory_limit --value 256M --dry-run
```

After approving a plan, repeat the command without `--dry-run`, adding
`--confirm DIGEST --expires-at TIMESTAMP` from the plan. `set-version` also accepts `native`.
Extensions and options require an explicit alternative PHP version.

Reviewed options:

- Booleans: `display_errors`, `display_startup_errors`, `log_errors`, `allow_url_fopen`,
  `file_uploads`, `session.use_strict_mode` (`on`, `off`, `1`, `0`).
- Limits: `memory_limit`, `upload_max_filesize`, `post_max_size` (numbers, optionally K/M/G).
  `memory_limit` also accepts `-1`.
- Integers: `max_execution_time`, `max_input_time`, `max_input_vars`, `max_file_uploads`.
  `max_input_time` also accepts `-1`.

The provider must expose an option before it can be changed. Options outside this list are not
returned or changed. Set an option back to its previous value to roll back; removing overrides and
global resets are not supported.

## Safety notes

- Every mutation requires confirmation. The plan includes the SSH endpoint, account, inputs, and
  previous state. Changed state or endpoint invalidates approval.
- Reads and mutations are audited. A successful mutation is verified by an independent read.
- PHP Selector settings can affect multiple sites within the account. A domain's PHP handler may
  still use MultiPHP or PHP-FPM. Selector verification confirms account configuration, not the PHP
  version actually serving every site; check the website separately.
- Extension changes may affect dependencies or break applications. Compiled-in extensions cannot
  be toggled. The CLI does not install runtime binaries or system packages.
- API tokens and Fernet keys are not sent to the SSH child process. The Fernet key is still required
  locally to sign mutation confirmations. Only non-secret option values are accepted.
- SSH errors and timeouts are reported without raw remote output. Inspect current state before
  retrying a timed-out mutation; remote execution may have continued.
- There is no browser, root, cross-account, or arbitrary-command fallback.
- Tests use simulated SSH output. Live operation remains unverified until tested with a suitable
  disposable hosting account. Unrecognized host output fails rather than implying success.

Source: [CloudLinux selectorctl documentation](https://docs.cloudlinux.com/cloudlinuxos/command-line_tools/#selectorctl).
