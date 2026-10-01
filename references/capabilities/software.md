# Software capability

## Use when

Manage existing Node.js, Python, and Ruby application source directories through cPanel's
Passenger Application Manager. The host must provide Application Manager and the relevant runtime.
Use `runtime php-*` for the existing PHP version and configuration commands.

Commands: `software list`, `register`, `edit`, `enable`, `disable`, `unregister`, and `dependencies`.
The `runtime passenger-apps` command remains available as the original inventory command.
See `references/operation-support.md` for the reviewed UAPI policy.

## Representative commands

```bash
cpanel-admin --profile staging software list
cpanel-admin --profile staging software register --name my-app \
  --domain app.example.com --path apps/my-app --base-uri / \
  --deployment-mode production --enabled 1 --dry-run
cpanel-admin --profile staging software edit --name my-app \
  --environment-file ./application-environment.json --dry-run
cpanel-admin --profile staging software edit --name my-app --clear-envvars 1 --dry-run
cpanel-admin --profile staging software disable --name my-app --dry-run
cpanel-admin --profile staging software enable --name my-app --dry-run
cpanel-admin --profile staging software unregister --name my-app --dry-run
cpanel-admin --profile staging software dependencies \
  --app-path /home/account/apps/my-app --type npm --dry-run
```

After reviewing and approving a plan, repeat its exact command without `--dry-run` and with
`--confirm DIGEST --expires-at TIMESTAMP` from that plan.

Registration uses a path relative to the account home, such as `apps/my-app`. Editing a path uses
an absolute path below the home directory returned by cPanel. Dependencies require the exact
absolute path of one registered application. Domains must belong to the account.

Environment files must be owned by the current user, regular files, and mode `0600`. Their JSON
object maps variable names to printable ASCII string values, for example `{"APP_MODE":"production"}`.
Use a local editor or secret manager to populate sensitive values. Never paste secrets into chat.
An environment update replaces the entire environment; `--clear-envvars 1` removes it.
Configuration-only edits preserve the current enabled state.

## Safety notes

- Every software mutation requires an expiring confirmation, including dependency installation.
- Preflight reads the application inventory and binds a fingerprint of the current application
  state and requested inputs. Changed state invalidates approval. Environment values are redacted.
- Lifecycle operations read the inventory again to verify the result. Unregistering removes the
  registration and web configuration, not the source files. Disabling interrupts web access.
- Dependencies install from `package.json` (`npm`), `requirements.txt` (`pip`), or `Gemfile` (`gem`).
  Package scripts may execute code with the account's permissions. Review source and manifests
  before approval and keep a backup; the CLI does not create one automatically.
- Dependency success means the job started. The result includes cPanel's task ID and, when supplied,
  its SSE progress path. Completion is not verified by this command. Inspect cPanel's task progress
  and test the application before reporting installation complete. Never retry a timed-out
  installation blindly.
- API support and runtime availability depend on the hosting provider. Failures remain errors.
- Standalone PEAR/CPAN package management, runtime binary installation, WP Toolkit, and Softaculous
  are outside this capability. The pinned UAPI catalog does not expose standalone PEAR/CPAN APIs.
- File paths receive lexical checks; remote symlink resolution and filesystem access remain subject
  to cPanel's account permissions. Use trusted application directories.

Official references: [register application](https://api.docs.cpanel.net/openapi/cpanel/operation/register_application/),
[edit application](https://api.docs.cpanel.net/openapi/cpanel/operation/edit_application/),
[install dependencies](https://api.docs.cpanel.net/openapi/cpanel/operation/ensure_deps/).
