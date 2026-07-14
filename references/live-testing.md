# Disposable live testing

Live tests are opt-in checks against a disposable individual cPanel account. They are not part of
the default test suite, and they must never target production hosting.

## Required gates

Set all of these before running live tests:

```bash
export CPANEL_ADMIN_RUN_LIVE_TESTS=1
export CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE
export CPANEL_ADMIN_LIVE_PROFILE=test-123reg
```

The named profile must already exist in the encrypted profile store. The Fernet key must be
available from `CPANEL_ADMIN_FERNET_KEY` or the protected key file documented in the README.
Never print the Fernet key, API token, encrypted profile store, or environment.

## Read-only coverage

Run the representative read-only matrix with:

```bash
.venv/bin/python -m pytest tests/test_live_cpanel.py -m live -v
```

The matrix covers these reviewed command surfaces when the disposable account supports the
corresponding cPanel feature:

- domains
- SSL
- databases
- email
- FTP
- diagnostics
- security controls
- runtime/site operations
- backups
- capability inspection

Some shared-hosting accounts do not expose every cPanel feature. A command may skip only when the
CLI returns the reviewed "operation feature is not available" capability error or cPanel returns a
UAPI application failure that explicitly says the account does not have the required feature.
Network, TLS, authentication, response parsing, policy, confirmation, and unexpected UAPI failures
must fail.

To write a redacted JSON-lines summary without storing raw cPanel response data:

```bash
export CPANEL_ADMIN_LIVE_REPORT=.live/cpanel-read-only.jsonl
.venv/bin/python -m pytest tests/test_live_cpanel.py -m live -v
```

Do not commit `.live/` reports unless every line has been reviewed for sensitive account metadata.

## Disposable mutation coverage

The database lifecycle test creates and removes a uniquely prefixed database. Enable it only on a
disposable account:

```bash
export CPANEL_ADMIN_LIVE_DATABASE_PREFIX=codex_mvp_probe_
.venv/bin/python -m pytest tests/test_live_cpanel.py::test_live_isolated_database_lifecycle -m live -v
```

If cleanup fails, the test output names the leftover database. Remove that resource manually from
cPanel before reusing the account.
