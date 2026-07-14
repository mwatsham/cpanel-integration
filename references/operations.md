# Supported operations

All website operations require global `--profile NAME`. Global options must precede the capability
group. Use `--timeout SECONDS` from 1 to 120 when needed. Every mutation accepts `--dry-run`.

## Profiles

```text
cpanel-admin profiles list
cpanel-admin profiles show NAME
cpanel-admin profiles add NAME --host HOST --username USER --api-token-stdin [--replace]
cpanel-admin profiles test NAME
cpanel-admin profiles rotate-key
cpanel-admin profiles remove NAME --dry-run
cpanel-admin profiles remove NAME --confirm DIGEST --expires-at TIMESTAMP
```

`profiles rotate-key` reads the current key from the normal environment-or-file lookup and the
replacement from `CPANEL_ADMIN_FERNET_KEY_NEW`. Rotation is atomic. Replace the protected key file
only after rotation succeeds. Listing and showing profiles never reveal token ciphertext. Adding a
token reads all input from standard input and strips only final line endings.

## Domains

```text
cpanel-admin --profile NAME domains list
cpanel-admin --profile NAME domains inspect --domain DOMAIN
cpanel-admin --profile NAME domains ssl-capable
cpanel-admin --profile NAME domains add-subdomain \
  --domain LABEL --rootdomain ROOT_DOMAIN --dir RELATIVE_DOCUMENT_ROOT [--dry-run]
```

The subdomain command maps exactly to `SubDomain/addsubdomain` using `domain`, `rootdomain`, and
`dir`. General addon-domain creation and domain deletion are unavailable because current UAPI does
not provide replacements for the deprecated API 2 operations.

## Files

```text
cpanel-admin --profile NAME files list --path RELATIVE_PATH
cpanel-admin --profile NAME files inspect --path RELATIVE_PATH
cpanel-admin --profile NAME files read --directory RELATIVE_PATH --filename NAME
cpanel-admin --profile NAME files write --directory RELATIVE_PATH --filename NAME \
  --content-stdin --dry-run
cpanel-admin --profile NAME files upload --directory RELATIVE_PATH --source LOCAL_FILE --dry-run
cpanel-admin --profile NAME files empty-trash --older-than DAYS --dry-run
```

Write and upload are classified as destructive because a same-named remote file may be overwritten.
Their plans include read-only target preflight metadata and a content hash, never content. Emptying
trash is permanent. Direct delete and move are excluded because Fileman UAPI does not expose them.
Paths must be relative and cannot contain `..`. Local upload, certificate, and key files are limited
to 10 MiB.

## SSL

```text
cpanel-admin --profile NAME ssl list
cpanel-admin --profile NAME ssl hosts
cpanel-admin --profile NAME ssl install --domain DOMAIN \
  --certificate CERT_FILE --private-key KEY_FILE [--cabundle CA_FILE] --dry-run
cpanel-admin --profile NAME ssl remove --domain DOMAIN --dry-run
```

Install and remove are destructive. PEM bodies are loaded locally and represented in plans only by
SHA-256 digest and byte count.

## MySQL and MariaDB

```text
cpanel-admin --profile NAME databases list
cpanel-admin --profile NAME databases users
cpanel-admin --profile NAME databases create --name FULL_NAME [--dry-run]
cpanel-admin --profile NAME databases create-user --name FULL_NAME \
  --password-stdin [--dry-run]
cpanel-admin --profile NAME databases grant --database FULL_NAME --user FULL_NAME \
  --privileges SELECT,INSERT [--dry-run]
cpanel-admin --profile NAME databases remove --name FULL_NAME --dry-run
cpanel-admin --profile NAME databases remove-user --name FULL_NAME --dry-run
```

Use the full names expected by the account's cPanel prefixing policy. The CLI does not silently add
or change prefixes. Supported privileges are validated and canonicalized. Database passwords enter
through standard input only.

## Confirmation syntax

Replace `--dry-run` on a destructive command with the exact values returned by its plan:

```text
--confirm 12_HEX_DIGEST --expires-at ISO_8601_TIMESTAMP
```

The digest expires after five minutes and is bound to the profile, operation, normalized safe
parameters, secret content hashes, file preflight state, and expiry.
