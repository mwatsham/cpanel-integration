# Domains capability

## Use when

Use this capability to list account domains, inspect a single domain, discover SSL-capable domains,
and create reviewed subdomains.

Do not use it for WHM account creation, addon-domain lifecycle through deprecated API 2, raw DNS-zone
edits, dynamic DNS, or browser automation. See `references/operation-support.md` for the exact
included and excluded domain operations.

## Representative commands

```bash
cpanel-admin --profile production domains list
cpanel-admin --profile production domains inspect --domain example.com
cpanel-admin --profile production domains ssl-capable
cpanel-admin --profile production domains add-subdomain --domain app --rootdomain example.com --dir public_html/app --dry-run
```

## Safety notes

- Subdomain creation mutates routing and document-root state. Run `--dry-run` first.
- Verify the document root before creating a subdomain to avoid pointing traffic at the wrong files.
- Deprecated addon-domain create/delete fallbacks are intentionally excluded.
- DNS-zone editing is not exposed as arbitrary passthrough.
- The authoritative support matrix is `references/operation-support.md`.
