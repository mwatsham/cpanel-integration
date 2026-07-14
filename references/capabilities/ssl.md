# SSL capability

## Use when

Use this capability to list stored certificates, inspect installed SSL hosts, install a certificate,
or remove an installed certificate for one individual cPanel account.

Do not use it for private-key export, DNSSEC administration, unrestricted DCV operations, AutoSSL
policy changes, WHM SSL management, or server-wide certificate administration. See
`references/operation-support.md` for the exact included and excluded SSL operations.

## Representative commands

```bash
cpanel-admin --profile production ssl list
cpanel-admin --profile production ssl hosts
cpanel-admin --profile production ssl install --domain example.com --certificate ./cert.pem --private-key ./key.pem --cabundle ./ca.pem --dry-run
cpanel-admin --profile production ssl remove --domain example.com --dry-run
```

## Safety notes

- SSL installation and removal are destructive because they can interrupt HTTPS. Run `--dry-run`
  first.
- Keep the prior certificate, private key, and CA bundle in a secure backup before replacement.
- Private keys must come from protected local files and must never be printed or committed.
- Verify installed hosts after any certificate change.
- The authoritative support matrix is `references/operation-support.md`.
