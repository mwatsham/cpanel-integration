# Email capability

## Use when

Use this capability for mailbox accounts, quotas, passwords, forwarders, autoresponders, filters,
spam controls, MX routing, SPF, DKIM, DMARC validation, greylisting reads, and mail SNI state within
one individual cPanel account.

Do not use it for mailbox browsing, message-body access, queue deletion, mailbox expunge, server
mail services, or root/reseller mail administration. See `references/operation-support.md` for the
exact included and excluded email operations.

## Representative commands

```bash
cpanel-admin --profile production email accounts
cpanel-admin --profile production email accounts-disk --domain example.com
cpanel-admin --profile production email forwarders --domain example.com
cpanel-admin --profile production email mx-list --domain example.com
cpanel-admin --profile production email routing-mode --domain example.com --mxcheck auto --dry-run
cpanel-admin --profile production email create-account --email admin --domain example.com --password-stdin --dry-run
cpanel-admin --profile production email validate-dmarc --domain example.com
```

## Safety notes

- Mailbox creation, password changes, routing changes, forwarders, filters, spam settings, SPF, and
  DKIM changes mutate account state. Run `--dry-run` first.
- Deletions of mailboxes, forwarders, filters, autoresponders, and MX records are destructive and
  require expiring confirmation.
- Supply mailbox passwords and private DKIM keys only through standard input or protected files.
- Do not inspect or expose message contents; this skill administers configuration only.
- The authoritative support matrix is `references/operation-support.md`.
