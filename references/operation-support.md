# cPanel Operation Support Matrix

> Generated from the pinned cPanel OpenAPI document and reviewed policy. Do not edit manually.

- Source UAPI version: `11.136.0.25`
- Source SHA-256: `3d9ec80cd8d774312c4bb6b0dfdbc17e6e6ffc92a8f0c2cd88f01e32864fa2c6`
- Included operations: 80
- Excluded operations: 313

The local allowlist is an application safeguard, not a substitute for cPanel account permissions. This catalog does not provide arbitrary UAPI passthrough.

| Canonical operation | Status | Capability | Risk | Reason |
| --- | --- | --- | --- | --- |
| `AccountEnhancements/has_enhancement` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `AccountEnhancements/list` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Backup/fullbackup_to_ftp` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/fullbackup_to_homedir` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/fullbackup_to_scp_with_key` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/fullbackup_to_scp_with_password` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/list_backups` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/restore_databases` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/restore_email_filters` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/restore_email_forwarders` | excluded | backups | - | not enabled until the backup capability review |
| `Backup/restore_files` | excluded | backups | - | not enabled until the backup capability review |
| `Bandwidth/get_enabled_protocols` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Bandwidth/get_retention_periods` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Bandwidth/query` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `BlockIP/add_ip` | excluded | security | - | not enabled until the security capability review |
| `BlockIP/remove_ip` | excluded | security | - | not enabled until the security capability review |
| `Chkservd/get_exim_ports` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Chkservd/get_exim_ports_ssl` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `ClamScanner/check_disinfection_status` | excluded | security | - | not enabled until the security capability review |
| `ClamScanner/disinfect_files` | excluded | security | - | not enabled until the security capability review |
| `ClamScanner/get_scan_paths` | excluded | security | - | not enabled until the security capability review |
| `ClamScanner/get_scan_status` | excluded | security | - | not enabled until the security capability review |
| `ClamScanner/list_infected_files` | excluded | security | - | not enabled until the security capability review |
| `ClamScanner/start_scan` | excluded | security | - | not enabled until the security capability review |
| `ContactInformation/get_notification_preferences` | excluded | security | - | not enabled until the security capability review |
| `ContactInformation/get_pushbullet_access_token` | excluded | security | - | not enabled until the security capability review |
| `ContactInformation/set_email_addresses` | excluded | security | - | not enabled until the security capability review |
| `ContactInformation/set_notification_preferences` | excluded | security | - | not enabled until the security capability review |
| `ContactInformation/set_pushbullet_access_token` | excluded | security | - | not enabled until the security capability review |
| `ContactInformation/unset_email_addresses` | excluded | security | - | not enabled until the security capability review |
| `DCV/check_domains_via_dns` | excluded | ssl | - | not enabled until the ssl capability review |
| `DCV/check_domains_via_http` | excluded | ssl | - | not enabled until the ssl capability review |
| `DCV/ensure_domains_can_pass_dcv` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNS/ensure_domains_reside_only_locally` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/fetch_cpanel_generated_domains` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/has_local_authority` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/is_alias_available` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/is_https_available` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/is_svcb_available` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/lookup` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/mass_edit_zone` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/parse_zone` | excluded | domains | - | not enabled until the domain capability review |
| `DNS/swap_ip_in_zones` | excluded | domains | - | not enabled until the domain capability review |
| `DNSSEC/activate_zone_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/add_zone_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/deactivate_zone_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/disable_dnssec` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/enable_dnssec` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/export_zone_dnskey` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/export_zone_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/fetch_ds_records` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/import_zone_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/remove_zone_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/set_nsec3` | excluded | ssl | - | not enabled until the ssl capability review |
| `DNSSEC/unset_nsec3` | excluded | ssl | - | not enabled until the ssl capability review |
| `DirectoryIndexes/get_indexing` | excluded | files | - | not enabled until the file capability review |
| `DirectoryIndexes/list_directories` | excluded | files | - | not enabled until the file capability review |
| `DirectoryIndexes/set_indexing` | excluded | files | - | not enabled until the file capability review |
| `DirectoryPrivacy/add_user` | excluded | files | - | not enabled until the file capability review |
| `DirectoryPrivacy/configure_directory_protection` | excluded | files | - | not enabled until the file capability review |
| `DirectoryPrivacy/delete_user` | excluded | files | - | not enabled until the file capability review |
| `DirectoryPrivacy/is_directory_protected` | excluded | files | - | not enabled until the file capability review |
| `DirectoryPrivacy/list_directories` | excluded | files | - | not enabled until the file capability review |
| `DirectoryPrivacy/list_users` | excluded | files | - | not enabled until the file capability review |
| `DirectoryProtection/list_directories` | excluded | files | - | not enabled until the file capability review |
| `Domain/convert_temporary_to_registered` | excluded | domains | - | not enabled until the domain capability review |
| `Domain/is_temporary_domain` | excluded | domains | - | not enabled until the domain capability review |
| `Domain/temporary_domain_is_disabled` | excluded | domains | - | not enabled until the domain capability review |
| `DomainInfo/domains_data` | excluded | domains | - | not enabled until the domain capability review |
| `DomainInfo/list_domains` | included | domains | read | supported by the existing MVP operation set |
| `DomainInfo/main_domain_builtin_subdomain_aliases` | excluded | domains | - | not enabled until the domain capability review |
| `DomainInfo/primary_domain` | excluded | domains | - | not enabled until the domain capability review |
| `DomainInfo/single_domain_data` | included | domains | read | supported by the existing MVP operation set |
| `DynamicDNS/create` | excluded | domains | - | not enabled until the domain capability review |
| `DynamicDNS/delete` | excluded | domains | - | not enabled until the domain capability review |
| `DynamicDNS/list` | excluded | domains | - | not enabled until the domain capability review |
| `DynamicDNS/recreate` | excluded | domains | - | not enabled until the domain capability review |
| `DynamicDNS/set_description` | excluded | domains | - | not enabled until the domain capability review |
| `Email/account_name` | included | email | read | reviewed email account administration operation |
| `Email/add_auto_responder` | included | email | mutate | reviewed email administration operation |
| `Email/add_domain_forwarder` | excluded | email | - | not enabled until the email capability review |
| `Email/add_forwarder` | included | email | mutate | reviewed email administration operation |
| `Email/add_list` | excluded | email | - | not enabled until the email capability review |
| `Email/add_mailman_delegates` | excluded | email | - | not enabled until the email capability review |
| `Email/add_mx` | included | email | mutate | reviewed email administration operation |
| `Email/add_pop` | included | email | mutate | reviewed email administration operation |
| `Email/add_spam_filter` | excluded | email | - | not enabled until the email capability review |
| `Email/browse_mailbox` | excluded | email | - | not enabled until the email capability review |
| `Email/change_mx` | included | email | mutate | reviewed email administration operation |
| `Email/check_fastmail` | excluded | email | - | not enabled until the email capability review |
| `Email/count_auto_responders` | excluded | email | - | not enabled until the email capability review |
| `Email/count_filters` | excluded | email | - | not enabled until the email capability review |
| `Email/count_forwarders` | excluded | email | - | not enabled until the email capability review |
| `Email/count_lists` | excluded | email | - | not enabled until the email capability review |
| `Email/count_pops` | included | email | read | reviewed email account administration operation |
| `Email/delete_auto_responder` | included | email | destructive | reviewed email administration operation |
| `Email/delete_domain_forwarder` | excluded | email | - | not enabled until the email capability review |
| `Email/delete_filter` | included | email | destructive | reviewed email administration operation |
| `Email/delete_forwarder` | included | email | destructive | reviewed email administration operation |
| `Email/delete_held_messages` | excluded | email | - | not enabled until the email capability review |
| `Email/delete_list` | excluded | email | - | not enabled until the email capability review |
| `Email/delete_mx` | included | email | destructive | reviewed email administration operation |
| `Email/delete_pop` | included | email | destructive | reviewed email administration operation |
| `Email/disable_filter` | included | email | mutate | reviewed email administration operation |
| `Email/disable_mailbox_autocreate` | included | email | mutate | reviewed email account administration operation |
| `Email/disable_spam_assassin` | included | email | mutate | reviewed email administration operation |
| `Email/disable_spam_autodelete` | excluded | email | - | not enabled until the email capability review |
| `Email/disable_spam_box` | included | email | mutate | reviewed email administration operation |
| `Email/dispatch_client_settings` | excluded | email | - | not enabled until the email capability review |
| `Email/edit_pop_quota` | included | email | mutate | reviewed email administration operation |
| `Email/enable_filter` | included | email | mutate | reviewed email administration operation |
| `Email/enable_mailbox_autocreate` | included | email | mutate | reviewed email account administration operation |
| `Email/enable_spam_assassin` | included | email | mutate | reviewed email administration operation |
| `Email/enable_spam_box` | included | email | mutate | reviewed email administration operation |
| `Email/export_lists` | excluded | email | - | not enabled until the email capability review |
| `Email/fetch_charmaps` | excluded | email | - | not enabled until the email capability review |
| `Email/fts_rescan_mailbox` | excluded | email | - | not enabled until the email capability review |
| `Email/generate_mailman_otp` | excluded | email | - | not enabled until the email capability review |
| `Email/get_auto_responder` | excluded | email | - | not enabled until the email capability review |
| `Email/get_charsets` | excluded | email | - | not enabled until the email capability review |
| `Email/get_client_settings` | excluded | email | - | not enabled until the email capability review |
| `Email/get_default_email_quota` | included | email | read | reviewed email account administration operation |
| `Email/get_default_email_quota_mib` | included | email | read | reviewed email account administration operation |
| `Email/get_disk_usage` | included | email | read | reviewed email account administration operation |
| `Email/get_filter` | excluded | email | - | not enabled until the email capability review |
| `Email/get_held_message_count` | excluded | email | - | not enabled until the email capability review |
| `Email/get_lists_total_disk_usage` | excluded | email | - | not enabled until the email capability review |
| `Email/get_mailbox_autocreate` | included | email | read | reviewed email account administration operation |
| `Email/get_mailman_delegates` | excluded | email | - | not enabled until the email capability review |
| `Email/get_main_account_disk_usage` | included | email | read | reviewed email account administration operation |
| `Email/get_main_account_disk_usage_bytes` | included | email | read | reviewed email account administration operation |
| `Email/get_max_email_quota` | included | email | read | reviewed email account administration operation |
| `Email/get_max_email_quota_mib` | included | email | read | reviewed email account administration operation |
| `Email/get_pop_quota` | included | email | read | reviewed email account administration operation |
| `Email/get_spam_settings` | included | email | read | reviewed email administration operation |
| `Email/get_webmail_settings` | excluded | email | - | not enabled until the email capability review |
| `Email/has_delegated_mailman_lists` | excluded | email | - | not enabled until the email capability review |
| `Email/has_plaintext_authentication` | excluded | email | - | not enabled until the email capability review |
| `Email/hold_outgoing` | included | email | mutate | reviewed email account administration operation |
| `Email/list_auto_responders` | included | email | read | reviewed email administration operation |
| `Email/list_default_address` | excluded | email | - | not enabled until the email capability review |
| `Email/list_domain_forwarders` | excluded | email | - | not enabled until the email capability review |
| `Email/list_filters` | included | email | read | reviewed email administration operation |
| `Email/list_filters_backups` | excluded | email | - | not enabled until the email capability review |
| `Email/list_forwarders` | included | email | read | reviewed email administration operation |
| `Email/list_forwarders_backups` | excluded | email | - | not enabled until the email capability review |
| `Email/list_lists` | excluded | email | - | not enabled until the email capability review |
| `Email/list_mail_domains` | included | email | read | reviewed email account administration operation |
| `Email/list_mxs` | included | email | read | reviewed email administration operation |
| `Email/list_pops` | included | email | read | reviewed email administration operation |
| `Email/list_pops_with_disk` | included | email | read | reviewed email account administration operation |
| `Email/list_system_filter_info` | excluded | email | - | not enabled until the email capability review |
| `Email/passwd_list` | excluded | email | - | not enabled until the email capability review |
| `Email/passwd_pop` | included | email | mutate | reviewed email administration operation |
| `Email/release_outgoing` | included | email | mutate | reviewed email account administration operation |
| `Email/remove_mailman_delegates` | excluded | email | - | not enabled until the email capability review |
| `Email/reorder_filters` | excluded | email | - | not enabled until the email capability review |
| `Email/set_always_accept` | excluded | email | - | not enabled until the email capability review |
| `Email/set_default_address` | excluded | email | - | not enabled until the email capability review |
| `Email/set_list_privacy_options` | excluded | email | - | not enabled until the email capability review |
| `Email/set_manual_mx_redirects` | included | email | mutate | reviewed email administration operation |
| `Email/stats_db_status` | excluded | email | - | not enabled until the email capability review |
| `Email/store_filter` | excluded | email | - | not enabled until the email capability review |
| `Email/suspend_incoming` | included | email | mutate | reviewed email account administration operation |
| `Email/suspend_login` | included | email | mutate | reviewed email account administration operation |
| `Email/suspend_outgoing` | included | email | mutate | reviewed email account administration operation |
| `Email/terminate_mailbox_sessions` | included | email | mutate | reviewed email account administration operation |
| `Email/trace_delivery` | excluded | email | - | not enabled until the email capability review |
| `Email/trace_filter` | excluded | email | - | not enabled until the email capability review |
| `Email/unset_manual_mx_redirects` | included | email | mutate | reviewed email administration operation |
| `Email/unsuspend_incoming` | included | email | mutate | reviewed email account administration operation |
| `Email/unsuspend_login` | included | email | mutate | reviewed email account administration operation |
| `Email/unsuspend_outgoing` | included | email | mutate | reviewed email account administration operation |
| `Email/verify_password` | included | email | read | reviewed email account administration operation |
| `EmailAuth/apply_dmarc` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/disable_dkim` | included | email | destructive | reviewed email DNS administration operation |
| `EmailAuth/enable_dkim` | included | email | mutate | reviewed email DNS administration operation |
| `EmailAuth/ensure_dkim_keys_exist` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/fetch_dkim_private_keys` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/install_dkim_private_keys` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/install_spf_records` | included | email | mutate | reviewed email DNS administration operation |
| `EmailAuth/remove_dmarc` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/validate_current_dkims` | included | email | read | reviewed email DNS administration operation |
| `EmailAuth/validate_current_dmarcs` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/validate_current_ptrs` | excluded | email | - | not enabled until the email capability review |
| `EmailAuth/validate_current_spfs` | included | email | read | reviewed email DNS administration operation |
| `Features/get_feature_metadata` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Features/has_feature` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Features/has_features_like` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Features/list_features` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Features/list_features_like` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Fileman/autocompletedir` | excluded | files | - | not enabled until the file capability review |
| `Fileman/empty_trash` | included | files | destructive | supported by the existing MVP operation set |
| `Fileman/get_file_content` | included | files | read | supported by the existing MVP operation set |
| `Fileman/get_file_information` | included | files | read | supported by the existing MVP operation set |
| `Fileman/list_files` | included | files | read | supported by the existing MVP operation set |
| `Fileman/save_file_content` | included | files | destructive | supported by the existing MVP operation set |
| `Fileman/transcode` | excluded | files | - | not enabled until the file capability review |
| `Fileman/upload_files` | included | files | destructive | supported by the existing MVP operation set |
| `Ftp/add_ftp` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/allows_anonymous_ftp` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/allows_anonymous_ftp_incoming` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/delete_ftp` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/ftp_exists` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/get_ftp_daemon_info` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/get_port` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/get_quota` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/get_welcome_message` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/kill_session` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/list_ftp` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/list_ftp_with_disk` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/list_sessions` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/passwd` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/server_name` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/set_anonymous_ftp` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/set_anonymous_ftp_incoming` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/set_homedir` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/set_quota` | excluded | ftp | - | not enabled until the ftp capability review |
| `Ftp/set_welcome_message` | excluded | ftp | - | not enabled until the ftp capability review |
| `KnownHosts/create` | excluded | security | - | not enabled until the security capability review |
| `KnownHosts/delete` | excluded | security | - | not enabled until the security capability review |
| `KnownHosts/update` | excluded | security | - | not enabled until the security capability review |
| `KnownHosts/verify` | excluded | security | - | not enabled until the security capability review |
| `LangPHP/php_get_domain_handler` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_get_impacted_domains` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_get_installed_versions` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_get_system_default_version` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_get_vhost_versions` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_ini_get_user_basic_directives` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_ini_get_user_content` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_ini_get_user_paths` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_ini_set_user_basic_directives` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_ini_set_user_content` | excluded | runtime | - | not enabled until the runtime capability review |
| `LangPHP/php_set_vhost_versions` | excluded | runtime | - | not enabled until the runtime capability review |
| `LastLogin/get_last_or_current_logged_in_ip` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `LogManager/delete_archive` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `LogManager/get_settings` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `LogManager/list_archives` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `LogManager/set_settings` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Mailboxes/expunge_mailbox_messages` | excluded | email | - | not enabled until the email capability review |
| `Mailboxes/expunge_messages_for_mailbox_guid` | excluded | email | - | not enabled until the email capability review |
| `Mailboxes/get_mailbox_status_list` | included | email | read | reviewed email account administration operation |
| `Mailboxes/has_utf8_mailbox_names` | included | email | read | reviewed email account administration operation |
| `Mailboxes/set_utf8_mailbox_names` | included | email | mutate | reviewed email account administration operation |
| `Mime/add_handler` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/add_hotlink` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/add_mime` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/add_redirect` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/delete_handler` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/delete_hotlink` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/delete_mime` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/delete_redirect` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/get_redirect` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/list_handlers` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/list_hotlinks` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/list_mime` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/list_redirects` | excluded | domains | - | not enabled until the domain capability review |
| `Mime/redirect_info` | excluded | domains | - | not enabled until the domain capability review |
| `ModSecurity/disable_all_domains` | excluded | security | - | not enabled until the security capability review |
| `ModSecurity/disable_domains` | excluded | security | - | not enabled until the security capability review |
| `ModSecurity/enable_all_domains` | excluded | security | - | not enabled until the security capability review |
| `ModSecurity/enable_domains` | excluded | security | - | not enabled until the security capability review |
| `ModSecurity/has_modsecurity_installed` | excluded | security | - | not enabled until the security capability review |
| `ModSecurity/list_domains` | excluded | security | - | not enabled until the security capability review |
| `Mysql/add_host` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/add_host_note` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/check_database` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/create_database` | included | databases | mutate | supported by the existing MVP operation set |
| `Mysql/create_user` | included | databases | mutate | supported by the existing MVP operation set |
| `Mysql/delete_database` | included | databases | destructive | supported by the existing MVP operation set |
| `Mysql/delete_host` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/delete_user` | included | databases | destructive | supported by the existing MVP operation set |
| `Mysql/dump_database_schema` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/get_host_notes` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/get_privileges_on_database` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/get_restrictions` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/get_server_information` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/list_databases` | included | databases | read | supported by the existing MVP operation set |
| `Mysql/list_routines` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/list_users` | included | databases | read | supported by the existing MVP operation set |
| `Mysql/locate_server` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/rename_database` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/rename_user` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/repair_database` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/revoke_access_to_database` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/set_password` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/set_privileges_on_database` | included | databases | mutate | supported by the existing MVP operation set |
| `Mysql/setup_db_and_user` | excluded | databases | - | not enabled until the database capability review |
| `Mysql/update_privileges` | excluded | databases | - | not enabled until the database capability review |
| `NginxCaching/clear_cache` | excluded | runtime | - | not enabled until the runtime capability review |
| `NginxCaching/disable_cache` | excluded | runtime | - | not enabled until the runtime capability review |
| `NginxCaching/enable_cache` | excluded | runtime | - | not enabled until the runtime capability review |
| `NginxCaching/reset_cache_config` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/disable_application` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/edit_application` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/enable_application` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/ensure_deps` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/list_applications` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/register_application` | excluded | runtime | - | not enabled until the runtime capability review |
| `PassengerApps/unregister_application` | excluded | runtime | - | not enabled until the runtime capability review |
| `Quota/get_local_quota_info` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Quota/get_quota_info` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `ResourceUsage/get_usages` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Restore/directory_listing` | excluded | backups | - | not enabled until the backup capability review |
| `Restore/get_users` | excluded | backups | - | not enabled until the backup capability review |
| `Restore/query_file_info` | excluded | backups | - | not enabled until the backup capability review |
| `Restore/restore_file` | excluded | backups | - | not enabled until the backup capability review |
| `SSH/get_port` | excluded | security | - | not enabled until the security capability review |
| `SSL/add_autossl_excluded_domains` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/can_ssl_redirect` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/check_shared_cert` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/delete_cert` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/delete_csr` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/delete_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/delete_ssl` | included | ssl | destructive | supported by the existing MVP operation set |
| `SSL/disable_mail_sni` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/enable_mail_sni` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/fetch_best_for_domain` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/fetch_cert_info` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/fetch_certificates_for_fqdns` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/fetch_key_and_cabundle_for_certificate` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/find_certificates_for_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/find_csrs_for_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/generate_cert` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/generate_csr` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/generate_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/get_autossl_excluded_domains` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/get_autossl_problems` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/get_autossl_renewal_status` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/get_cabundle` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/get_cn_name` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/install_ssl` | included | ssl | destructive | supported by the existing MVP operation set |
| `SSL/installed_host` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/installed_hosts` | included | ssl | read | supported by the existing MVP operation set |
| `SSL/is_autossl_check_in_progress` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/is_mail_sni_supported` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/is_sni_supported` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/list_certs` | included | ssl | read | supported by the existing MVP operation set |
| `SSL/list_csrs` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/list_keys` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/list_ssl_items` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/mail_sni_status` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/rebuild_mail_sni_config` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/rebuildssldb` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/remove_autossl_excluded_domains` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/set_autossl_excluded_domains` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/set_cert_friendly_name` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/set_csr_friendly_name` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/set_default_key_type` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/set_key_friendly_name` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/set_primary_ssl` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/show_cert` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/show_csr` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/show_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/start_autossl_check` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/toggle_ssl_redirect_for_domains` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/upload_cert` | excluded | ssl | - | not enabled until the ssl capability review |
| `SSL/upload_key` | excluded | ssl | - | not enabled until the ssl capability review |
| `ServerInformation/get_information` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `SpamAssassin/clear_spam_box` | excluded | email | - | not enabled until the email capability review |
| `SpamAssassin/get_symbolic_test_names` | excluded | email | - | not enabled until the email capability review |
| `SpamAssassin/get_user_preferences` | excluded | email | - | not enabled until the email capability review |
| `SpamAssassin/update_user_preference` | excluded | email | - | not enabled until the email capability review |
| `Stats/get_bandwidth` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Stats/get_site_errors` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Stats/get_stats_daily` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Stats/list_sites` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Stats/list_stats_by_domain` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `StatsBar/get_stats` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `StatsManager/get_configuration` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `StatsManager/save_configuration` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `SubDomain/addsubdomain` | included | domains | mutate | supported by the existing MVP operation set |
| `SubDomain/changedocroot` | excluded | domains | - | not enabled until the domain capability review |
| `UserTasks/delete` | excluded | security | - | not enabled until the security capability review |
| `UserTasks/retrieve` | excluded | security | - | not enabled until the security capability review |
| `Variables/get_server_information` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Variables/get_session_information` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `Variables/get_user_information` | excluded | diagnostics | - | not enabled until the diagnostics capability review |
| `VersionControl/create` | excluded | runtime | - | not enabled until the runtime capability review |
| `VersionControl/delete` | excluded | runtime | - | not enabled until the runtime capability review |
| `VersionControl/retrieve` | excluded | runtime | - | not enabled until the runtime capability review |
| `VersionControl/update` | excluded | runtime | - | not enabled until the runtime capability review |
| `VersionControlDeployment/create` | excluded | runtime | - | not enabled until the runtime capability review |
| `VersionControlDeployment/delete` | excluded | runtime | - | not enabled until the runtime capability review |
| `VersionControlDeployment/retrieve` | excluded | runtime | - | not enabled until the runtime capability review |
| `WebVhosts/list_domains` | excluded | domains | - | not enabled until the domain capability review |
| `WebVhosts/list_ssl_capable_domains` | included | domains | read | supported by the existing MVP operation set |
| `cPGreyList/disable_all_domains` | excluded | email | - | not enabled until the email capability review |
| `cPGreyList/disable_domains` | excluded | email | - | not enabled until the email capability review |
| `cPGreyList/enable_all_domains` | excluded | email | - | not enabled until the email capability review |
| `cPGreyList/enable_domains` | excluded | email | - | not enabled until the email capability review |
| `cPGreyList/has_greylisting_enabled` | excluded | email | - | not enabled until the email capability review |
| `cPGreyList/list_domains` | excluded | email | - | not enabled until the email capability review |
