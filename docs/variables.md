# Variable reference

Generated from `service/variables.tf`. See that file and `service/README.md` for full detail; deployment-specific values live only in the Terragrunt leaf.

| Variable | Type | Default | Description |
|---|---|---|---|
| `service_name` | `string` | `(required)` | Name of the Fastly VCL delivery service, e.g. \"waf-staging\". |
| `domains` | `list(string)` | `(required)` | Public hostnames this service answers for (the customer vhosts). Order-insensitive. |
| `activate` | `bool` | `true` | Activate the newest service version on apply. Leave true; set false to stage a version for manual activation. |
| `default_ttl` | `number` | `3600` | Default cache TTL (seconds) for cacheable responses with no explicit lifetime. |
| `backend_address` | `string` | `(required)` | Origin address Fastly fetches from (the app server, e.g. the origin's public IP or a locked-down origin hostname). Cus… |
| `backend_port` | `number` | `443` | Origin port. |
| `backend_name` | `string` | `"origin"` | Label for the origin backend. |
| `override_host` | `string` | `""` | Host header Fastly sends to the origin (the real customer vhost). Usually the primary entry in var.domains. Empty = se… |
| `origin_tls` | `bool` | `true` | Connect to the origin over TLS (strongly recommended; mirrors the production Fastly posture). |
| `origin_sni_hostname` | `string` | `""` | SNI hostname presented to the origin. Defaults to override_host when empty. |
| `origin_cert_hostname` | `string` | `""` | Hostname the origin certificate is validated against. Defaults to override_host when empty. |
| `origin_check_cert` | `bool` | `true` | Verify the origin TLS certificate. Keep true in production. May be set false ONLY on a staging origin that serves a sn… |
| `origin_shield` | `string` | `""` | Fastly shield POP (e.g. \"sydney-au\") for origin shielding and tiered cache. Empty = no shield. |
| `backend_connect_timeout` | `number` | `5000` | Origin TCP connect timeout (ms). |
| `backend_first_byte_timeout` | `number` | `60000` | Origin first-byte timeout (ms). Generous enough to ride slow origin request handling; a slow-origin runaway should be … |
| `backend_between_bytes_timeout` | `number` | `30000` | Origin between-bytes timeout (ms). |
| `backend_min_tls_version` | `string` | `"1.2"` | Minimum TLS version to the origin. |
| `health_check_path` | `string` | `"/robots.txt"` | Path the health check requests. Must be cheap and WAF/auth-exempt at the origin (e.g. a static 200). A path the WAF or… |
| `health_check_expected_response` | `number` | `200` | HTTP status the health check treats as healthy. |
| `health_check_host` | `string` | `""` | Host header for the health check. Defaults to override_host when empty. |
| `health_check_window` | `number` | `10` | Number of recent probes considered. |
| `health_check_threshold` | `number` | `3` | Successful probes (within the window) required to be healthy. Low vs window = warmup-tolerant. |
| `health_check_interval` | `number` | `15000` | Probe interval (ms). |
| `health_check_initial` | `number` | `8` | Probes assumed successful before the first real result (keeps the backend up through a deploy). |
| `manage_service` | `bool` | `true` | Manage the Fastly VCL delivery service (domains, origin backend, TLS, health check, headers, cache, logging). |
| `manage_ngwaf_workspace` | `bool` | `true` | Manage the Next-Gen WAF workspace (the WAF brain: mode, inline attack-signal blocking, client-IP headers). |
| `manage_ngwaf_edge` | `bool` | `true` | Attach the NGWAF workspace to the delivery service at the edge (product_enablement.ngwaf). CREATE-ONLY: adoption skips… |
| `manage_ngwaf_signals` | `bool` | `true` | Manage the custom NGWAF signals (categories the system signal set does not cover: ColdFusion/CFML, cred-hunt, WP probe… |
| `manage_ngwaf_rules` | `bool` | `true` | Manage the NGWAF request rules: the CMS signal-exclusion (false-positive safety) and the per-category block rules. |
| `manage_ngwaf_rate_limits` | `bool` | `true` | Manage the NGWAF rate-limit rules (the feed cache-buster abuse backstop, the CFIDE/admin login ceiling). |
| `manage_ngwaf_thresholds` | `bool` | `true` | Manage the attack-signal repeat-offender threshold backstop (a SECOND layer; per-request blocking is the primary gate). |
| `manage_ngwaf_virtual_patches` | `bool` | `false` | Manage Fastly NGWAF virtual patches (CVE templates, e.g. Log4Shell/Spring4Shell). Off by default: the available virtua… |
| `manage_tls` | `bool` | `false` | Manage the Fastly TLS subscription for var.domains. OFF by default: TLS subscriptions are ordering/validation-sensitiv… |
| `manage_logging` | `bool` | `false` | Manage the syslog logging endpoint shipping Fastly access logs to the log stack. |
| `tls_certificate_authority` | `string` | `"lets-encrypt"` | ACME CA for the TLS subscription when manage_tls = true: certainly, lets-encrypt or globalsign. |
| `ngwaf_mode` | `string` | `"block"` | Workspace operating mode. \"block\" = enforce (production), \"log\" = observe only (staging/grading with the efficacy … |
| `ngwaf_immediate_block` | `bool` | `true` | Block immediately (per-request) when ANY attack signal is detected, instead of waiting for a per-IP count threshold. T… |
| `ngwaf_block_response_code` | `number` | `406` | HTTP status returned on a block. 406 matches the NGWAF default and is what the efficacy harness fingerprints as a Fast… |
| `ngwaf_client_ip_headers` | `list(string)` | `["Fastly-Client-IP"]` | Headers NGWAF trusts for the real client IP. Fastly-Client-IP is set by Fastly from the real edge connection; keep it … |
| `ngwaf_ip_anonymization` | `string` | `""` | IP anonymization for stored events. \"hashed\" or empty. |
| `ngwaf_edge_ramp` | `number` | `100` | Percentage (0-100) of edge traffic the NGWAF workspace inspects at the edge attachment. Ramp 10 -> 50 -> 100 during th… |
| `feed_cachebuster_path` | `string` | `""` | Exact path of a high-cost dynamic JSON endpoint targeted by cache-busting abuse. Empty (default) = no feed-specific co… |
| `feed_cache_normalize` | `bool` | `false` | Enable the VCL that strips the query string on var.feed_cachebuster_path so all cache-buster variants collapse to one |
| `feed_cache_ttl` | `number` | `30` | TTL (seconds) for the normalized a high-cost dynamic JSON feed object (when feed_cache_normalize = true). Short, so da… |
| `ngwaf_attack_thresholds` | `object(` | `{}` | Repeat-offender backstop counts for the attack-signal thresholds block (one_minute/ten_minutes/one_hour). Deliberately… |
| `trusted_exemption_ips` | `list(string)` | `[]` | IPs/CIDRs exempt from BODY XSS/SQLI blocking on the CMS admin + JSON-API paths ONLY (e.g. a trusted office IP, CMS-edi… |
| `cms_admin_paths` | `list(string)` | `[]` | the CMS admin path prefixes where trusted editors legitimately POST rich-text/HTML that trips XSS/SQLI (e.g. [\"/admin… |
| `cms_json_api_paths` | `list(string)` | `[]` | the CMS JSON-API path prefixes trusted editors use (e.g. [\"/index.cfm/_api/json\", \"/rest\"]). |
| `cms_exempt_signals` | `list(string)` | `["SQLI", "XSS"]` | Which signals the scoped CMS exemption removes for trusted editors. Default ["SQLI","XSS"] - the signals that |
| `signal_pattern_overrides` | `map(list(string))` | `{}` | Map of custom-category key => list(string) of match patterns, merged OVER the baseline in locals.tf |
| `custom_category_disable` | `list(string)` | `[]` | List of baseline custom-category keys to NOT emit a block rule for (keeps the signal/metrics, drops the block) - for l… |
| `rate_limits` | `any` | `{}` | Map of rate-limit key => definition, merged OVER the baseline in locals.tf (the feed, CFIDE login); |
| `virtual_patches` | `map(object(` | `{}` | Curated map of CVE id => { action (log\|block, default block), enabled (default true) }, keyed by the bare CVE |
| `ngwaf_virtual_patch_force_log` | `bool` | `false` | Force EVERY managed virtual patch to action=log regardless of its per-CVE setting. Use during the staging/grading phas… |
| `origin_secret_header` | `string` | `"X-Origin-Secret"` | Header name injected toward the origin for origin-lockdown. The origin nginx must require it. |
| `origin_secret_value` | `string` | `""` | Shared-secret value for origin_secret_header. Sensitive; supply from Secrets Manager via the leaf. Empty = do not inje… |
| `syslog_address` | `string` | `""` | Syslog endpoint (host:port) for Fastly access logs shipped to the log stack. Required when manage_logging = true. |
| `syslog_tls_hostname` | `string` | `""` | TLS hostname for the syslog endpoint (enables TLS when set). |

_58 inputs._
