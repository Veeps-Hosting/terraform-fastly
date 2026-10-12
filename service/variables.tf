# ---------------------------------------------------------------------------------------------------------------------
# SERVICE IDENTITY + DELIVERY (CDN)
# ---------------------------------------------------------------------------------------------------------------------

variable "service_name" {
  description = "Name of the Fastly VCL delivery service, e.g. \"waf-staging\"."
  type        = string
}

variable "domains" {
  description = "Public hostnames this service answers for (the customer vhosts). Order-insensitive."
  type        = list(string)
}

variable "activate" {
  description = "Activate the newest service version on apply. Leave true; set false to stage a version for manual activation."
  type        = bool
  default     = true
}

variable "default_ttl" {
  description = "Default cache TTL (seconds) for cacheable responses with no explicit lifetime."
  type        = number
  default     = 3600
}

# --- Origin -----------------------------------------------------------------------------------------------------------

variable "backend_address" {
  description = "Origin address Fastly fetches from (the app server, e.g. the origin's public IP or a locked-down origin hostname). Customer-specific: set in the leaf only."
  type        = string
}

variable "backend_port" {
  description = "Origin port."
  type        = number
  default     = 443
}

variable "backend_name" {
  description = "Label for the origin backend."
  type        = string
  default     = "origin"
}

variable "override_host" {
  description = "Host header Fastly sends to the origin (the real customer vhost). Usually the primary entry in var.domains. Empty = send the requested host through unchanged."
  type        = string
  default     = ""
}

variable "origin_tls" {
  description = "Connect to the origin over TLS (strongly recommended; mirrors the production Fastly posture)."
  type        = bool
  default     = true
}

variable "origin_sni_hostname" {
  description = "SNI hostname presented to the origin. Defaults to override_host when empty."
  type        = string
  default     = ""
}

variable "origin_cert_hostname" {
  description = "Hostname the origin certificate is validated against. Defaults to override_host when empty."
  type        = string
  default     = ""
}

variable "origin_check_cert" {
  description = "Verify the origin TLS certificate. Keep true in production. May be set false ONLY on a staging origin that serves a snakeoil cert (documented divergence)."
  type        = bool
  default     = true
}

variable "origin_shield" {
  description = "Fastly shield POP (e.g. \"sydney-au\") for origin shielding and tiered cache. Empty = no shield."
  type        = string
  default     = ""
}

variable "backend_connect_timeout" {
  description = "Origin TCP connect timeout (ms)."
  type        = number
  default     = 5000
}

variable "backend_first_byte_timeout" {
  description = "Origin first-byte timeout (ms). Generous enough to ride slow origin request handling; a slow-origin runaway should be capped at the origin, not here."
  type        = number
  default     = 60000
}

variable "backend_between_bytes_timeout" {
  description = "Origin between-bytes timeout (ms)."
  type        = number
  default     = 30000
}

variable "backend_min_tls_version" {
  description = "Minimum TLS version to the origin."
  type        = string
  default     = "1.2"
}

# --- Health check -----------------------------------------------------------------------------------------------------
# Tuned to tolerate JVM app-server warmup (transient 307/503/000 for 1-2 min on restart): a wide window with a
# low success threshold, so one warmup blip never marks the origin down. Never window=1/threshold=1.

variable "health_check_path" {
  description = "Path the health check requests. Must be cheap and WAF/auth-exempt at the origin (e.g. a static 200). A path the WAF or auth_basic answers 401/403/challenge reads as an outage (a challenged monitoring probe reads as an outage)."
  type        = string
  default     = "/robots.txt"
}

variable "health_check_expected_response" {
  description = "HTTP status the health check treats as healthy."
  type        = number
  default     = 200
}

variable "health_check_host" {
  description = "Host header for the health check. Defaults to override_host when empty."
  type        = string
  default     = ""
}

variable "health_check_window" {
  description = "Number of recent probes considered."
  type        = number
  default     = 10
}

variable "health_check_threshold" {
  description = "Successful probes (within the window) required to be healthy. Low vs window = warmup-tolerant."
  type        = number
  default     = 3
}

variable "health_check_interval" {
  description = "Probe interval (ms)."
  type        = number
  default     = 15000
}

variable "health_check_initial" {
  description = "Probes assumed successful before the first real result (keeps the backend up through a deploy)."
  type        = number
  default     = 8
}

# ---------------------------------------------------------------------------------------------------------------------
# FEATURE SWITCHES
# Each switch toggles a whole resource family. Turning one off on an adopted service DESTROYS those resources in
# state. The cloudflare module documents the same contract. Mirrors manage_* there.
# ---------------------------------------------------------------------------------------------------------------------

variable "manage_service" {
  description = "Manage the Fastly VCL delivery service (domains, origin backend, TLS, health check, headers, cache, logging)."
  type        = bool
  default     = true
}

variable "manage_ngwaf_workspace" {
  description = "Manage the Next-Gen WAF workspace (the WAF brain: mode, inline attack-signal blocking, client-IP headers)."
  type        = bool
  default     = true
}

variable "manage_ngwaf_edge" {
  description = "Attach the NGWAF workspace to the delivery service at the edge (product_enablement.ngwaf). CREATE-ONLY: adoption skips it (see adopt.tf)."
  type        = bool
  default     = true
}

variable "manage_ngwaf_signals" {
  description = "Manage the custom NGWAF signals (categories the system signal set does not cover: ColdFusion/CFML, cred-hunt, WP probes, scanner paths, ...)."
  type        = bool
  default     = true
}

variable "manage_ngwaf_rules" {
  description = "Manage the NGWAF request rules: the CMS signal-exclusion (false-positive safety) and the per-category block rules."
  type        = bool
  default     = true
}

variable "manage_ngwaf_rate_limits" {
  description = "Manage the NGWAF rate-limit rules (the feed cache-buster abuse backstop, the CFIDE/admin login ceiling)."
  type        = bool
  default     = true
}

variable "manage_ngwaf_thresholds" {
  description = "Manage the attack-signal repeat-offender threshold backstop (a SECOND layer; per-request blocking is the primary gate)."
  type        = bool
  default     = true
}

variable "manage_ngwaf_virtual_patches" {
  description = "Manage Fastly NGWAF virtual patches (CVE templates, e.g. Log4Shell/Spring4Shell). Off by default: the available virtual_patch_id values are account/API-specific and must be supplied in the leaf."
  type        = bool
  default     = false
}

variable "manage_tls" {
  description = "Manage the Fastly TLS subscription for var.domains. OFF by default: TLS subscriptions are ordering/validation-sensitive and import-hostile; provision them out-of-band for the trial, then adopt. (Mirrors cloudflare manage_content_scanning being off.)"
  type        = bool
  default     = false
}

variable "manage_logging" {
  description = "Manage the syslog logging endpoint shipping Fastly access logs to the log stack."
  type        = bool
  default     = false
}

variable "tls_certificate_authority" {
  description = "ACME CA for the TLS subscription when manage_tls = true: certainly, lets-encrypt or globalsign."
  type        = string
  default     = "lets-encrypt"

  validation {
    condition     = contains(["certainly", "lets-encrypt", "globalsign"], var.tls_certificate_authority)
    error_message = "tls_certificate_authority must be certainly, lets-encrypt or globalsign."
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# NGWAF WORKSPACE POSTURE
# ---------------------------------------------------------------------------------------------------------------------

variable "ngwaf_mode" {
  description = "Workspace operating mode. \"block\" = enforce (production), \"log\" = observe only (staging/grading with the efficacy harness), \"off\" = disabled. Stage in log, grade, then flip to block."
  type        = string
  default     = "block"

  validation {
    condition     = contains(["block", "log", "off"], var.ngwaf_mode)
    error_message = "ngwaf_mode must be block, log or off."
  }
}

variable "ngwaf_immediate_block" {
  description = "Block immediately (per-request) when ANY attack signal is detected, instead of waiting for a per-IP count threshold. TRUE is what makes NGWAF behave like a semantic WAF's per-request deny and is the whole point of this posture; the stock default (false) lets request #1 of every attacker through."
  type        = bool
  default     = true
}

variable "ngwaf_block_response_code" {
  description = "HTTP status returned on a block. 406 matches the NGWAF default and is what the efficacy harness fingerprints as a Fastly WAF block."
  type        = number
  default     = 406
}

variable "ngwaf_client_ip_headers" {
  description = "Headers NGWAF trusts for the real client IP. Fastly-Client-IP is set by Fastly from the real edge connection; keep it first. Do NOT trust a bare X-Forwarded-For at the true edge (spoofable)."
  type        = list(string)
  default     = ["Fastly-Client-IP"]
}

variable "ngwaf_ip_anonymization" {
  description = "IP anonymization for stored events. \"hashed\" or empty."
  type        = string
  default     = ""
}

variable "ngwaf_edge_ramp" {
  description = "Percentage (0-100) of edge traffic the NGWAF workspace inspects at the edge attachment. Ramp 10 -> 50 -> 100 during the staged rollout. Applies when manage_ngwaf_edge = true."
  type        = number
  default     = 100

  validation {
    condition     = var.ngwaf_edge_ramp >= 0 && var.ngwaf_edge_ramp <= 100
    error_message = "ngwaf_edge_ramp must be between 0 and 100."
  }
}

variable "feed_cachebuster_path" {
  description = "Exact path of a high-cost dynamic JSON endpoint targeted by cache-busting abuse. Empty (default) = no feed-specific controls. When set, drives the (opt-in) cache-key normalization and the feed rate-limit rule."
  type        = string
  default     = ""
}

variable "feed_cache_normalize" {
  description = <<-EOT
    Enable the VCL that strips the query string on var.feed_cachebuster_path so all cache-buster variants collapse to one
    cached object (the primary fix for the fund-feed DoS). DEFAULT FALSE: only correct if the feed returns one
    aggregate object for that path - if it selects a fund by a query parameter, stripping the query serves the wrong
    quote. Confirm the endpoint's parameter contract, then enable. The NGWAF rate-limit backstop is on regardless.
  EOT
  type        = bool
  default     = false
}

variable "feed_cache_ttl" {
  description = "TTL (seconds) for the normalized a high-cost dynamic JSON feed object (when feed_cache_normalize = true). Short, so data stays fresh while the buster URLs collapse to one cached object."
  type        = number
  default     = 30
}

variable "ngwaf_attack_thresholds" {
  description = "Repeat-offender backstop counts for the attack-signal thresholds block (one_minute/ten_minutes/one_hour). Deliberately HIGH: a low threshold on a shared office-NAT IP is how legitimate shared-IP users got blocked before. Per-request blocking (ngwaf_immediate_block) is the real gate; these only catch sustained floods."
  type = object({
    one_minute  = optional(number, 10000)
    ten_minutes = optional(number, 10000)
    one_hour    = optional(number, 10000)
  })
  default = {}
}

# ---------------------------------------------------------------------------------------------------------------------
# FALSE-POSITIVE SAFETY (the CMS) + TRUSTED SOURCES
# ---------------------------------------------------------------------------------------------------------------------

variable "trusted_exemption_ips" {
  description = "IPs/CIDRs exempt from BODY XSS/SQLI blocking on the CMS admin + JSON-API paths ONLY (e.g. a trusted office IP, CMS-editor egress). They are NOT exempt from any other signal, path or everywhere else. Customer-specific: leaf only. Empty = no exemption rule emitted."
  type        = list(string)
  default     = []
}

variable "cms_admin_paths" {
  description = "the CMS admin path prefixes where trusted editors legitimately POST rich-text/HTML that trips XSS/SQLI (e.g. [\"/admin\", \"/index.cfm/_admin\"]). Scope of the exemption."
  type        = list(string)
  default     = []
}

variable "cms_json_api_paths" {
  description = "the CMS JSON-API path prefixes trusted editors use (e.g. [\"/index.cfm/_api/json\", \"/rest\"])."
  type        = list(string)
  default     = []
}

variable "cms_exempt_signals" {
  description = <<-EOT
    Which signals the scoped CMS exemption removes for trusted editors. Default ["SQLI","XSS"] - the signals that
    CMS rich-text/HTML admin saves legitimately trip. Keep this TIGHT: adding CMDEXE/TRAVERSAL/LOG4J/etc would let a
    spoofed-trusted-IP RCE through on admin/JSON paths, which is exactly the hole the scoped exemption avoids.
    (Monitoring/health-check sources are handled at the origin's own allowlist, not here; this posture blocks attacks
    rather than challenging, so a plain Icinga http probe is not flagged.)
  EOT
  type        = list(string)
  default     = ["SQLI", "XSS"]
}

# ---------------------------------------------------------------------------------------------------------------------
# CUSTOM SIGNALS + BLOCK RULES (data-driven)
# The baseline set lives in locals.tf. These inputs ADD to or OVERRIDE it, so a leaf can tune a pattern or add a
# category without editing the module. Each entry is one custom signal + the request rule that blocks it.
# ---------------------------------------------------------------------------------------------------------------------

variable "signal_pattern_overrides" {
  description = <<-EOT
    Map of custom-category key => list(string) of match patterns, merged OVER the baseline in locals.tf
    (same key REPLACES the whole list). Lets a leaf tune a category's patterns without editing the module.
    Keys and what the patterns mean (see locals.tf local.signal_patterns_baseline):
      cf_admin   - path substrings (ColdFusion/CFML admin surfaces)
      cred_hunt       - path substrings (secret/dotfile hunts)
      wp_probe_paths  - path substrings (WordPress surfaces)
      wp_probe_params - query-parameter NAMES whose presence signals a WP REST probe (e.g. rest_route)
      scanner_paths   - path substrings (actuator/HNAP/cgi-bin/...)
      scanner_uas     - User-Agent substrings (Nikto/Nmap/...)
      php_discovery   - path substrings (phpMyAdmin/phpunit eval-stdin/...)
      encoded_trav    - REGEX patterns matched against the path (encoded/backslash/overlong traversal)
    Body-pattern categories (SSRF/SSTI/deserialization/PHP-wrappers) are deliberately NOT custom signals here:
    the system signals (CODEINJECTION/SSRF/BACKDOOR) plus virtual patches cover them with far lower false-positive
    risk than hand-authored body regex against a CMS JSON API. To add such a rule, declare an extra
    fastly_ngwaf_workspace_rule in the leaf (in log mode first), or extend the module.
  EOT
  type        = map(list(string))
  default     = {}
}

variable "custom_category_disable" {
  description = "List of baseline custom-category keys to NOT emit a block rule for (keeps the signal/metrics, drops the block) - for log-mode tuning of a noisy category."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------------------------------------------------
# RATE LIMITS
# ---------------------------------------------------------------------------------------------------------------------

variable "rate_limits" {
  description = <<-EOT
    Map of rate-limit key => definition, merged OVER the baseline in locals.tf (the feed, CFIDE login);
    a key present here REPLACES the whole baseline value for that key.
    Each definition:
      description  - human description
      enabled      - default true
      signal_name  - lowercase-alphanumeric custom signal the limiter counts on (a workspace signal is created for it)
      field        - request field the condition matches (e.g. "path")
      operator     - match operator (e.g. "contains")
      patterns     - list(string) of values; each becomes one ORed condition selecting the requests to count
      threshold    - count per interval that trips the limit (1..100000)
      interval     - 60, 600 or 3600 (seconds)
      duration     - block duration (seconds) once tripped
      client_key   - client identifier type: ip | post_parameter | request_cookie | request_header | signal_payload
  EOT
  type        = any
  default     = {}
}

# ---------------------------------------------------------------------------------------------------------------------
# VIRTUAL PATCHES (CVE templates)
# ---------------------------------------------------------------------------------------------------------------------

variable "virtual_patches" {
  description = <<-EOT
    Curated map of CVE id => { action (log|block, default block), enabled (default true) }, keyed by the bare CVE
    string (the virtual_patch_id), e.g. "CVE-2021-44228". Virtual patches are pre-seeded per workspace by Fastly; this
    map only TOGGLES them. Ids not seeded in the workspace are skipped and surfaced in the
    virtual_patches_requested_but_unavailable output (fail-safe, not a mid-apply error). Requires
    manage_ngwaf_virtual_patches = true. See examples/ for the JVM-tuned tiered set.
  EOT
  type = map(object({
    action  = optional(string, "block")
    enabled = optional(bool, true)
  }))
  default = {}

  validation {
    condition     = alltrue([for k, v in var.virtual_patches : contains(["log", "block"], v.action)])
    error_message = "Each virtual_patches entry action must be log or block."
  }
}

variable "ngwaf_virtual_patch_force_log" {
  description = "Force EVERY managed virtual patch to action=log regardless of its per-CVE setting. Use during the staging/grading phase so nothing blocks while the efficacy harness runs; set false to enforce."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------------------------------------------------
# ORIGIN LOCKDOWN (shared-secret header)
# The Fastly IP allowlist at the origin firewall is necessary but NOT sufficient: Fastly egress IPs are shared
# across all tenants, so any Fastly customer could reach the origin. This injects a secret header that the origin
# nginx must require (403 on mismatch) - the "WAF-in-front, origin-wide-open" bypass principle. The IP allowlist itself
# is enforced in Puppet (profile allow_fastly + cdn_whitelist_monitor.py), not here.
# ---------------------------------------------------------------------------------------------------------------------

variable "origin_secret_header" {
  description = "Header name injected toward the origin for origin-lockdown. The origin nginx must require it."
  type        = string
  default     = "X-Origin-Secret"
}

variable "origin_secret_value" {
  description = "Shared-secret value for origin_secret_header. Sensitive; supply from Secrets Manager via the leaf. Empty = do not inject (lockdown relies on IP allowlist only - weaker)."
  type        = string
  default     = ""
  sensitive   = true
}

# ---------------------------------------------------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------------------------------------------------

variable "syslog_address" {
  description = "Syslog endpoint (host:port) for Fastly access logs shipped to the log stack. Required when manage_logging = true."
  type        = string
  default     = ""
}

variable "syslog_tls_hostname" {
  description = "TLS hostname for the syslog endpoint (enables TLS when set)."
  type        = string
  default     = ""
}
