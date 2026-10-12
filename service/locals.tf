# ---------------------------------------------------------------------------------------------------------------------
# COMPUTED DEFAULTS + SECURE BASELINE
# The cloudflare module's pattern: a shared baseline built as data here, merged with per-leaf overrides, then fed to
# the resources. Customer specifics (IPs, hostnames, secrets) never live here - they arrive as inputs from the leaf.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  # Host-header / SNI / cert-name fallbacks: everything defaults to override_host, which defaults to the first domain.
  primary_domain = length(var.domains) > 0 ? var.domains[0] : ""
  override_host  = var.override_host != "" ? var.override_host : local.primary_domain
  origin_sni     = var.origin_sni_hostname != "" ? var.origin_sni_hostname : local.override_host
  origin_cert    = var.origin_cert_hostname != "" ? var.origin_cert_hostname : local.override_host
  hc_host        = var.health_check_host != "" ? var.health_check_host : local.override_host

  # Whether to emit the origin-lockdown shared-secret header toward origin.
  inject_origin_secret = var.origin_secret_value != ""

  # -------------------------------------------------------------------------------------------------------------------
  # SYSTEM ATTACK SIGNALS - handled INLINE per-request by the workspace itself (mode=block +
  # attack_signal_thresholds.immediate=true). These are Fastly/NGWAF-provided signals; we do NOT author custom
  # signals for them. Listed here for documentation and for the README coverage table only.
  # -------------------------------------------------------------------------------------------------------------------
  system_attack_signals = [
    "SQLI",          # SQL injection            
    "XSS",           # cross-site scripting     
    "TRAVERSAL",     # directory traversal / LFI 
    "CMDEXE",        # OS command injection     
    "CODEINJECTION", # code injection (PHP/ASP/Java) 
    "BACKDOOR",      # backdoor / webshell access
    "SANS",          # SANS/known-bad patterns
    "USERAGENT",     # malicious tooling user-agents
    "SCANNER",       # scanner behaviour
    "LOG4J-JNDI",    # Log4Shell / JNDI lookups - DIRECTLY exploitable class on a JVM origin 
  ]

  # -------------------------------------------------------------------------------------------------------------------
  # CUSTOM SIGNAL PATTERNS - categories the system signal set does not score, but which a WAF replacing a semantic WAF must
  # block inline. Deliberately limited to cleanly-matchable PATH / USER-AGENT / QUERY-PARAM-NAME patterns (low
  # false-positive risk). Body-pattern categories (SSRF/SSTI/deserialization) are left to the system signals +
  # virtual patches - hand-authored body regex is the highest FP risk against a CMS JSON API.
  # Each list is overridable per-leaf via var.signal_pattern_overrides (whole-list replace).
  # -------------------------------------------------------------------------------------------------------------------
  signal_patterns_baseline = {
    cf_admin = [
      "/CFIDE/adminapi", "/CFIDE/administrator", "/CFIDE/wizards", "/CFIDE/componentutils",
      "/cfide/adminapi", "/lucee/admin", "/administrator/enter.cfm", "administrator.cfc", "_logintowizard.cfm",
    ]
    cred_hunt = [
      "/.env", "/.git/", "/.aws/", "/.svn/", "/.hg/", "id_rsa", "/.htpasswd", "/.htaccess",
      "/config/gcp-credentials.json", "/credentials.json", "/server-status", "/.DS_Store", "/wp-config.php.bak",
    ]
    wp_probe_paths = [
      # trailing slashes keep these from matching legitimate content slugs that merely contain the token
      "/wp-login.php", "/wp-admin/", "/wp-json/", "/xmlrpc.php", "/wp-content/", "/wp-includes/",
    ]
    # The query-string REST vector: ?rest_route=/wp/v2/... was 88% of a prior batch/v1 campaign. A path-only rule
    # misses it, so we also match these query-parameter NAMES (presence), not just /wp-json paths.
    wp_probe_params = ["rest_route"]
    scanner_paths = [
      "/actuator", "/HNAP1/", "/hnap1/", "/cgi-bin/", "/solr/", "/console/", "/_ignition/", "/telescope/",
      "/.well-known/security.txt.bak", "/jenkins/", "/manager/html",
    ]
    scanner_uas = [
      "nikto", "nmap scripting engine", "sqlmap", "masscan", "() { :;}", "zgrab", "nessus", "acunetix", "wpscan",
    ]
    php_discovery = [
      "/phpmyadmin", "/phpMyAdmin", "/pma/", "/vendor/phpunit/", "eval-stdin.php", "/php-cgi", "allow_url_include",
    ]
    # Regex (operator "matches") against the path for encoded / backslash / overlong-UTF8 traversal the normalised
    # TRAVERSAL signal can miss. Kept conservative.
    encoded_trav = [
      "(?i)(%25|%)2e(%25|%)2e(%25|%)2f", "(?i)\\.\\.(%5c|\\\\)", "(?i)%c0%af", "(?i)\\.\\.(/|%2f){2,}",
    ]
  }

  signal_patterns = merge(local.signal_patterns_baseline, var.signal_pattern_overrides)

  # Map each custom BLOCK category to the signal it tags and the field/operator its patterns use. The block rules in
  # rulesets.tf are explicit (heterogeneous condition shapes), driven by these pattern lists.
  # NOTE signal names are lowercase-alphanumeric only: the provider rejects periods and special characters
  # (hyphens included) in custom signal names. They are referenced in rules as site.<name>.
  custom_categories = {
    cf_admin      = { signal = "cfadmin", field = "path", operator = "contains" }
    cred_hunt     = { signal = "credhunt", field = "path", operator = "contains" }
    wp_probe      = { signal = "wpprobe", field = "path", operator = "contains" }     # query params handled separately
    scanner_paths = { signal = "scannerpath", field = "path", operator = "contains" } # key MUST match signal_patterns_baseline.scanner_paths
    php_discovery = { signal = "phpdiscovery", field = "path", operator = "contains" }
    encoded_trav  = { signal = "encodedtraversal", field = "path", operator = "matches" }
  }

  # Rate-limit counter signal names (also lowercase-alphanumeric), referenced by the rate-limit rules.
  ratelimit_signal_names = [for k, v in local.rate_limits : v.signal_name]

  # All custom signals we create (for metrics + rule references): the block-category tags + the rate-limit counters
  # + the exemption marker.
  custom_signal_names = distinct(concat(
    [for k, v in local.custom_categories : v.signal],
    ["scannerua", "cmsexempt"],
    local.ratelimit_signal_names,
  ))

  # -------------------------------------------------------------------------------------------------------------------
  # FALSE-POSITIVE SAFETY (the CMS) - the scoped signal exclusion.
  # Emitted ONLY when trusted_exemption_ips AND at least one admin/JSON path are set. Removes ONLY the SQLI and XSS
  # signals, ONLY for trusted IPs, ONLY on the CMS admin/JSON-API paths, and tags the exemption tag so every exemption
  # is visible. This is NOT an allow/skip-all: CMDEXE/TRAVERSAL/LOG4J/etc still block even from a trusted IP.
  # -------------------------------------------------------------------------------------------------------------------
  exemption_paths = concat(var.cms_admin_paths, var.cms_json_api_paths)
  emit_exemption  = length(var.trusted_exemption_ips) > 0 && length(local.exemption_paths) > 0
  # Which signals to exclude for trusted editors. Default SQLI/XSS (what CMS rich-text/HTML saves trip). Keep this
  # list TIGHT - adding CMDEXE/TRAVERSAL/LOG4J would let a spoofed-trusted-IP RCE through on admin/JSON paths.
  exemption_signals = var.cms_exempt_signals

  # -------------------------------------------------------------------------------------------------------------------
  # RATE LIMITS - baseline (feed cache-buster abuse, CFIDE/admin login ceiling), merged over by var.rate_limits.
  # Thresholds are deliberately well above any legitimate client (the observed abuser ran ~56 req/min; a human poller
  # is far lower). client_key defaults to ip.
  # -------------------------------------------------------------------------------------------------------------------
  # The feed cache-buster rate-limit is emitted only when a feed path is configured (feed_cachebuster_path != ""):
  # with an empty path a "contains" condition would match every request.
  feed_rate_limit = var.feed_cachebuster_path != "" ? {
    feed_abuse = {
      description = "High-cost dynamic JSON feed cache-buster abuse ceiling (primary fix is cache-key normalization in main.tf)"
      enabled     = true
      signal_name = "feedabuse"
      field       = "path"
      operator    = "contains"
      patterns    = [var.feed_cachebuster_path]
      threshold   = 100
      interval    = 60
      duration    = 600
      client_key  = "ip"
    }
  } : {}

  rate_limits_baseline = merge(local.feed_rate_limit, {
    cf_admin_login = {
      description = "ColdFusion/CFML admin login brute-force ceiling (on top of the deterministic cfadmin block)"
      enabled     = true
      signal_name = "cfadminlogin"
      field       = "path"
      operator    = "contains"
      patterns    = ["/CFIDE/administrator", "/lucee/admin"]
      threshold   = 10
      interval    = 60
      duration    = 3600
      client_key  = "ip"
    }
  })
  rate_limits = merge(local.rate_limits_baseline, var.rate_limits)

  # Categories that actually emit a block rule: baseline set minus any the leaf disabled, and only where the pattern
  # list is non-empty. wp_probe and the UA/header matcher are handled explicitly in rulesets.tf (different shapes),
  # so they are excluded from the generic path-block engine here.
  path_block_categories = {
    for k, v in local.custom_categories : k => v
    if !contains(var.custom_category_disable, k) && length(lookup(local.signal_patterns, k, [])) > 0 && k != "wp_probe"
  }
}
