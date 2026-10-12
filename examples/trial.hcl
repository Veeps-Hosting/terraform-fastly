# ---------------------------------------------------------------------------------------------------------------------
# EXAMPLE terragrunt leaf: Fastly CDN + NGWAF staging trial for a CMS / dynamic web app on a JVM (ColdFusion/CFML)
# origin. SANITIZED - all deployment-specific values are <ANGLE-BRACKETED> placeholders. The real leaf (origin
# address, hostnames, trusted IPs, the origin shared secret from your secret store) lives in your PRIVATE live repo,
# never in this module repo.
#
# Rollout intent (see docs/operations.md):
#   1. Apply with ngwaf_mode="log" + ngwaf_virtual_patch_force_log=true + ngwaf_edge_ramp=10 on the temp hostname, any
#      incumbent WAF still authoritative for prod. 2. Grade with scripts/waf_efficacy_check.sh (0 control FPs, bypass%
#      at or under baseline). 3. Flip ngwaf_mode="block", force_log=false, ramp 50 -> 100. 4. Only then plan prod DNS.
# ---------------------------------------------------------------------------------------------------------------------

terraform {
  source = "github.com/Veeps-Hosting/terraform-fastly//service?ref=0.1"

  # FASTLY_API_KEY is the single credential (CDN service + native NGWAF). Set per-account via the env; never on disk.
  extra_arguments "fastly_token" {
    commands = concat(get_terraform_commands_that_need_vars(), ["state", "show"])
    env_vars = {
      FASTLY_API_KEY = get_env("FASTLY_API_KEY_<ACCOUNT>")
    }
  }
}

include "root" {
  path = find_in_parent_folders("root.hcl")
}

inputs = {
  service_name = "waf-staging"

  # Temp trial hostname (a CNAME -> this service). Production names are added only at cutover.
  domains       = ["trial.example.com"]
  override_host = "origin.example.com" # the real vhost the staging origin serves

  # --- Origin (the staging app server) -------------------------------------------------------------------------------
  backend_address      = "<ORIGIN-IP>"
  backend_port         = 443
  origin_tls           = true
  origin_sni_hostname  = "origin.example.com"
  origin_cert_hostname = "origin.example.com"
  origin_check_cert    = true # set false only if the staging origin serves a snakeoil cert
  origin_shield        = "sydney-au"

  # Origin lockdown: Fastly injects this header; the origin must REQUIRE it (403 on mismatch). Value from a secret store.
  origin_secret_header = "X-Origin-Secret"
  origin_secret_value  = "<FROM-SECRET-STORE>" # sensitive; never commit the real value

  # --- Health check: tolerate JVM warmup -----------------------------------------------------------------------------
  health_check_path = "/robots.txt" # cheap, WAF/auth-exempt at the origin
  # defaults (window 10 / threshold 3 / initial 8) are already warmup-tolerant

  # --- NGWAF posture -------------------------------------------------------------------------------------------------
  ngwaf_mode                    = "log"  # STAGE 1: observe. Flip to "block" after grading.
  ngwaf_immediate_block         = true   # per-request blocking once mode=block
  ngwaf_block_response_code     = 406    # what the efficacy harness fingerprints as a Fastly WAF block
  ngwaf_edge_ramp               = 10     # ramp 10 -> 50 -> 100
  ngwaf_virtual_patch_force_log = true   # STAGE 1: no virtual patch blocks while grading

  # --- False-positive safety (CMS editors) ---------------------------------------------------------------------------
  # Trusted editor/office egress exempt from BODY XSS/SQLI on admin/JSON paths ONLY, logged; every other signal still
  # blocks. NOT a skip-all. cms_exempt_signals defaults to ["SQLI","XSS"] - keep tight; do NOT add CMDEXE/TRAVERSAL/LOG4J.
  trusted_exemption_ips = ["<TRUSTED-OFFICE-IP>/32"]
  cms_admin_paths       = ["/admin", "/index.cfm/_admin"]
  cms_json_api_paths    = ["/index.cfm/_api/json", "/rest"]

  # --- High-cost endpoint DoS (optional) -----------------------------------------------------------------------------
  # Set feed_cachebuster_path to a high-cost JSON endpoint to enable the rate-limit backstop; enable cache-key
  # normalization only after confirming that path returns ONE aggregate object (not a per-item query parameter):
  # feed_cachebuster_path  = "/api/quote"
  # feed_cache_normalize   = true

  # --- Virtual patches: JVM/ColdFusion-tuned tiers (CVE id = virtual_patch_id; validated against the seeded set) -----
  # The Java-RCE patches are directly relevant on a JVM origin. There is NO Fastly VP for ColdFusion/CFML itself - that
  # stack is covered by the system signals + custom rules, not here. Unseeded ids are skipped and surfaced in outputs.
  virtual_patches = {
    "CVE-2021-44228" = { action = "block" } # Log4Shell
    "CVE-2022-42889" = { action = "block" } # Text4Shell
    "CVE-2022-22965" = { action = "block" } # Spring4Shell
    "CVE-2017-5638"  = { action = "block" } # Struts2 Jakarta Multipart RCE
    "CVE-2022-26134" = { action = "block" } # Confluence OGNL unauth RCE
    "CVE-2021-44228-STRICT" = { action = "log" } # higher FP; log only on a CMS
  }

  manage_ngwaf_virtual_patches = true
  manage_tls                   = true # greenfield temp hostname -> let Fastly issue; publish tls_managed_dns_challenge
  manage_logging               = true
  syslog_address               = "<LOG-ENDPOINT-HOST>:514"
}
