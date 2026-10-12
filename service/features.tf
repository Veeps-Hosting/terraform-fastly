# ---------------------------------------------------------------------------------------------------------------------
# NEXT-GEN WAF WORKSPACE
# The WAF brain. The whole point of this module's posture lives in two settings:
#   mode = "block"                             -> enforce (not just observe)
#   attack_signal_thresholds { immediate=true }-> block on request #1 when ANY attack signal fires
# Together they give per-request-equivalent per-request denial. The stock NGWAF default is to COUNT attack signals per
# source IP and only act once a threshold is crossed, so request #1 of every attacker reaches origin - the exact gap
# behind the team's low confidence in Fastly "out of the box". We close it here.
# The one_minute/ten_minutes/one_hour counts are a repeat-offender BACKSTOP only, set deliberately HIGH so a shared
# office-NAT IP's incidental noise never trips them (a low threshold there is how a shared office-NAT IP + CMS editors were
# blocked before). The real gate is immediate=true plus the explicit rules in rulesets.tf.
# ---------------------------------------------------------------------------------------------------------------------

resource "fastly_ngwaf_workspace" "this" {
  count = var.manage_ngwaf_workspace ? 1 : 0

  name                           = var.service_name
  description                    = "terraform-fastly NGWAF workspace for ${local.primary_domain}"
  mode                           = var.ngwaf_mode
  default_blocking_response_code = var.ngwaf_block_response_code
  client_ip_headers              = var.ngwaf_client_ip_headers
  ip_anonymization               = var.ngwaf_ip_anonymization != "" ? var.ngwaf_ip_anonymization : null

  attack_signal_thresholds {
    immediate   = var.ngwaf_immediate_block
    one_minute  = var.ngwaf_attack_thresholds.one_minute
    ten_minutes = var.ngwaf_attack_thresholds.ten_minutes
    one_hour    = var.ngwaf_attack_thresholds.one_hour
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# TLS SUBSCRIPTION  (manage_tls, default OFF)
# TLS subscriptions are ordering/validation-sensitive and import-hostile, so like the cloudflare module's
# content_scanning they default off: provision out-of-band for the trial, or enable on a greenfield temp hostname and
# publish the managed_dns_challenge (see outputs.tf) as a DNS record to complete ACME validation. certificate_authority
# is one of certainly | lets-encrypt | globalsign.
# ---------------------------------------------------------------------------------------------------------------------

resource "fastly_tls_subscription" "this" {
  count = var.manage_tls ? 1 : 0

  domains               = var.domains
  certificate_authority = var.tls_certificate_authority
  common_name           = local.primary_domain

  # Let a destroy proceed even while the subscription is attached (trial teardown).
  force_destroy = true

  lifecycle {
    create_before_destroy = true
  }
}
