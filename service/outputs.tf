output "service_id" {
  description = "Fastly VCL delivery service ID."
  value       = one(fastly_service_vcl.this[*].id)
}

output "active_version" {
  description = "Active version number of the delivery service."
  value       = one(fastly_service_vcl.this[*].active_version)
}

output "ngwaf_workspace_id" {
  description = "NGWAF workspace ID (the WAF the leaf and the efficacy harness reference)."
  value       = one(fastly_ngwaf_workspace.this[*].id)
}

output "ngwaf_mode" {
  description = "Effective NGWAF operating mode (block/log/off)."
  value       = var.manage_ngwaf_workspace ? var.ngwaf_mode : null
}

output "ngwaf_edge_ramp" {
  description = "Percentage of edge traffic the workspace inspects (when the edge attachment is managed)."
  value       = (var.manage_ngwaf_edge && var.manage_ngwaf_workspace) ? var.ngwaf_edge_ramp : null
}

output "custom_signal_names" {
  description = "Custom NGWAF signals created by this module."
  value       = var.manage_ngwaf_signals ? local.custom_signal_names : []
}

output "block_rule_categories" {
  description = "Custom categories that emit a block rule (after disables/empty-pattern filtering)."
  value       = var.manage_ngwaf_rules ? keys(local.path_block_categories) : []
}

output "cms_exemption_active" {
  description = "Whether the scoped CMS body-signal exemption rule is emitted (needs trusted IPs AND admin/JSON paths)."
  value       = var.manage_ngwaf_rules && local.emit_exemption
}

# --- Virtual-patch validation / drift (the data-source-driven safety net) --------------------------------------------

output "virtual_patches_managed" {
  description = "CVE ids this module is toggling (curated AND seeded in the workspace)."
  value       = var.manage_ngwaf_virtual_patches ? keys(local.vp_manageable) : []
}

output "virtual_patches_requested_but_unavailable" {
  description = "CVE ids in var.virtual_patches that the workspace does NOT seed - confirm these are typos or not-yet-available, not silent gaps."
  value       = var.manage_ngwaf_virtual_patches ? local.vp_requested_but_unavailable : []
}

output "virtual_patches_available_but_unmanaged" {
  description = "CVE ids the workspace seeds that var.virtual_patches does not mention - triage these (Fastly adds patches continuously; new Java/CF ones matter here)."
  value       = var.manage_ngwaf_virtual_patches ? local.vp_available_but_unmanaged : []
}

# --- TLS validation challenge (publish as DNS to complete ACME when manage_tls = true) -------------------------------

output "tls_managed_dns_challenge" {
  description = "DNS record(s) to publish to validate the Fastly TLS subscription (when manage_tls = true). Give these to whoever controls DNS (your DNS provider)."
  value       = var.manage_tls ? one(fastly_tls_subscription.this[*].managed_dns_challenges) : null
}
