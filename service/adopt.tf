# ---------------------------------------------------------------------------------------------------------------------
# ADOPT AN EXISTING SERVICE / WORKSPACE
# A trial deployment is greenfield (a new service on a temp hostname), so adoption is normally unnecessary here. When
# you DO need to bring already-live Fastly objects under Terraform, Fastly imports are by explicit object ID (there is
# no name->id lookup as clean as Cloudflare's zone data source), so adoption is driven by IDs you supply, not by a
# live search. Set adopt_existing = true and populate adopt_ids with the IDs from the Fastly UI/API.
#
# Honest limits (mirrors how the cloudflare module flags content_scanning / TLS as import-hostile):
#   * The NGWAF edge attachment (product_enablement.ngwaf) is CREATE-ONLY here - it is part of the service version and
#     is not separately importable; on adoption keep manage_ngwaf_edge = false until the service is imported, then
#     enable it (it re-asserts enablement on the next version) - or accept one version bump.
#   * fastly_tls_subscription is ordering/validation-sensitive; adopt it out-of-band, keep manage_tls = false.
#   * Virtual patches are pre-seeded (no import needed): the resource only toggles them, and the data source in
#     rulesets.tf already reconciles the curated map against the live set.
#
# After setting the IDs, the first plan should read "N to import, 0 to add/change/destroy". If it wants to add or
# change, an input does not match the live object - fix the input, do not apply.
# ---------------------------------------------------------------------------------------------------------------------

variable "adopt_existing" {
  description = "Import existing Fastly objects (by the IDs in adopt_ids) into state instead of creating them."
  type        = bool
  default     = false
}

variable "adopt_ids" {
  description = <<-EOT
    IDs of the live objects to import when adopt_existing = true:
      service_id    - the fastly_service_vcl id
      workspace_id  - the fastly_ngwaf_workspace id
    Signals/lists are imported as "<workspace_id>/<object_id>"; add them to adopt_ids.signals/lists maps
    (key = the resource for_each key, value = the live object id). Generated RULES are create-only here: brownfield
    rule adoption is out of scope for the greenfield trial (add import blocks if a brownfield adoption is ever needed).
  EOT
  type = object({
    service_id   = optional(string, "")
    workspace_id = optional(string, "")
    signals      = optional(map(string), {})
    lists        = optional(map(string), {})
  })
  default = {}
}

import {
  for_each = var.adopt_existing && var.manage_service && var.adopt_ids.service_id != "" ? toset(["this"]) : toset([])
  to       = fastly_service_vcl.this[0]
  id       = var.adopt_ids.service_id
}

import {
  for_each = var.adopt_existing && var.manage_ngwaf_workspace && var.adopt_ids.workspace_id != "" ? toset(["this"]) : toset([])
  to       = fastly_ngwaf_workspace.this[0]
  id       = var.adopt_ids.workspace_id
}

import {
  for_each = { for k, id in var.adopt_ids.signals : k => id if var.adopt_existing && var.manage_ngwaf_signals }
  to       = fastly_ngwaf_workspace_signal.custom[each.key]
  id       = "${var.adopt_ids.workspace_id}/${each.value}"
}

import {
  for_each = { for k, id in var.adopt_ids.lists : k => id if var.adopt_existing && var.manage_ngwaf_rules && local.emit_exemption && k == "trusted_exempt" }
  to       = fastly_ngwaf_workspace_list.trusted_exempt[0]
  id       = "${var.adopt_ids.workspace_id}/${each.value}"
}
