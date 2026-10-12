# ---------------------------------------------------------------------------------------------------------------------
# CUSTOM SIGNALS
# Named tags for the categories the system signal set does not score (ColdFusion/CFML admin, cred-hunt, WP probes,
# scanner paths/UAs, phpunit discovery, encoded traversal), plus the rate-limit counters and the exemption marker.
# A signal is just a label; the rules in rulesets.tf are what detect and act. Referenced elsewhere as site.<name>.
# ---------------------------------------------------------------------------------------------------------------------

resource "fastly_ngwaf_workspace_signal" "custom" {
  for_each = var.manage_ngwaf_signals ? toset(local.custom_signal_names) : toset([])

  workspace_id = fastly_ngwaf_workspace.this[0].id
  name         = each.value
  description  = "custom signal: ${each.value}"
}
