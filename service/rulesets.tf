# ---------------------------------------------------------------------------------------------------------------------
# NGWAF RULES
# Order of EFFECT (the engine applies signal exclusions during inspection, before the attack-signal block decision):
#   1. the CMS signal-exclusion rules   - remove SQLI/XSS for trusted IPs on admin/JSON paths (FP safety), logged
#   2. system attack signals          - blocked inline by the workspace (features.tf: immediate=true), SQLI/XSS now
#                                        absent for the exempted requests
#   3. custom per-category block rules - ColdFusion/CFML, cred-hunt, WP (path+query), scanner path/UA, phpunit, encoded trav
#   4. rate-limit rules                - feed cache-buster abuse, CFIDE/admin login brute force
#   5. virtual patches                 - CVE templates (Log4Shell etc.) - see virtual_patches var / examples
#
# APPLY-TIME VERIFY (string semantics terraform validate cannot check; confirm on the first real plan/apply):
#   (a) a workspace-LIST reference in a condition is `site.<list-name>` (same `site.` prefix as a custom signal), while
#       a SYSTEM signal in exclude_signal is the bare name ("SQLI"); (b) custom signals are referenced as `site.<name>`
#       and names are lowercase-alphanumeric (no hyphen/period); (c) multival fields value_string/query_parameter/name
#       are accepted; (d) encoded-traversal `matches` on the path fires on encoded/double-encoded forms.
# ---------------------------------------------------------------------------------------------------------------------

# Trusted-IP list backing the CMS exemption (only when an exemption is actually configured).
resource "fastly_ngwaf_workspace_list" "trusted_exempt" {
  count = var.manage_ngwaf_workspace && var.manage_ngwaf_rules && local.emit_exemption ? 1 : 0

  workspace_id = fastly_ngwaf_workspace.this[0].id
  name         = "trusted-exempt"
  type         = "ip"
  description  = "Trusted sources (a trusted office IP + CMS-editor egress) exempt from BODY XSS/SQLI on the CMS admin/JSON paths only"
  entries      = var.trusted_exemption_ips
}

# -------------------------------------------------------------------------------------------------------------------
# 1. CMS FALSE-POSITIVE SAFETY - scoped signal exclusion (NOT an allow/skip-all).
# One rule per excluded signal (default SQLI, XSS; override via var.cms_exempt_signals). Scope: trusted IP AND one of
# the CMS admin/JSON paths. Every other signal (CMDEXE/TRAVERSAL/LOG4J/...) still blocks, even from a trusted IP.
# request_logging + the cmsexempt tag keep each exemption visible. Prevents the blocked-trusted-IP / blocked-editors
# incidents. The list reference MUST be `site.<list-name>` (provider requirement for a workspace-list condition).
# -------------------------------------------------------------------------------------------------------------------
resource "fastly_ngwaf_workspace_rule" "cms_exclusion" {
  for_each = var.manage_ngwaf_workspace && var.manage_ngwaf_rules && local.emit_exemption ? toset(local.exemption_signals) : toset([])

  workspace_id    = fastly_ngwaf_workspace.this[0].id
  type            = "signal"
  description     = "the CMS FP-safety: exclude ${each.value} for trusted IPs on admin/JSON-API paths"
  enabled         = true
  group_operator  = "all"
  request_logging = "sampled"

  condition {
    field    = "ip"
    operator = "in_list"
    value    = "site.${fastly_ngwaf_workspace_list.trusted_exempt[0].name}"
  }

  group_condition {
    group_operator = "any"
    dynamic "condition" {
      for_each = toset(local.exemption_paths)
      content {
        field    = "path"
        operator = "contains"
        value    = condition.value
      }
    }
  }

  action {
    type   = "exclude_signal"
    signal = each.value
  }

  # Tag the exemption so every waived request is visible in NGWAF metrics (audit, not a security action).
  action {
    type   = "add_signal"
    signal = "site.cmsexempt"
  }
}

# -------------------------------------------------------------------------------------------------------------------
# 3a. PATH-BASED CUSTOM BLOCK RULES - ColdFusion/CFML admin, cred-hunt, scanner paths, phpunit discovery, encoded
# traversal. One rule per category; conditions are ORed (group_operator = any) over that category's pattern list.
# Each rule tags its category signal (add_signal) AND blocks, so per-category metrics are populated.
# -------------------------------------------------------------------------------------------------------------------
resource "fastly_ngwaf_workspace_rule" "path_block" {
  for_each = var.manage_ngwaf_workspace && var.manage_ngwaf_rules ? local.path_block_categories : {}

  workspace_id    = fastly_ngwaf_workspace.this[0].id
  type            = "request"
  description     = "Block ${each.key} (tags site.${each.value.signal})"
  enabled         = true
  group_operator  = "any"
  request_logging = "sampled"

  dynamic "condition" {
    for_each = toset(lookup(local.signal_patterns, each.key, []))
    content {
      field    = each.value.field
      operator = each.value.operator
      value    = condition.value
    }
  }

  action {
    type   = "add_signal"
    signal = "site.${each.value.signal}"
  }
  action {
    type = "block"
  }

  depends_on = [fastly_ngwaf_workspace_signal.custom]
}

# -------------------------------------------------------------------------------------------------------------------
# 3b. WORDPRESS PROBE BLOCK - matches on PATH or on the presence of a WP REST query parameter (?rest_route=...).
# The query-string form was 88% of a prior batch/v1 campaign; a path-only rule misses it. group_operator = any so
# either arm fires.
# -------------------------------------------------------------------------------------------------------------------
resource "fastly_ngwaf_workspace_rule" "wp_probe_block" {
  count = var.manage_ngwaf_workspace && var.manage_ngwaf_rules && !contains(var.custom_category_disable, "wp_probe") && (length(lookup(local.signal_patterns, "wp_probe_paths", [])) > 0 || length(lookup(local.signal_patterns, "wp_probe_params", [])) > 0) ? 1 : 0

  workspace_id    = fastly_ngwaf_workspace.this[0].id
  type            = "request"
  description     = "Block WordPress probes by path or ?rest_route= query parameter (tags site.wpprobe)"
  enabled         = true
  group_operator  = "any"
  request_logging = "sampled"

  dynamic "condition" {
    for_each = toset(lookup(local.signal_patterns, "wp_probe_paths", []))
    content {
      field    = "path"
      operator = "contains"
      value    = condition.value
    }
  }

  dynamic "multival_condition" {
    for_each = length(lookup(local.signal_patterns, "wp_probe_params", [])) > 0 ? [1] : []
    content {
      field          = "query_parameter"
      operator       = "exists"
      group_operator = "any"
      dynamic "condition" {
        for_each = toset(lookup(local.signal_patterns, "wp_probe_params", []))
        content {
          field    = "name"
          operator = "equals"
          value    = condition.value
        }
      }
    }
  }

  action {
    type   = "add_signal"
    signal = "site.wpprobe"
  }
  action {
    type = "block"
  }

  depends_on = [fastly_ngwaf_workspace_signal.custom]
}

# -------------------------------------------------------------------------------------------------------------------
# 3c. SCANNER USER-AGENT BLOCK - Nikto / Nmap NSE / sqlmap / shellshock-probe UAs (header match).
# -------------------------------------------------------------------------------------------------------------------
resource "fastly_ngwaf_workspace_rule" "scanner_ua_block" {
  count = var.manage_ngwaf_workspace && var.manage_ngwaf_rules && !contains(var.custom_category_disable, "scanner_ua") && length(lookup(local.signal_patterns, "scanner_uas", [])) > 0 ? 1 : 0

  workspace_id    = fastly_ngwaf_workspace.this[0].id
  type            = "request"
  description     = "Block known scanner/tooling User-Agents (tags site.scannerua)"
  enabled         = true
  group_operator  = "any"
  request_logging = "sampled"

  dynamic "multival_condition" {
    for_each = toset(lookup(local.signal_patterns, "scanner_uas", []))
    content {
      field          = "request_header"
      operator       = "exists"
      group_operator = "all"
      condition {
        field    = "name"
        operator = "equals"
        value    = "User-Agent"
      }
      condition {
        field    = "value_string"
        operator = "contains"
        value    = multival_condition.value
      }
    }
  }

  action {
    type   = "add_signal"
    signal = "site.scannerua"
  }
  action {
    type = "block"
  }

  depends_on = [fastly_ngwaf_workspace_signal.custom]
}

# -------------------------------------------------------------------------------------------------------------------
# 4. RATE LIMITS - feed cache-buster abuse ceiling, CFIDE/admin login brute-force ceiling. The limiter counts requests
# matching its condition into its custom signal; when the threshold/interval is crossed the client is blocked for
# `duration`. Thresholds are well above any legitimate client. depends_on the signals so the counter exists first.
# -------------------------------------------------------------------------------------------------------------------
resource "fastly_ngwaf_workspace_rule" "rate_limit" {
  for_each = var.manage_ngwaf_workspace && var.manage_ngwaf_rate_limits ? { for k, v in local.rate_limits : k => v if lookup(v, "enabled", true) } : {}

  workspace_id    = fastly_ngwaf_workspace.this[0].id
  type            = "rate_limit"
  description     = each.value.description
  enabled         = true
  group_operator  = "any"
  request_logging = "sampled"

  dynamic "condition" {
    for_each = toset(each.value.patterns)
    content {
      field    = each.value.field
      operator = each.value.operator
      value    = condition.value
    }
  }

  rate_limit {
    signal    = "site.${each.value.signal_name}"
    threshold = each.value.threshold
    interval  = each.value.interval
    duration  = each.value.duration

    client_identifiers {
      type = each.value.client_key
    }
  }

  action {
    type   = "block_signal"
    signal = "site.${each.value.signal_name}"
  }

  # The counting signal is created in signals.tf; it and this rule are gated by different switches, so an explicit
  # dependency (not a resource reference) guarantees create order.
  depends_on = [fastly_ngwaf_workspace_signal.custom]
}

# -------------------------------------------------------------------------------------------------------------------
# 5. VIRTUAL PATCHES - CVE templates. Virtual patches are PRE-SEEDED per workspace by Fastly (List/Edit only, no
# create/delete); virtual_patch_id is the bare CVE string (one exception: "CVE-2021-44228-STRICT"). We therefore only
# TOGGLE seeded patches. On a JVM origin the Java-RCE-class patches (Log4Shell CVE-2021-44228, Spring4Shell,
# Struts2, ...) are directly relevant; keep them block. NOTE there is NO Fastly virtual patch for ColdFusion/CFML
# itself - that stack is covered by the system signals + the custom rules above, not here.
#
# The curated map (var.virtual_patches, keyed by CVE id) is the source of truth for INTENT (per-CVE action + enabled).
# The data source validates it against what the workspace actually seeds, so a CVE id Fastly has not seeded is skipped
# (surfaced in outputs) instead of erroring mid-apply. enabled=false is passed through to actively DISABLE a seeded
# patch (not dropped), so the map can both enable and disable. ngwaf_virtual_patch_force_log forces log during grading.
# -------------------------------------------------------------------------------------------------------------------
data "fastly_ngwaf_virtual_patches" "available" {
  count        = var.manage_ngwaf_workspace && var.manage_ngwaf_virtual_patches ? 1 : 0
  workspace_id = fastly_ngwaf_workspace.this[0].id
}

locals {
  vp_available_ids = (var.manage_ngwaf_workspace && var.manage_ngwaf_virtual_patches) ? toset([for p in data.fastly_ngwaf_virtual_patches.available[0].virtual_patches : p.id]) : toset([])
  vp_requested_ids = toset(keys(var.virtual_patches))
  # Manage (toggle) every requested id the workspace actually seeds - enabled true OR false is passed through so the
  # map can disable a seeded patch as well as enable one.
  vp_manageable = { for id, cfg in var.virtual_patches : id => cfg if contains(local.vp_available_ids, id) }

  # Surfaced via outputs for operator triage:
  vp_requested_but_unavailable = setsubtract(local.vp_requested_ids, local.vp_available_ids) # typo / not-yet-seeded
  vp_available_but_unmanaged   = setsubtract(local.vp_available_ids, local.vp_requested_ids) # new Fastly patches to triage
}

resource "fastly_ngwaf_virtual_patches" "this" {
  for_each = (var.manage_ngwaf_workspace && var.manage_ngwaf_virtual_patches) ? local.vp_manageable : {}

  workspace_id     = fastly_ngwaf_workspace.this[0].id
  virtual_patch_id = each.key
  action           = var.ngwaf_virtual_patch_force_log ? "log" : each.value.action
  enabled          = each.value.enabled
}

# -------------------------------------------------------------------------------------------------------------------
# REPEAT-OFFENDER THRESHOLD BACKSTOP - a SECOND layer only; immediate=true already denied request #1. Set HIGH.
# One threshold per high-confidence system attack signal, blocking a sustained flood source.
# -------------------------------------------------------------------------------------------------------------------
resource "fastly_ngwaf_thresholds" "attack_backstop" {
  for_each = var.manage_ngwaf_workspace && var.manage_ngwaf_thresholds ? toset(["SQLI", "XSS", "CMDEXE", "TRAVERSAL"]) : toset([])

  workspace_id = fastly_ngwaf_workspace.this[0].id
  name         = "backstop-${lower(each.value)}"
  signal       = each.value
  action       = "block"
  interval     = 600
  limit        = 100
  duration     = 3600
  enabled      = true
  dont_notify  = false
}
