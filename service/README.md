# service

A Fastly **CDN delivery service + native Next-Gen WAF** for one application, in one module, through one provider
(`fastly/fastly ~> 9.8`) and one credential (`FASTLY_API_KEY`). Built to put a dynamic web application (e.g. a CMS)
behind Fastly with a posture that **blocks attacks inline, per request**, while staying safe for the application.

## Why this exists / the headline decision

NGWAF **out of the box counts attack signals per source IP and only blocks once a threshold is crossed** — so
request #1 of every new attacker reaches the origin. That is the opposite of a semantic WAF's per-request deny, and is
why a stock NGWAF deployment can feel weak. This module closes the gap with two settings on the workspace:

```
mode                            = "block"
attack_signal_thresholds { immediate = true }   # block on request #1 when ANY attack signal fires
```

plus **explicit block rules** for the categories the system signal set does not score, and a **scoped exclusion** so a
CMS with rich-text/HTML editing never trips a false positive. The per-IP count thresholds are kept only as a high
repeat-offender backstop.

## What it manages (feature switches)

| `manage_*` | Family | Default |
|---|---|---|
| `manage_service` | VCL delivery: domains, origin backend (TLS/SNI/cert-check), warmup-tolerant health check, real-client-IP + origin-secret headers, optional feed cache-key normalization, syslog | `true` |
| `manage_ngwaf_workspace` | The NGWAF workspace: `mode`, `immediate` inline blocking, client-IP headers, backstop thresholds | `true` |
| `manage_ngwaf_edge` | Attach the workspace to the service at the edge (`product_enablement.ngwaf`, `traffic_ramp`) — create-only | `true` |
| `manage_ngwaf_signals` | Custom signals (ColdFusion/CFML admin, cred-hunt, WP, scanner, phpunit, encoded-traversal, rate-limit counters) | `true` |
| `manage_ngwaf_rules` | The CMS exclusion + per-category block rules | `true` |
| `manage_ngwaf_rate_limits` | Optional high-cost-endpoint abuse + admin-login ceilings | `true` |
| `manage_ngwaf_thresholds` | High repeat-offender attack-signal backstop | `true` |
| `manage_ngwaf_virtual_patches` | CVE virtual-patch toggles (data-source-validated) | `false` |
| `manage_tls` | Fastly TLS subscription (import-hostile; off by default) | `false` |
| `manage_logging` | Syslog access logs to a log endpoint | `false` |

## How each attack category is blocked inline

| Category | Control |
|---|---|
| SQLi, XSS, cmd-injection, LFI/traversal, code-injection, backdoor | **System attack signals + `immediate=true`** — per-request block |
| Log4Shell/JNDI (a JVM origin is exploitable-class) | System `LOG4J-JNDI` signal **+** `CVE-2021-44228` virtual patch (block) |
| ColdFusion/CFML admin, cred-hunt, phpunit/phpMyAdmin, scanner paths, scanner UAs, encoded traversal | **Custom block rules** (`rulesets.tf`), path/UA matched |
| WordPress probes incl. `?rest_route=` **query form** | Custom rule matching path **or** the query-parameter name (a path-only rule misses the query-string form) |
| High-cost endpoint cache-buster abuse | **VCL cache-key normalization** (opt-in, collapses buster URLs to one object) + NGWAF rate limit (backstop) |
| Java product RCEs (Struts/Spring/Confluence) | Virtual patches (block) — defence-in-depth + scanner-swat |
| Origin-direct bypass | Origin **IP allowlist** + **shared-secret header** injected here, required by the origin |

> There is **no** Fastly virtual patch for ColdFusion/CFML itself — the application stack is covered by the system
> signals + custom rules above, not by a virtual patch.

## False-positive safety (CMS editors) — the scoped exclusion, never a skip-all

A CMS whose editors POST rich-text/HTML will legitimately trip SQLI/XSS. The module emits a **signal-exclusion** rule
(`exclude_signal`) that removes **only the signals in `cms_exempt_signals`** (default SQLI, XSS), **only for
`trusted_exemption_ips`**, **only on `cms_admin_paths` / `cms_json_api_paths`**, and **logs every exemption**. Every
other signal (CMDEXE, TRAVERSAL, LOG4J, …) still blocks even from a trusted IP. This is categorically **not** a blanket
trusted-IP allow — a skip-all would wave a spoofed-trusted-IP RCE straight through. Set `trusted_exemption_ips = []` to
emit no exemption at all.

## Staged rollout (gated by a replay/efficacy test)

1. `ngwaf_mode = "log"`, `ngwaf_virtual_patch_force_log = true`, `ngwaf_edge_ramp = 10`, on a temporary hostname.
2. Grade with a benign WAF efficacy replay (`scripts/waf_efficacy_check.sh`): require **0 false positives** on
   legitimate control requests and an attack bypass rate at or under your baseline.
3. Flip `ngwaf_mode = "block"`, `ngwaf_virtual_patch_force_log = false`, ramp `50 → 100`.
4. Only then plan the production DNS cutover.

## Origin lockdown (precondition)

A WAF in front with the origin wide-open is bypassable: Fastly egress IPs are **shared across all tenants**, so an IP
allowlist alone lets any Fastly customer reach the origin. Two controls, both required before any production cutover:
- **IP allowlist** at the origin firewall (Fastly's published ranges).
- **Shared-secret header** (`origin_secret_header`/`origin_secret_value`) injected by this module; the origin must
  require it and 403 on mismatch. See [`docs/origin-wiring.md`](../docs/origin-wiring.md).

## Usage

```hcl
terraform {
  source = "github.com/Veeps-Hosting/terraform-fastly//service?ref=0.1"
  extra_arguments "fastly_token" {
    commands = concat(get_terraform_commands_that_need_vars(), ["state", "show"])
    env_vars = { FASTLY_API_KEY = get_env("FASTLY_API_KEY_<ACCOUNT>") }
  }
}
include "root" { path = find_in_parent_folders("root.hcl") }
inputs = { /* see examples/trial.hcl */ }
```

## Apply-time verify (not caught by `terraform validate`)

`terraform validate` checks HCL + provider schema, not NGWAF string semantics. Confirm on the first real plan:
- a workspace-list condition references the list as **`site.<list-name>`** (same `site.` prefix as a custom signal);
  a **system** signal in `exclude_signal` is the **bare** name (`"SQLI"`);
- custom signals are referenced as **`site.<name>`** and names are **lowercase-alphanumeric** (no hyphen/period);
- the multival header field is **`value_string`** and query fields are **`query_parameter`** / **`name`**;
- a `request` rule with two actions (**`add_signal`** + **`block`**) applies both;
- `product_enablement.ngwaf.traffic_ramp` accepts the ramp **number**;
- the `encoded_trav` `matches` regex fires on encoded/double-encoded paths (NGWAF may normalize the path first).

Outputs `virtual_patches_requested_but_unavailable` / `_available_but_unmanaged` surface CVE-id drift to triage.

## Requirements

OpenTofu >= 1.12.0, provider `fastly/fastly ~> 9.8`. Pin a tag in leaves: `//service?ref=X.Y`.
