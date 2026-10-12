# Architecture

## One product boundary, one credential

This module manages a Fastly **CDN delivery service** and the Fastly-native **Next-Gen WAF (NGWAF)** as one unit,
through the single `fastly/fastly` provider and a single `FASTLY_API_KEY`. Fastly's current NGWAF uses a **workspace**
model exposed by that provider — there is no separate Signal Sciences corp/site, and no second credential. (The legacy
`signalsciences/sigsci` provider models the older standalone product; this module deliberately does not use it.)

```
                         FASTLY_API_KEY (env, per-leaf via Terragrunt)
                                   │  provider fastly/fastly ~> 9.8
        ┌──────────────────────────┴───────────────────────────────┐
        ▼                                                           ▼
  fastly_service_vcl  ── product_enablement.ngwaf ───▶  fastly_ngwaf_workspace
  (delivery/edge)        enabled, workspace_id,            mode=block, immediate=true
   • domains             traffic_ramp                      • workspace_rule  (exclude + block + rate_limit)
   • backend (origin TLS)                                  • workspace_signal (custom categories)
   • healthcheck                                           • thresholds       (repeat-offender backstop)
   • header (real-IP, origin secret)                       • virtual_patches  (CVE templates, data-source validated)
   • snippet (feed cache-key, opt-in)                      • workspace_list   (trusted-IP exemption)
   • logging_syslog
  fastly_tls_subscription (optional, import-hostile → off by default)
```

## Module files (`service/`)

| File | Contents |
|---|---|
| `versions.tf` | provider pin `~> 9.8`, `backend "s3" {}` (filled by Terragrunt `root.hcl`), no provider block |
| `variables.tf` | all inputs + `manage_*` feature switches; secure defaults; no deployment-specific data |
| `locals.tf` | secure baseline: system attack-signal list, custom-signal pattern lists, rule assembly, FP-exemption scope, rate-limit baseline |
| `main.tf` | the `fastly_service_vcl` delivery service + the `product_enablement.ngwaf` edge attachment |
| `features.tf` | the `fastly_ngwaf_workspace` (the WAF brain) + the TLS subscription |
| `signals.tf` | `fastly_ngwaf_workspace_signal` custom signals |
| `rulesets.tf` | the CMS exclusion, per-category block rules, rate limits, virtual patches (+ data source), threshold backstop |
| `outputs.tf` | service/workspace ids, posture summary, virtual-patch drift outputs, TLS DNS challenge |
| `adopt.tf` | `adopt_existing` import path, honest about Fastly's by-ID / create-only limits |

## How requests are judged (order of effect)

1. **Signal exclusion** (`exclude_signal`, type=`signal`) removes the exempt signals (default SQLI/XSS) **only** for
   trusted IPs on CMS admin/JSON paths — applied during inspection, before the block decision, so an exempt editor
   request never trips the inline block.
2. **System attack signals** (SQLI, XSS, CMDEXE, TRAVERSAL, CODEINJECTION, BACKDOOR, LOG4J-JNDI, SCANNER, …) are
   blocked **inline, per request** by the workspace (`mode=block` + `attack_signal_thresholds{immediate=true}`).
3. **Custom block rules** (type=`request`, action=`block`) catch the path/UA/query categories the system set does not
   score: ColdFusion/CFML admin, cred-hunt, WP (path **or** `?rest_route=`), scanner paths/UAs, phpunit, encoded trav.
4. **Rate-limit rules** (type=`rate_limit`) cap optional high-cost-endpoint abuse and admin-login brute force.
5. **Virtual patches** block CVE templates (Java-RCE class — relevant on a JVM origin).
6. **Threshold backstop** blocks a sustained flood source (high limit; secondary to per-request blocking).

## State & deployment

Terragrunt leaf → `source = "…/terraform-fastly//service?ref=X.Y"`, S3 backend with a native lockfile, OpenTofu
≥ 1.12. The leaf holds all deployment-specific values (origin address, hostnames, trusted IPs, the origin shared
secret); the module holds only generic logic and secure defaults. See the sibling `terraform-cloudflare` for the
identical convention.
