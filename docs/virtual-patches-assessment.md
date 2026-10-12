# Fastly Next-Gen WAF (NGWAF) Virtual Patches — Enumeration & Applicability Assessment

**For:** (financial services, AU) — Fastly CDN + NGWAF module replacing the incumbent WAF
**Origin stack:** the CMS on **a JVM app / Adobe ColdFusion = a JVM / Java application server** (NOT PHP/WordPress, though it receives PHP/WP probe traffic)
**Date:** 2026-10-13
**Constraint:** No Fastly API key — enumerated **entirely from published Fastly docs, the Terraform provider docs, and Fastly changelog/blog announcements**. No IDs fabricated; every CVE below was found in a cited public Fastly source. The authoritative per-workspace list must be pulled from the data source at apply time (see §2 completeness caveat).

---

## 1. How virtual patches work in Fastly NGWAF

### What a virtual patch *is*
From the Fastly guide **"Virtual patches for CVEs"** (`https://www.fastly.com/documentation/guides/next-gen-waf/using-ngwaf/virtual-patches-for-cves/`), verbatim:

> "A virtual patch is a pre-constructed rule that targets a specific CVE. Once enabled, requests that meet the virtual patch's criteria are tagged with the appropriate CVE signal and then blocked or logged per your enablement specification."

> "We announce new virtual patches through our changelog guide."

So a virtual patch is a **Fastly-authored, pre-built detection rule for one named CVE**. It is *not* something you create — you enable/disable it and choose log vs block. New ones are announced in the Fastly changelog ("Next-Gen WAF announcements") and via an optional email subscription ("Alert me when a new Virtual Patch for a CVE is available").

### How the `virtual_patch_id` is obtained, and whether it is a CVE string or opaque ID
**It is the bare CVE string.** Confirmed three independent ways:

1. **Terraform provider resource example** (`fastly/terraform-provider-fastly`, `docs/resources/ngwaf_virtual_patches.md`), verbatim:
   ```terraform
   resource "fastly_ngwaf_virtual_patches" "demo" {
     action            = "block"
     enabled           = true
     virtual_patch_id    = "CVE-2017-5638"
     workspace_id       = fastly_ngwaf_workspace.demo.id
   }
   ```
   → the `virtual_patch_id` value is literally `"CVE-2017-5638"`.

2. **Fastly changelog entries** name the patch/templated-rule by the bare CVE ID. The 2026-07 entry for the WordPress "wp2shell" chain states the control-panel object is "a templated rule named **CVE-2026-63030**" / "a virtual patch named **CVE-2026-63030**", located by searching the CVE ID.

3. **Guide text** refers to the signal generically as `CVE-YYYY-NNNNN`.

**Caveat on the API field description:** the Fastly API reference (`https://www.fastly.com/documentation/reference/api/ngwaf/virtual-patches/`) describes the `id` field only as *"The ID of the virtual patch."* — it does **not** itself commit to the CVE-string format. But the Terraform example and every changelog entry use the bare CVE string, so for module purposes **treat `virtual_patch_id` = the CVE string** (e.g. `CVE-2021-44228`). One known non-CVE-exact id exists: the Log4Shell **STRICT** variant is `CVE-2021-44228-STRICT` (CVE string + suffix).

### Per-workspace vs global
**Per-workspace.** The API endpoints are all nested under a workspace:
`/ngwaf/v1/workspaces/{workspace_id}/virtual-patches`. The Terraform resource requires `workspace_id`, and the data source is scoped `workspace_id`. Fastly **pre-seeds the full catalog into every workspace** — the API exposes only **List / Retrieve / Edit (PATCH)** operations; there is **no Create and no Delete** endpoint. You therefore do not add patches; you enumerate the ones Fastly has seeded and toggle `enabled` + `mode`/`action` on each.

### Resource + data source fields (verbatim)

**Resource `fastly_ngwaf_virtual_patches`** (`docs/resources/ngwaf_virtual_patches.md`) — description verbatim:
> "Provides a Fastly Next-Gen WAF Virtual Patch. Virtual patching rules block or log requests matching specific vulnerabilities."

Schema (verbatim):
- **Required**
  - `action` (String) — "Action to take when a signal for virtual patch is detected. Accepted values are `log` and `block`."
  - `enabled` (Boolean) — "Control for enabling and disabling a virtual patch."
  - `virtual_patch_id` (String) — "The ID of the virtual patch."
  - `workspace_id` (String) — "The ID of the workspace."
- **Read-Only**
  - `id` (String) — "The ID of this resource."

Import (verbatim): `terraform import fastly_ngwaf_virtual_patches.demo <workspace_id>/<virtual_patch_id>`

**Data source `fastly_ngwaf_virtual_patches`** (`docs/data-sources/ngwaf_virtual_patches.md`) — description verbatim:
> "Use this data source to get a list of Fastly Next-Gen WAF Virtual Patches for a given workspace."

Schema (verbatim):
- **Required**: `workspace_id` (String) — "The ID of the workspace."
- **Read-Only**:
  - `id` (String) — "The ID of this resource."
  - `virtual_patches` (Set of Object) — "List of all virtual patches for a given workspace."
  - Nested schema for `virtual_patches` (Read-Only): `enabled` (Boolean); `id` (String); `mode` (String)

**API data model** (`reference/api/ngwaf/virtual-patches/`) adds a `description` field and defines `mode`:
- `id` (string) — "The ID of the virtual patch."
- `enabled` (boolean) — "Control for enabling and disabling a virtual patch."
- `mode` (string) — "Action to take when a signal for virtual patch is detected."
- `description` (string) — "Description of the virtual patch."

> **Naming gotcha for the module:** the **resource** calls the log/block field `action`; the **data source and API** call the same field `mode`. Both carry `log` / `block`. Don't let the module's internal variable drift between the two names. Also note `enabled=false` is the true "off" state — there is no separate "disabled" action value; a patch with `enabled=false` does nothing regardless of `mode`/`action`.

---

## 2. Enumerated catalog (confirmed-from-public-docs subset)

### COMPLETENESS CAVEAT — READ THIS
**This table is NOT the complete catalog.** Fastly's published docs/API/provider docs show only **examples** (`CVE-2017-5638`, `CVE-2022-26134`), and there is **no public index page** listing every seeded virtual patch. The entries below were reconstructed from individual Fastly **changelog announcements** and **security blog posts** — i.e. the ones Fastly chose to publicise. The real, authoritative, complete list for 's workspace is **only obtainable at apply time from `data.fastly_ngwaf_virtual_patches` (or `GET /ngwaf/v1/workspaces/{id}/virtual-patches`)**. Fastly adds new patches continuously (the changelog has many more "Protection from CVE…" / "Added virtual patch for CVE…" entries than are captured here).

**→ Practical rule: treat every `virtual_patch_id` below as a candidate to be validated against the live data source. Do not `terraform apply` a hardcoded id without confirming the workspace actually seeds it, or the resource will error.**

### Relevance key
- **HIGH** = directly exploitable-class against a JVM/ColdFusion/CFML origin (Java RCE / injection / JNDI / OGNL / EL / deserialization patterns).
- **MED** = infrastructure/web-server layer that *could* sit in 's path (reverse proxy, Tomcat front).
- **LOW** = product-specific to a stack does NOT run (WordPress, Magento, Next.js, Oracle EBS) — defence-in-depth + visibility only, because probe traffic for these exists.

### FP-risk note that applies to the whole table
Virtual patches fall into two shapes, and FP risk follows the shape:
- **Generic-pattern patches** (Log4Shell `${jndi:…}`, Text4Shell `${script:…}`, Spring4Shell `class.*.classLoader.*`) match injection strings that can in principle appear in *any* request body/param → slightly higher (still low) FP risk, but **broader protective value**. ColdFusion/CFML markup uses `#…#` / `##`, **not** `${…}`, so the `${…}`-based ones are low-FP on this specific origin.
- **Product-shaped patches** (Struts param names like `top.UploadFileName`, Confluence URIs like `/wiki/…`, the `spring.cloud.function.routing-expression` header) match request shapes that **never occur legitimately on a a CMS site** → ~nil FP risk, but protective value limited to swatting scanners (they will NOT catch a CFML-native RCE).

| CVE / name | What it protects against | Technology | Relevance to | Recommended action | FP risk (the CMS/a JVM app) | Rationale |
|---|---|---|---|---|---|---|
| **CVE-2021-44228** (Log4Shell) | Log4j2 JNDI lookup RCE (`${jndi:ldap://…}`) | **Java** (Log4j2) | **HIGH** | **block** | Low — `${jndi:}` never legitimate; a JVM app uses `#…#` not `${}` | Top-priority. Matches the ~130 Java/deserialization/Log4Shell-JNDI probes seen in 30d. Regex virtual patch; Fastly later shipped a lower-FP SmartParse **Log4j-JNDI system signal** that is the better long-term control (see §4 note on signals). |
| **CVE-2021-44228-STRICT** | Stricter Log4Shell variant | **Java** (Log4j2) | **HIGH** | **log** (not block) | **Medium — Fastly explicitly warns it "could result in more false positives"** | Keep in LOG as a visibility net; do NOT block with the strict variant on a CMS. Grade on staging before considering block. |
| **CVE-2022-42889** (Text4Shell) | Apache Commons Text interpolation RCE (`${script:…}`, `${dns:…}`, `${url:…}`) | **Java** (Commons Text) | **HIGH** | **block** | Low — same `${…}` shape, not used by a JVM app markup | Java RCE-class, generic-pattern, on-path with the deserialization/JNDI probe category. |
| **CVE-2022-22965** (Spring4Shell) | Spring MVC/WebFlux data-binding RCE (`class.module.classLoader…`) | **Java** (Spring) | **HIGH** | **block** | Very low — those param names never occur legitimately | Confirmed templated rule. Exploit needs Tomcat WAR deploy (a JVM app *runs on Tomcat*), so exploitable-class, not merely theoretical. |
| **CVE-2022-22963** (Spring Cloud Function) | SpEL injection via `spring.cloud.function.routing-expression` header | **Java** (Spring Cloud) | **HIGH** | **block** | Nil — that header never appears legitimately | Zero-FP, cheap. Fastly documented a rule for it (DIY/templated). |
| **CVE-2017-5638** (Struts2 / Equifax) | Struts2 Jakarta Multipart OGNL RCE via `Content-Type` | **Java** (Struts2) | **HIGH** | **block** | Nil — OGNL in Content-Type never legitimate | The provider's own example id. Zero-FP, keep on. |
| **CVE-2023-50164** | Apache Struts path-traversal file-upload RCE | **Java** (Struts) | **HIGH** (class) / product-shaped | **block** | Nil for non-Struts origin | Defence-in-depth + scanner visibility; signature is Struts-specific so protective value limited, but zero-FP. |
| **CVE-2024-53677** (S2-067) | Apache Struts file-upload logic RCE | **Java** (Struts) | **HIGH** (class) / product-shaped | **block** | Nil for non-Struts origin | As above. |
| **CVE-2022-26134** | Atlassian Confluence unauth OGNL injection RCE | **Java** (Confluence) | MED (OGNL class) | **block** (zero-FP) or log | Nil — Confluence URIs don't exist on the CMS | Provider/guide example. Product-shaped; keep as cheap zero-FP scanner net. |
| **CVE-2021-26084** | Atlassian Confluence OGNL injection RCE | **Java** (Confluence) | MED (OGNL class) | **block** (zero-FP) or log | Nil — Confluence-specific | Same class as above. |
| **CVE-2021-41773** | Apache HTTP Server path traversal → RCE | Apache httpd | MED | **log** | Low–med (generic traversal shape) | Relevant only if an Apache/httpd tier sits in front of a JVM app/Tomcat. Fastly notes TRAVERSAL & CMDEXE system signals also cover it. |
| **CVE-2021-40438** | Apache HTTP mod_proxy SSRF | Apache httpd | MED | **log** | Low | Infra-layer; log for visibility. |
| **CVE-2026-63030** (wp2shell) | WordPress RCE chain | WordPress/PHP | **LOW** | **log** | Low — WP-specific paths | Origin is not WP; WP probe traffic exists → keep as cheap visibility. Same patch also covers **CVE-2026-60137**. |
| **CVE-2026-60137** | Covered by the wp2shell patch above | WordPress/PHP | **LOW** | (folded into CVE-2026-63030) | Low | Not a separate enable — Fastly bundles it under CVE-2026-63030. |
| **CVE-2025-29927** | Next.js middleware authorization bypass | Next.js | **LOW** | log or skip | Low | Not Next.js; near-zero value. Log only if you want the telemetry. |
| **CVE-2025-54236** (SessionReaper) | Adobe Commerce / Magento unauth API access | Magento/PHP | **LOW** | log or skip | Low | Not Magento. |
| **CVE-2024-34102** (CosmicSting) | Adobe Commerce / Magento XXE | Magento/PHP | **LOW** | log or skip | Low | Not Magento (referenced in Fastly JA guide screenshot). |
| **CVE-2026-75650** (StyleSmuggler) | Adobe Commerce / Magento | Magento/PHP | **LOW** | log or skip | Low | Not Magento. (Also tracked fleet-wide as the incumbent WAF policy 175 for actual Magento hosts.) |
| **CVE-2025-61882** | Oracle E-Business Suite pre-auth RCE | Oracle EBS | **LOW / skip** | skip | n/a | No Oracle EBS anywhere near . |

### KEY HONEST FINDING — the origin's OWN product CVEs are NOT in the catalog
**No Fastly virtual patch exists for ColdFusion (e.g. CVE-2023-26360) or for any a JVM app RCE** in any public Fastly doc, changelog, or blog that could be found. This is the crucial caveat for :

- Fastly's Java virtual patches are for **Struts, Spring, Log4j, Commons Text, Confluence** — not for the ColdFusion/CFML engine the CMS actually runs on.
- Therefore the virtual-patch layer gives **Java RCE-*class* coverage and scanner visibility**, but the **primary protection for a ColdFusion/CFML-native vulnerability (ColdFusion/CFML admin probes, CF deserialization, a JVM app RCE) must come from the NGWAF system attack signals** — `CMDEXE`, `TRAVERSAL`, `SQLI`, `XSS`, `CODEINJECTION`, the Log4j-JNDI SmartParse signal, backdoor/scanner signals — configured via NGWAF **rules/signals**, which are a *separate* module concern from `virtual_patches`. Set expectations accordingly: don't tell "the virtual patches cover ColdFusion." They don't; the attack-signal engine does.
- **Action item:** at apply time, `grep` the live `data.fastly_ngwaf_virtual_patches` output for any `coldfusion`/`lucee`/`CVE-2023-26360`-type entry. If Fastly has added one since this research, promote it to HIGH/block. If absent (expected), rely on system signals.

---

## 3. Ready-to-paste Terraform `virtual_patches` map (target end-state)

> **Staging rollout note:** the values below are the **graded target end-state**. Per the workflow, during the staging phase the module should force **every** entry to `action = "log"` on the temp staging URL (e.g. a module-level `var.staging = true` that overrides `action` to `log`), grade with the benign replay harness, then flip to the per-entry `action` shown here on production cutover. Do **not** ship `block` straight to production unseen.
>
> **Every id is marked `# <-- confirm id via data.fastly_ngwaf_virtual_patches`** because the authoritative list is per-workspace (see §2). An id not seeded in the workspace will fail apply — validate first (see §4).

```hcl
virtual_patches = {
  # ─────────────────────────────────────────────────────────────────────────
  # TIER 1 — Java/JVM RCE-class, directly exploitable-class vs a ColdFusion/CFML origin.
  #          Target action = block. Generic injection-pattern patches first.
  # ─────────────────────────────────────────────────────────────────────────
  "CVE-2021-44228" = { action = "block", enabled = true }  # Log4Shell (Log4j JNDI)        # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2022-42889" = { action = "block", enabled = true }  # Text4Shell (Commons Text)      # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2022-22965" = { action = "block", enabled = true }  # Spring4Shell                   # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2022-22963" = { action = "block", enabled = true }  # Spring Cloud Function SpEL     # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2017-5638"  = { action = "block", enabled = true }  # Struts2 Jakarta Multipart RCE  # <-- confirm id via data.fastly_ngwaf_virtual_patches

  # ─────────────────────────────────────────────────────────────────────────
  # TIER 2 — Java product-shaped (Struts/Confluence). Zero-FP on a non-Java-app
  #          origin → safe to block for scanner-swatting + visibility, but low
  #          protective value (won't catch a CFML-native RCE).
  # ─────────────────────────────────────────────────────────────────────────
  "CVE-2023-50164" = { action = "block", enabled = true }  # Struts dir-traversal upload    # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2024-53677" = { action = "block", enabled = true }  # Struts S2-067 upload RCE        # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2022-26134" = { action = "block", enabled = true }  # Confluence OGNL unauth RCE      # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2021-26084" = { action = "block", enabled = true }  # Confluence OGNL injection       # <-- confirm id via data.fastly_ngwaf_virtual_patches

  # ─────────────────────────────────────────────────────────────────────────
  # TIER 3 — LOG only. High-FP Java variant + infra layer. Keep as visibility.
  # ─────────────────────────────────────────────────────────────────────────
  "CVE-2021-44228-STRICT" = { action = "log", enabled = true }  # Log4Shell STRICT — Fastly warns higher FP; NEVER block on a CMS  # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2021-41773"        = { action = "log", enabled = true }  # Apache httpd traversal (only if httpd tier in front)            # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2021-40438"        = { action = "log", enabled = true }  # Apache httpd mod_proxy SSRF                                     # <-- confirm id via data.fastly_ngwaf_virtual_patches

  # ─────────────────────────────────────────────────────────────────────────
  # TIER 4 — PHP/WordPress/Magento/Next.js/Oracle. Origin does NOT run these.
  #          Defence-in-depth + probe-traffic visibility only → LOG.
  #          (Set enabled=false to drop entirely if you want a lean map.)
  # ─────────────────────────────────────────────────────────────────────────
  "CVE-2026-63030" = { action = "log", enabled = true }   # WP "wp2shell" RCE (also covers CVE-2026-60137)  # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2025-29927" = { action = "log", enabled = false }  # Next.js authz bypass — not our stack            # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2025-54236" = { action = "log", enabled = false }  # Magento SessionReaper — not our stack           # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2024-34102" = { action = "log", enabled = false }  # Magento CosmicSting XXE — not our stack          # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2026-75650" = { action = "log", enabled = false }  # Magento StyleSmuggler — not our stack            # <-- confirm id via data.fastly_ngwaf_virtual_patches
  "CVE-2025-61882" = { action = "log", enabled = false }  # Oracle EBS pre-auth RCE — not our stack          # <-- confirm id via data.fastly_ngwaf_virtual_patches
}
```

---

## 4. Data-source-driven pattern (avoid hardcoding IDs)

The provider **does** support enumerating the live catalog: `data "fastly_ngwaf_virtual_patches"` returns `virtual_patches` as a set of `{ id, enabled, mode }` for the workspace. Use it two ways:

**(a) Validate the curated map against what the workspace actually seeds** — fail fast instead of a mid-apply error on an id Fastly hasn't seeded:

```hcl
data "fastly_ngwaf_virtual_patches" "available" {
  workspace_id = fastly_ngwaf_workspace.this.id
}

locals {
  available_ids = toset([for p in data.fastly_ngwaf_virtual_patches.available.virtual_patches : p.id])
  requested_ids = toset(keys(var.virtual_patches))
  # ids we asked for that the workspace does NOT offer:
  missing_ids   = setsubtract(local.requested_ids, local.available_ids)
}

# Only manage patches that actually exist in the workspace:
resource "fastly_ngwaf_virtual_patches" "this" {
  for_each         = { for id, cfg in var.virtual_patches : id => cfg if contains(local.available_ids, id) }
  workspace_id     = fastly_ngwaf_workspace.this.id
  virtual_patch_id = each.key
  action           = var.staging ? "log" : each.value.action   # staging override → everything logs
  enabled          = each.value.enabled
}

# Surface the gap so an operator confirms it's intentional, not a typo/missing seed:
output "virtual_patches_requested_but_unavailable" {
  value = local.missing_ids
}
```

**(b) Discover what Fastly has added since this research** — list everything the workspace offers but the map doesn't mention, so new high-value Java/CF patches aren't missed:

```hcl
output "virtual_patches_available_but_unmanaged" {
  value = setsubtract(local.available_ids, local.requested_ids)
}
```

**Why not pure for_each over the data source?** You *could* `for_each` directly over `data...virtual_patches` and blanket-enable, but that throws away the per-CVE action/priority grading that is the whole point for a JVM origin (block the Java RCE-class, log the rest). Keep the **curated map as the source of truth for intent**, and use the data source only to **validate** (a) and **surface drift/new patches** (b). This gives: no hardcoded id can silently fail, and new Fastly patches get flagged for triage rather than auto-blocked.

**Notes / gotchas for the module author**
- Resource field is `action`; data source/API field is `mode`. Same log/block semantics — keep the module variable name consistent and map to `action` on the resource.
- No create/delete API → the module only ever toggles seeded patches. Removing an entry from the map (with the `for_each` above) will `terraform destroy` that resource, which in NGWAF terms reverts the patch toward its default state — confirm that default is "disabled/log" before relying on removal as a disable.
- The STRICT Log4Shell variant id carries a `-STRICT` suffix, so the "id == CVE string" assumption isn't 100% — another reason to validate against the data source rather than regex-deriving ids from a CVE list.
- **Separate but essential:** virtual patches are only the CVE-template layer. The ColdFusion/CFML-native protection (ColdFusion/CFML admin probes, CF deserialization, the bulk of the common attack categories (LFI, command-injection, SQLi, code-injection, XSS)) is delivered by NGWAF **attack-type system signals + custom rules**, which the module must wire up alongside `virtual_patches`. The Log4j JNDI SmartParse **system signal** (lower FP than the regex CVE-2021-44228 virtual patch) belongs in that layer too.

---

## Sources
- Terraform provider — resource: `github.com/fastly/terraform-provider-fastly` `docs/resources/ngwaf_virtual_patches.md` (fetched via `gh api`, raw markdown)
- Terraform provider — data source: same repo `docs/data-sources/ngwaf_virtual_patches.md`
- Fastly API reference: https://www.fastly.com/documentation/reference/api/ngwaf/virtual-patches/
- Fastly guide "Virtual patches for CVEs": https://www.fastly.com/documentation/guides/next-gen-waf/using-ngwaf/virtual-patches-for-cves/
- Fastly guide "Configuring system signals": https://www.fastly.com/documentation/guides/next-gen-waf/signals/configuring-system-signals/
- Changelog — wp2shell: https://www.fastly.com/documentation/reference/changes/2026/07/added-virtual-patch-for-cve-2026-63030-wp2shell-also-covers-cve-2026-60137/
- Changelog — Log4Shell virtual patch + STRICT: https://www.fastly.com/documentation/reference/changes/2021/12/added-virtual-patch-for-cve-2021-44228/ and `.../added-virtual-patch-for-cve-2021-44228-strict/`
- Changelog — Text4Shell: https://www.fastly.com/documentation/reference/changes/2022/10/protection-from-cve-2022-42889-text4shell
- Changelog — Confluence CVE-2022-26134: https://www.fastly.com/documentation/reference/changes/2022/06/protection-from-cve-2022-26134-unauthenticated-rce-in-confluence
- Changelog — Struts CVE-2023-50164: https://www.fastly.com/documentation/reference/changes/2023/12/protection-from-cve-2023-50164-apache-struts-directory-traversal
- Changelog — Struts CVE-2024-53677: https://www.fastly.com/documentation/reference/changes/2024/12/protection-from-cve-2024-53677-apache-struts-file-upload-logic-vulnerability/
- Changelog — Next.js CVE-2025-29927, Magento CVE-2025-54236 / CVE-2026-75650, Oracle EBS CVE-2025-61882 (Fastly changelog, 2025–2026)
- Fastly blog — Spring4Shell/Spring Cloud (CVE-2022-22965 / CVE-2022-22963): https://www.fastly.com/blog/spring-has-sprung-breaking-down-cve-2022-22963-and-spring4shell-cve-2022
- Fastly blog — Log4j JNDI attack signal: https://www.fastly.com/blog/announcement-log4j-jndi-attack-signal-available-now
- Fastly blog — Confluence OGNL CVE-2021-26084: https://www.fastly.com/blog/protecting-our-customers-against-atlassian-confluence-ognl-injection-vulnerability
- **Not found (honest negative):** no Fastly virtual patch for ColdFusion CVE-2023-26360 or any a JVM app RCE in any public Fastly source.
