# Security posture

The design goal is explicit: **block, inline and per request, the common web-attack set** that a semantic WAF blocks,
while never false-positive-blocking a CMS whose editors post rich-text/HTML. This document is the threat model and the
per-category coverage.

## The gap this closes

Stock NGWAF **counts** attack signals per source IP and only acts once a per-IP threshold is crossed — so request #1
of every new attacker reaches the origin. A semantic WAF denies per request. This module makes NGWAF behave the same:

```
mode = "block"                               # enforce, not observe
attack_signal_thresholds { immediate = true } # block on request #1 when ANY attack signal fires
```

The per-IP count thresholds (`fastly_ngwaf_thresholds`) are kept only as a high **repeat-offender backstop**,
deliberately set well above a shared office-NAT IP's incidental noise.

## Coverage: every category → an inline control

| Category | Inline control | Confidence |
|---|---|---|
| SQLi | system `SQLI` + immediate block; CMS body-exclusion for trusted admin only | high |
| XSS | system `XSS` + immediate block; same scoped exclusion | high |
| LFI / file-include | system `TRAVERSAL` + custom `encodedtraversal` regex | high |
| Command injection | system `CMDEXE` + immediate block (no exemption) | high |
| PHP code injection | system `CODEINJECTION` / `BACKDOOR` | high |
| Log4Shell / JNDI | system `LOG4J-JNDI` (inspects headers+body) **+** `CVE-2021-44228` virtual patch — **exploitable-class on a JVM origin** | high |
| Java product RCE (Struts/Spring/Confluence) | virtual patches (block) — defence-in-depth + scanner-swat | high |
| Deserialization | system signals; optional body rule in log first | medium |
| SSRF / SSTI | system signals; tight custom rules only if graded clean | medium |
| ColdFusion/CFML admin | custom `cfadmin` path block (hard block) + login rate-limit | high |
| cred-hunt `/.env /.git` | custom `credhunt` path block | high |
| WP probes incl `?rest_route=` | custom rule: path **OR** query-parameter name (catches the query-string form a path-only rule misses) | high |
| scanner paths + UAs | system `SCANNER`/`USERAGENT` + custom `scannerpath`/`scannerua` | high |
| phpunit / phpMyAdmin | custom `phpdiscovery` path block | high |
| high-cost endpoint cache-buster abuse | **VCL cache-key normalization** (opt-in, primary) + NGWAF rate limit (backstop) | high |
| origin-direct bypass | Fastly-IP allowlist **+** shared-secret header (origin 403s on mismatch) | high |

### Why the custom path rules matter (measured)

A semantic WAF (incumbent-class) scores injection *payloads* — SQLi/XSS/cmd in params and bodies — and blocks those
inline. It does **not** flag a bare attack *path* (e.g. `GET /wp-login.php`, `/.env`, `/CFIDE/administrator/`) because
there is no injection signature in it. On a representative preprod site, **13 of 58** benign attack-pattern probes
passed the semantic WAF untouched and were caught only by the origin's own path denylist. The module's custom block
rules (`cfadmin`, `credhunt`, `wpprobe`, `phpdiscovery`, `scannerpath`, `encoded_trav`) exist to close exactly that
gap at the edge — so the origin path denylist can be retired *after* these are enabled and replay-verified, not
before (see `docs/operations.md` Stage 4 and `docs/origin-wiring.md`).

## Defence in depth (layers)

1. **Fastly edge** — NGWAF inline block + rate limits + virtual patches + TLS termination + cache.
2. **Origin IP gate** — origin trusts only Fastly CIDRs, 403 otherwise.
3. **Origin secret gate** — origin requires the Fastly-injected secret header, 403 otherwise (defeats the
   shared-Fastly-IP bypass).
4. **App** — the application, now seeing the true client IP (realip from XFF).

## False-positive safety (the #1 operational risk)

A CMS whose editors post rich-text/HTML will legitimately trip SQLI/XSS. The module emits a **scoped `exclude_signal`**
rule: removes **only the signals in `cms_exempt_signals`** (default SQLI/XSS), **only for `trusted_exemption_ips`**,
**only on CMS admin/JSON paths**, **logged**. Every other signal still blocks, even from a trusted IP — so a
spoofed-trusted-IP RCE is **not** waved through. This is the opposite of a blanket trusted-IP allow, which is a classic
way to re-block legitimate editors on a shared office IP (or to open a hole). Monitoring/health-check sources are
handled at the origin's own allowlist; because this posture blocks attacks rather than challenging, a plain health
probe is not flagged.

## What is explicitly NOT covered

- **No Fastly virtual patch exists for ColdFusion/CFML itself.** A JVM/ColdFusion application's own product CVEs are
  covered by the **system signals + custom rules**, not by a virtual patch. The virtual patches give Java-RCE-class
  coverage (Log4Shell/Spring/Struts) + scanner visibility.
- Virtual-patch catalog completeness is **apply-time** — the data source reconciles the curated map against what the
  workspace seeds and surfaces drift; new Fastly patches must be triaged (`virtual_patches_available_but_unmanaged`).
- Body-pattern categories (SSRF/SSTI/deser) are left to system signals + virtual patches rather than hand-authored
  body regex, which is the highest FP risk against a JSON API; add such rules in **log** mode first.

## Residual risks → mitigations

| Risk | Mitigation |
|---|---|
| NGWAF string-semantics (signal refs, `in_list`, field names) not caught by `terraform validate` | apply-time verify checklist in `service/README.md`; first plan on staging |
| A custom block pattern over-matches a legit application URL | staged **log** mode + the efficacy harness's control probes must stay 0 FP before `block` |
| Origin reachable directly if IP **or** secret gate misconfigured | both gates required; verify checklist in `docs/origin-wiring.md` |
| Shared secret leakage / rotation | stored once in a secret store, injected by Fastly + required by origin; rotate in both |
| Cold `block` flip breaks the app | staged log→block, ramp 10→50→100, incumbent WAF authoritative for production until proven |
