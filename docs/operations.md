# Operations runbook

Staged rollout, grading, cutover, rollback and troubleshooting for a Fastly CDN + NGWAF deployment. Roll out on a
**staging** target first, with any incumbent WAF remaining authoritative for production throughout.

## Prerequisites

- A Fastly account with NGWAF entitlement; `FASTLY_API_KEY_<ACCOUNT>` exported on the deploy host.
- The origin shared secret created in a secret store — the **same** value feeds the leaf `origin_secret_value` and the
  origin web server's required-header check.
- The origin wiring in place per [`docs/origin-wiring.md`](origin-wiring.md) (trust Fastly IPs, restore real client
  IP, require the secret header).

## Stage 1 — deploy in LOG mode, parallel to any incumbent

1. Leaf inputs: `ngwaf_mode="log"`, `ngwaf_virtual_patch_force_log=true`, `ngwaf_edge_ramp=10`, `manage_tls=true`,
   domains = a temporary trial hostname, backend = the staging origin.
2. On the deploy host: `cd <leaf> && terragrunt plan` → review (expect all creates). `terragrunt apply`.
   (If the `FASTLY_API_KEY` is IP-pinned, use `scripts/tg-fastly` with `TG_FORCE_V4=1`.)
3. Publish the `tls_managed_dns_challenge` output as a DNS record to validate the Fastly cert for the temp name.
   CNAME the temp name to the Fastly service.
4. Bring the origin wiring up for the trial hostname and run the origin verify checklist in `docs/origin-wiring.md`.

## Stage 2 — grade with the efficacy harness

```
scripts/waf_efficacy_check.sh https://<trial-hostname> --host <origin-vhost>
```

Wraps a benign attack-pattern replay (`--config fastly`). **Gate:** bypass rate ≤ your baseline **and** 0 false
positives on legitimate control requests. In log mode NGWAF observes; read the NGWAF event feed to confirm each attack
category is flagged. Tune `signal_pattern_overrides` / `custom_category_disable` for any false-positive category,
re-run, until clean.

## Stage 3 — enforce and ramp

1. Flip `ngwaf_mode="block"`, `ngwaf_virtual_patch_force_log=false`. `terragrunt apply`.
2. Re-run the harness against block mode: attacks are now **blocked** (406 + the Fastly body fingerprint), the controls
   still 200. Confirm bypass% at/under baseline.
3. Ramp edge inspection `ngwaf_edge_ramp` 10 → 50 → 100 across applies, watching origin health + NGWAF events.

## Stage 4 — remove duplicate origin protections (end-state)

Once Fastly is the sole front for the trial names and graded clean, in one reviewed commit retire the origin controls
Fastly now owns (origin rate-limits, the incumbent-WAF allow, a double HSTS). Keep the IP + secret gates. See
`docs/origin-wiring.md`.

## Production cutover (separate, gated)

Only after staging is proven: build a production leaf (prod domains, prod origin), repeat log→grade→block→ramp on a
temp name, then DNS cutover. Origin lockdown (IP + secret) must be confirmed **before** cutover — a WAF with an open
origin is advisory, not enforcing.

## Rollback

- **Fast disable (keep the service):** `ngwaf_mode="off"` (or `="log"`), apply — WAF stops blocking in ~seconds.
- **Remove the WAF from traffic:** CNAME the name back to the incumbent/origin; the Fastly service can stay for later.
- **Full teardown:** `terragrunt destroy` (the TLS subscription has `force_destroy`). Revert the origin wiring.

## Apply-time verify (NGWAF string semantics `terraform validate` cannot check)

On the first real plan/apply confirm: a workspace-list condition references the list as **`site.<list-name>`**; custom
signals referenced as **`site.<name>`** and names lowercase-alphanumeric; multival fields `value_string` /
`query_parameter` / `name` accepted; `product_enablement.ngwaf.traffic_ramp` applied as expected; the `block` response
is `406` (what the harness fingerprints). Outputs `virtual_patches_requested_but_unavailable` /
`virtual_patches_available_but_unmanaged` must be triaged (not silently ignored).

## Monitoring / troubleshooting

- **Origin health:** the Fastly health check tolerates JVM warmup (wide window, low threshold); a brief 307/503 on an
  app-server restart is expected, a sustained one is real. The probe carries the origin secret header so the origin's
  secret gate does not 403 it.
- **"Site blocked for everyone":** check the NGWAF event feed for a mis-scoped block rule or over-broad custom
  pattern; flip `ngwaf_mode="log"` to stop enforcing while you fix.
- **Editors blocked:** confirm the trusted IP is in `trusted_exemption_ips` and the path is in `cms_admin_paths`/
  `cms_json_api_paths`; the exemption only covers `cms_exempt_signals` — another signal tripping means tighten the
  rule, do not widen the exemption to allow-all.
- **403 from origin on every request:** the IP or secret gate — confirm the request arrives from a Fastly IP with the
  correct secret header (the gates are AND).
- **Rate limit hitting real users:** confirm `client_identifiers type=ip` is keying on the **true** client (realip),
  not a Fastly edge IP; raise the threshold.
- **block fingerprint:** a Fastly NGWAF block = 406 + Fastly body; an origin nginx 403 = small body. The harness
  classifies by body size + headers — always capture `%{size_download}`.
