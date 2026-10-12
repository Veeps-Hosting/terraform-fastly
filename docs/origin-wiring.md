# Origin web-server wiring

What the **origin web server** must do so a site works correctly and securely behind the Fastly CDN + NGWAF this
module builds. Examples are for nginx; adapt to your server. Roll this out on a **staging** origin first.

## Request flow

```
client ─TLS─▶ Fastly edge POP (NGWAF inspects, blocks inline) ─TLS─▶ origin :443
                                                                     │  (1) IP gate: trust Fastly ranges, else 403
                                                                     │  (2) secret gate: require the edge secret, else 403
                                                                     │  (3) restore real client IP from X-Forwarded-For
                                                                     ▼
                                                                  application
```

Fastly sets `Fastly-Client-IP` from the real edge connection and appends the client to `X-Forwarded-For`; the origin
restores the true client IP from XFF for its logs and any residual origin rate-limit.

## 1. Trust Fastly and restore the real client IP

Trust only Fastly's published ranges as proxies (fetch them from `https://api.fastly.com/public-ip-list`), and read
the client IP from `X-Forwarded-For`:

```nginx
# one set_real_ip_from line per Fastly CIDR (keep in sync with the public-ip-list; alarm on drift)
set_real_ip_from 23.235.32.0/20;
# ... (all Fastly ranges) ...
real_ip_header    X-Forwarded-For;
real_ip_recursive on;
```

## 2. IP origin-lockdown

Refuse any request that does not arrive from a trusted proxy (Fastly). For example, with a `geo` map:

```nginx
geo $realip_remote_addr $is_trusted_proxy { default 0; 23.235.32.0/20 1; /* ... */ }
# in the server block, before any app logic:
if ($is_trusted_proxy = 0) { return 403; }
```

## 3. Secret origin-lockdown (required)

The IP allowlist alone is **not** sufficient: Fastly egress IPs are shared across every Fastly tenant, so any Fastly
customer could reach the origin from a "trusted" IP. Require the shared-secret header the module injects
(`origin_secret_header` / `origin_secret_value`) and 403 on mismatch:

```nginx
# header name maps to the nginx variable, e.g. X-Origin-Secret -> $http_x_origin_secret
if ($http_x_origin_secret != "<SECRET>") { return 403; }
```

- Store the secret **once** in your secret store; the **same** value feeds the module leaf's `origin_secret_value` and
  this origin check. Rotate in both places together.
- Keep both gates (IP **and** secret) — they are what make the WAF non-bypassable.
- The Fastly **health check** carries this header (the module sets it on the probe), so the secret gate does not mark
  the backend down.

## 4. Retire duplicate protections (end-state, after Fastly is proven)

While rolling out, keep any incumbent controls so the site is reachable both ways. Once Fastly is the **sole** front
and graded clean, retire the origin controls the WAF now owns, in one reviewed change:

| Origin control | Why it's now duplicate | End-state |
|---|---|---|
| origin rate-limits (e.g. `limit_req` zones) | Fastly NGWAF `rate_limit` rules own rate limiting | remove |
| an incumbent WAF's origin allow/trust | that WAF no longer fronts these names | remove |
| origin bot/UA/geo blocking | NGWAF system signals + scanner rules own it | evaluate; drop if duplicate |
| origin `Strict-Transport-Security` | the Fastly service also sets HSTS | keep one, not both |

**Keep** at the origin even behind Fastly (defence in depth, not duplicate): the IP gate, the secret gate, realip,
TLS, and the application config. **Do not** strip the IP/secret gates.

## Verify checklist (origin)

- rendered server block contains the IP 403 **and** the secret-header 403, plus the realip lines.
- a request from a non-Fastly IP **without** the secret → `403`; **with** the correct secret header from a Fastly
  path → the site serves.
- the origin access log shows the **true client IP** (from XFF), not a Fastly edge IP.
