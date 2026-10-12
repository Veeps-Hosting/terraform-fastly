# ---------------------------------------------------------------------------------------------------------------------
# CDN DELIVERY SERVICE
# The Fastly VCL service: domains, the origin backend over TLS, a JVM-warmup-tolerant health check,
# real-client-IP + origin-lockdown headers, and feed cache-key normalization. The NGWAF workspace is attached to
# this service at the edge via the product_enablement.ngwaf block (gated by manage_ngwaf_edge).
# ---------------------------------------------------------------------------------------------------------------------

resource "fastly_service_vcl" "this" {
  count = var.manage_service ? 1 : 0

  name            = var.service_name
  activate        = var.activate
  default_ttl     = var.default_ttl
  version_comment = "Managed by terraform-fastly//service"

  dynamic "domain" {
    for_each = toset(var.domains)
    content {
      name = domain.value
    }
  }

  # --- Origin -------------------------------------------------------------------------------------------------------
  backend {
    name    = var.backend_name
    address = var.backend_address
    port    = var.backend_port

    # Host header sent upstream = the real customer vhost.
    override_host = local.override_host

    # TLS to origin. ssl_check_cert stays true in prod; a staging origin on snakeoil may set origin_check_cert=false.
    use_ssl           = var.origin_tls
    ssl_sni_hostname  = var.origin_tls ? local.origin_sni : null
    ssl_cert_hostname = var.origin_tls ? local.origin_cert : null
    ssl_check_cert    = var.origin_tls ? var.origin_check_cert : null
    min_tls_version   = var.origin_tls ? var.backend_min_tls_version : null

    connect_timeout       = var.backend_connect_timeout
    first_byte_timeout    = var.backend_first_byte_timeout
    between_bytes_timeout = var.backend_between_bytes_timeout

    shield = var.origin_shield != "" ? var.origin_shield : null

    healthcheck = "origin-health"
  }

  # --- Health check -------------------------------------------------------------------------------------------------
  # Wide window + low success threshold + generous initial so a JVM-warmup blip (transient 307/503/000 for
  # 1-2 min on restart) never marks the origin down. Probe a cheap, WAF/auth-exempt path.
  # The probe must carry the origin-lockdown secret header, or the origin's secret gate 403s the health check and
  # marks the backend down. headers is a list of raw "Name: value" strings.
  healthcheck {
    name              = "origin-health"
    host              = local.hc_host
    path              = var.health_check_path
    method            = "GET"
    expected_response = var.health_check_expected_response
    window            = var.health_check_window
    threshold         = var.health_check_threshold
    check_interval    = var.health_check_interval
    initial           = var.health_check_initial
    timeout           = 5000
    headers           = local.inject_origin_secret ? ["${var.origin_secret_header}: ${var.origin_secret_value}"] : []
  }

  # --- Real client IP ----------------------------------------------------------------------------------------------
  # Fastly populates Fastly-Client-IP from the real edge connection and appends X-Forwarded-For. The origin nginx
  # (the origin realip config) restores the client IP from XFF for logging and its own rate limits.
  header {
    name          = "Forward real client IP"
    type          = "request"
    action        = "set"
    destination   = "http.X-Forwarded-For"
    source        = "req.http.Fastly-Client-IP"
    ignore_if_set = false
    priority      = 10
  }

  # --- Origin lockdown: shared-secret header (open-origin-bypass principle) ----------------------------------------------------------
  # Fastly egress IPs are shared across all tenants, so an origin IP-allowlist alone is bypassable by any Fastly
  # customer. The origin nginx must REQUIRE this header and 403 on mismatch. Value is sensitive (from the leaf / SM).
  dynamic "header" {
    for_each = local.inject_origin_secret ? [1] : []
    content {
      name        = "Origin lockdown shared secret"
      type        = "request"
      action      = "set"
      destination = "http.${var.origin_secret_header}"
      source      = "\"${var.origin_secret_value}\""
      priority    = 20
    }
  }

  # --- Security response headers -----------------------------------------------------------------------------------
  header {
    name        = "HSTS"
    type        = "response"
    action      = "set"
    destination = "http.Strict-Transport-Security"
    source      = "\"max-age=31536000\""
    priority    = 10
  }

  # --- a high-cost dynamic JSON feed: cache-key normalization (primary DoS fix) ----------------------------------------------
  # The abuse was 80,210 cache-busting hits/day from one IP, all 200s - distinct query strings defeating the cache.
  # Stripping the query for this path collapses every buster variant to ONE cache object; the NGWAF rate-limit rule
  # (rulesets.tf) is the backstop that stays on regardless.
  #
  # OPT-IN (feed_cache_normalize, default false): stripping the query is ONLY correct if the feed returns one
  # aggregate object for that path. If the endpoint selects a fund by a query parameter (e.g. ?symbol=XYZ), stripping
  # the query would serve the wrong quote to every caller. Confirm the parameter contract of var.feed_cachebuster_path
  # against the origin BEFORE enabling. Only a 200 is pinned, so a transient 5xx during app-server warmup is not cached.
  dynamic "snippet" {
    for_each = var.feed_cache_normalize && var.feed_cachebuster_path != "" ? [1] : []
    content {
      name     = "feed-cache-key-normalize"
      type     = "recv"
      priority = 100
      content  = <<-VCL
        if (req.url.path == "${var.feed_cachebuster_path}") {
          set req.http.X-Feed-Normalized = "the feed";
          set req.url = req.url.path;
        }
      VCL
    }
  }

  dynamic "snippet" {
    for_each = var.feed_cache_normalize && var.feed_cachebuster_path != "" ? [1] : []
    content {
      name     = "feed-cache-ttl"
      type     = "fetch"
      priority = 100
      content  = <<-VCL
        if (req.http.X-Feed-Normalized == "the feed" && beresp.status == 200) {
          set beresp.ttl = ${var.feed_cache_ttl}s;
          set beresp.cacheable = true;
          return(deliver);
        }
      VCL
    }
  }

  # --- NGWAF edge attachment ---------------------------------------------------------------------------------------
  # Binds the workspace to this service at the edge. CREATE-ONLY in practice (adopt.tf does not import it).
  dynamic "product_enablement" {
    for_each = (var.manage_ngwaf_edge && var.manage_ngwaf_workspace) ? [1] : []
    content {
      name = var.service_name
      ngwaf {
        enabled      = true
        workspace_id = fastly_ngwaf_workspace.this[0].id
        traffic_ramp = var.ngwaf_edge_ramp
      }
    }
  }

  # --- Access logging to the log stack -----------------------------------------------------------------------
  dynamic "logging_syslog" {
    for_each = (var.manage_logging && var.syslog_address != "") ? [1] : []
    content {
      name         = "logstack"
      address      = split(":", var.syslog_address)[0]
      port         = tonumber(split(":", var.syslog_address)[1])
      tls_hostname = var.syslog_tls_hostname != "" ? var.syslog_tls_hostname : null
      use_tls      = var.syslog_tls_hostname != ""
      # %%{...} escapes Terraform's template directive so Fastly receives a literal %{...} log token.
      format         = "%h %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\" waf=%%{resp.http.X-NGWAF-Action}o"
      format_version = 2
    }
  }

}
