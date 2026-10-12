#!/usr/bin/env python3
"""
waf_efficacy_test.py  -  WAF efficacy / bypass-rate harness.

Replays a corpus of SIGNATURE-SHAPED BUT BENIGN probes (see corpus.json) against a
target and measures what the WAF layer catches vs. lets through. Point it at the same
site fronted different ways (SafeLine / direct-to-origin / Cloudflare / Fastly / temp
URL) and compare the catch rates.

This is a TEST tool, not an attack tool:
  * payloads are detection signatures against benign/non-existent paths,
  * network sinks are RFC-invalid (.invalid) and do not resolve,
  * every request carries an X-WAF-Test header + a wafqa=<runid> marker so the team
    can identify and exclude the traffic,
  * it is sequential and rate-limited (no flooding), and
  * it does nothing until you pass --run (default is a dry-run plan).

Stdlib only; runs anywhere with python3 (incl. a jump box). No pip.

Examples
--------
  # see the plan without sending anything
  ./waf_efficacy_test.py --target https://trial.example.com --config safeline

  # run against SafeLine-fronted temp URL
  ./waf_efficacy_test.py --target https://trial.example.com --config safeline --run

  # run against the origin directly (pin Host header + connect IP, skip cert check)
  ./waf_efficacy_test.py --target https://origin.example.com --host origin.example.com \
      --resolve origin.example.com:203.0.113.10 --config direct --insecure --run

  # behind a Cloudflare / Fastly trial, same corpus
  ./waf_efficacy_test.py --target https://cf-trial.example.com --config cloudflare --run
  ./waf_efficacy_test.py --target https://fastly-trial.example.com --config fastly --run

  # compare results side by side
  ./waf_efficacy_test.py --compare out/*.json
"""
import argparse, csv, glob, http.client, json, os, random, socket, ssl, sys, time
from collections import defaultdict
from urllib.parse import quote, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Block-fingerprints per front-end. Each returns (verdict, blocker) where
#   verdict in {BLOCKED, CHALLENGED, PASSED}
#   blocker in {waf, origin, none}
# "PASSED" for an attack probe == the signature reached the origin app (a miss).
# Raw status / body_len / headers are always stored so you can re-classify later.
# ---------------------------------------------------------------------------
def _h(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return ""

def classify(config, status, headers, body_len, body_snippet):
    sc = status or 0
    server = _h(headers, "server").lower()
    cfray = _h(headers, "cf-ray")
    cfmit = _h(headers, "cf-mitigated").lower()
    via = _h(headers, "via").lower()
    xsb = _h(headers, "x-served-by").lower()
    sigsci = any(k.lower().startswith("x-sigsci") for k, _ in headers)
    setck = _h(headers, "set-cookie").lower()
    bl = (body_snippet or "").lower()

    if config == "safeline":
        # SafeLine deny = 403 ~16512 bytes (+sl-session); challenge = 468 ~17982.
        if sc == 468 or (body_len and 17000 < body_len < 19000):
            return "CHALLENGED", "waf"
        if sc == 403 and (body_len or 0) > 8000:
            return "BLOCKED", "waf"
        if "sl-session" in setck and sc in (403, 406):
            return "BLOCKED", "waf"
        if sc in (403, 444, 406, 429):          # small body -> origin nginx rule
            return "BLOCKED", "origin"
        if sc == 401:                           # origin basic_auth gate (passed through the WAF)
            return "BLOCKED", "origin"
        return "PASSED", "none"

    if config == "cloudflare":
        cf = bool(cfray) or "cloudflare" in server
        blocky = ("attention required" in bl or "error code: 1020" in bl
                  or "sorry, you have been blocked" in bl or "ray id" in bl)
        if cf and (cfmit == "challenge" or sc in (503, 429) or "managed_challenge" in bl
                   or "just a moment" in bl):
            return "CHALLENGED", "waf"
        if cf and (sc in (403, 401, 406) or blocky):
            return "BLOCKED", "waf"
        if sc in (403, 406, 429, 444):
            return "BLOCKED", "origin"
        return "PASSED", "none"

    if config == "fastly":
        fastly = "fastly" in xsb or "fastly" in via or "varnish" in via or sigsci
        blocky = ("request blocked" in bl or "blocked by" in bl or sigsci
                  or "varnish cache server" in bl)
        if fastly and (sc in (406, 403) or blocky):   # NGWAF/SigSci default 406
            return "BLOCKED", "waf"
        if sc in (403, 406, 429, 444):
            return "BLOCKED", "origin"
        return "PASSED", "none"

    if config == "direct":
        # No WAF in front: anything blocked here is the origin's own protections.
        # 401 = basic_auth gate; 403/444/406/429 = the origin nginx/Lucee rules (the ones we're assessing).
        if sc in (401, 403, 444, 406, 429):
            return "BLOCKED", "origin"
        return "PASSED", "none"

    # generic / unknown front-end
    if sc == 468 or (body_len and 17000 < body_len < 19000):
        return "CHALLENGED", "waf"
    if sc in (403, 406, 429, 444, 503, 401):
        return "BLOCKED", "waf"
    return "PASSED", "none"


# ---------------------------------------------------------------------------
# Request sender  -  raw socket so we control connect-IP vs SNI vs Host, and so
# already-encoded attack paths/queries are sent literally (no double-encoding).
# ---------------------------------------------------------------------------
def build_query(probe, runid):
    parts = []
    if "raw_query" in probe:
        parts.append(probe["raw_query"])
    for k, v in (probe.get("query") or {}).items():
        parts.append("%s=%s" % (quote(str(k), safe=""), quote(str(v), safe="")))
    parts.append("wafqa=" + runid)                      # benign test marker
    return "&".join(p for p in parts if p)

def send(probe, base, host, connect_ip, runid, timeout, insecure, extra_headers=None):
    scheme = base.scheme
    port = base.port or (443 if scheme == "https" else 80)
    connect_to = connect_ip or host
    path = probe["path"]
    q = build_query(probe, runid)
    full = path + ("?" + q if q else "")
    method = probe.get("method", "GET").upper()

    headers = {
        "Host": host,
        "User-Agent": "WAF-Efficacy-Test/1.0",
        "Accept": "*/*",
        "X-WAF-Test": runid,
        "Connection": "close",
    }
    headers.update(extra_headers or {})                 # global --auth / --header (e.g. basic auth to get past 401)
    headers.update(probe.get("headers") or {})          # probe may set a malicious-looking UA etc. (overrides globals)
    body = probe.get("body")
    body_bytes = body.encode("utf-8", "replace") if isinstance(body, str) else (body or b"")
    if body_bytes:
        headers["Content-Type"] = probe.get("content_type", "application/x-www-form-urlencoded")
        headers["Content-Length"] = str(len(body_bytes))

    req = ["%s %s HTTP/1.1" % (method, full)]
    for k, v in headers.items():
        req.append("%s: %s" % (k, v))
    raw = ("\r\n".join(req) + "\r\n\r\n").encode("latin-1", "replace") + body_bytes

    t0 = time.time()
    sock = socket.create_connection((connect_to, port), timeout=timeout)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw)
        resp = http.client.HTTPResponse(sock, method=method)
        resp.begin()
        hdrs = resp.getheaders()
        data = resp.read(65536)
        status = resp.status
    finally:
        try: sock.close()
        except Exception: pass
    elapsed = round((time.time() - t0) * 1000)
    body_len = int(_h(hdrs, "content-length") or len(data))
    return status, hdrs, body_len, data[:400].decode("latin-1", "replace"), elapsed


# ---------------------------------------------------------------------------
def load_corpus(path, cats):
    with open(path) as f:
        data = json.load(f)
    probes = data["probes"]
    if cats:
        want = set(c.strip() for c in cats.split(","))
        probes = [p for p in probes if p["category"] in want or p["category"] == "control"]
    return probes

def run(args):
    base = urlsplit(args.target)
    host = args.host or base.hostname
    connect_ip = None
    if args.resolve:
        rhost, _, rip = args.resolve.partition(":")
        connect_ip = rip or None
    probes = load_corpus(args.corpus, args.categories)
    runid = args.runid or ("wafqa-%d" % int(time.time()))
    attacks = [p for p in probes if p["expect"] == "block"]
    controls = [p for p in probes if p["expect"] == "pass"]

    # --- DoS-safety guard: this tool must never be turnable into a flood ---
    if args.rate > args.max_rate:
        print("REFUSING: --rate %.2f exceeds --max-rate %.2f (DoS-safety guard). Lower --rate, or raise --max-rate "
              "deliberately only if you know the target's thresholds." % (args.rate, args.max_rate))
        return

    # --- global headers: basic auth (from --auth or env WAFQA_AUTH) + any --header ---
    extra_headers = {}
    auth = args.auth or os.environ.get("WAFQA_AUTH")
    if auth and ":" in auth:
        import base64
        extra_headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    for h in (args.headers or []):
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    interval = 1.0 / args.rate if args.rate > 0 else 0
    est_secs = int(len(probes) * (interval + args.jitter / 2.0))
    print("# WAF efficacy test")
    print("#   target     : %s" % args.target)
    print("#   host hdr   : %s%s" % (host, (" (connect %s)" % connect_ip) if connect_ip else ""))
    print("#   config     : %s" % args.config)
    print("#   runid      : %s   (marker: header X-WAF-Test + query wafqa=%s)" % (runid, runid))
    print("#   probes     : %d attack + %d control" % (len(attacks), len(controls)))
    print("#   pacing     : ~%.2f req/s (<= %.2f max), concurrency 1, ~%ds total  [DoS-safe: well under flood thresholds]"
          % (args.rate, args.max_rate, est_secs))
    if "Authorization" in extra_headers:
        print("#   auth       : HTTP basic auth ON (to measure protections behind a 401 gate)")
    if not args.run:
        print("\nDRY-RUN (no requests sent). Plan:")
        for p in probes:
            print("  [%-14s] %-6s %s%s" % (p["category"], p.get("method", "GET"),
                  p["path"], (" ?" + build_query(p, runid)) if (p.get("query") or p.get("raw_query")) else ""))
        print("\nRe-run with --run to send. Each request is benign and marked; see README.md.")
        return

    results = []
    for i, p in enumerate(probes):
        try:
            status, hdrs, blen, snip, ms = send(p, base, host, connect_ip, runid,
                                                 args.timeout, args.insecure, extra_headers)
            verdict, blocker = classify(args.config, status, hdrs, blen, snip)
            err = ""
        except Exception as e:
            status, blen, ms, verdict, blocker, err = 0, 0, 0, "ERROR", "none", str(e)[:120]
        row = {"id": p["id"], "category": p["category"], "expect": p["expect"],
               "weight": p.get("weight", 0), "method": p.get("method", "GET"),
               "path": p["path"], "status": status, "body_len": blen, "ms": ms,
               "verdict": verdict, "blocker": blocker, "error": err}
        results.append(row)
        mark = {"BLOCKED": "block", "CHALLENGED": "chlng", "PASSED": "PASS ", "ERROR": "err  "}[verdict]
        flag = ""
        if p["expect"] == "block" and verdict == "PASSED": flag = "  <-- reached origin"
        if p["expect"] == "pass" and verdict in ("BLOCKED", "CHALLENGED"): flag = "  <-- FALSE POSITIVE"
        print("  %-14s %-6s %-40.40s  %3s %6sb  %-5s %-6s%s" %
              (p["category"], row["method"], p["path"], status, blen, mark, blocker, flag))
        if interval and i < len(probes) - 1:
            time.sleep(interval + random.uniform(0, args.jitter))

    summarize(args, runid, results)
    write_out(args, runid, results)

def summarize(args, runid, results):
    atk = [r for r in results if r["expect"] == "block" and r["verdict"] != "ERROR"]
    ctl = [r for r in results if r["expect"] == "pass" and r["verdict"] != "ERROR"]
    errs = [r for r in results if r["verdict"] == "ERROR"]
    by = defaultdict(lambda: {"n": 0, "blocked": 0, "passed": 0, "reached_origin": 0, "weight": 0})
    for r in atk:
        c = by[r["category"]]
        c["n"] += 1
        c["weight"] = r["weight"]
        if r["verdict"] in ("BLOCKED", "CHALLENGED"):
            c["blocked"] += 1
            if r["blocker"] == "origin":
                c["reached_origin"] += 1   # WAF passed it; origin caught it
        else:
            c["passed"] += 1
            c["reached_origin"] += 1

    print("\n=== %s / config=%s ===" % (runid, args.config))
    print("%-16s %4s %7s %8s %12s" % ("category", "n", "caught", "passed", "reached_orig"))
    tw = tpw = 0.0
    for cat in sorted(by):
        c = by[cat]
        cr = c["blocked"] / c["n"] if c["n"] else 0
        print("%-16s %4d %6.0f%% %7.0f%% %12d" % (cat, c["n"], cr * 100,
              (c["passed"] / c["n"] * 100) if c["n"] else 0, c["reached_origin"]))
        tw += c["weight"]
        tpw += c["weight"] * (c["passed"] / c["n"] if c["n"] else 0)
    n = len(atk)
    caught = sum(1 for r in atk if r["verdict"] in ("BLOCKED", "CHALLENGED"))
    passed = n - caught
    reached = sum(1 for r in atk if r["verdict"] == "PASSED" or r["blocker"] == "origin")
    fp = sum(1 for r in ctl if r["verdict"] in ("BLOCKED", "CHALLENGED"))
    print("-" * 52)
    print("attack probes      : %d" % n)
    print("caught by layer    : %d  (%.1f%%)" % (caught, caught / n * 100 if n else 0))
    print("PASSED the WAF     : %d  (%.1f%%)   <-- headline bypass rate" %
          (passed, passed / n * 100 if n else 0))
    print("reached the origin : %d  (%.1f%%)  (passed + origin-caught)" %
          (reached, reached / n * 100 if n else 0))
    if tw:
        print("traffic-weighted bypass (by observed 30d volume): %.1f%%" % (tpw / tw * 100))
    print("control probes     : %d   false positives: %d  (%.1f%%)" %
          (len(ctl), fp, fp / len(ctl) * 100 if ctl else 0))
    if errs:
        print("errors             : %d  (e.g. %s)" % (len(errs), errs[0]["error"]))

def write_out(args, runid, results):
    os.makedirs(args.out, exist_ok=True)
    stem = os.path.join(args.out, "%s_%s" % (runid, args.config))
    meta = {"runid": runid, "config": args.config, "target": args.target,
            "host": args.host or urlsplit(args.target).hostname, "ts": int(time.time())}
    with open(stem + ".json", "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=2)
    with open(stem + ".csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader(); w.writerows(results)
    print("\nwrote %s.json / .csv" % stem)

def compare(paths):
    files = []
    for pat in paths:
        files.extend(sorted(glob.glob(pat)))
    runs = []
    for fp in files:
        with open(fp) as f:
            d = json.load(f)
        runs.append((d["meta"]["config"], d["results"], fp))
    cats = sorted({r["category"] for _, res, _ in runs for r in res if r["expect"] == "block"})
    print("%-16s %s" % ("category", "  ".join("%-10s" % c for c, _, _ in runs)))
    for cat in cats:
        cells = []
        for _, res, _ in runs:
            rs = [r for r in res if r["category"] == cat and r["expect"] == "block" and r["verdict"] != "ERROR"]
            if rs:
                cr = sum(1 for r in rs if r["verdict"] in ("BLOCKED", "CHALLENGED")) / len(rs)
                cells.append("%-10s" % ("%.0f%% caught" % (cr * 100)))
            else:
                cells.append("%-10s" % "-")
        print("%-16s %s" % (cat, "  ".join(cells)))
    print("\noverall PASSED-the-WAF (bypass rate):")
    for cfg, res, fp in runs:
        atk = [r for r in res if r["expect"] == "block" and r["verdict"] != "ERROR"]
        ctl = [r for r in res if r["expect"] == "pass" and r["verdict"] != "ERROR"]
        passed = sum(1 for r in atk if r["verdict"] == "PASSED")
        fpos = sum(1 for r in ctl if r["verdict"] in ("BLOCKED", "CHALLENGED"))
        print("  %-10s  %.1f%% bypass  (%d/%d)   false-pos %d/%d   [%s]" %
              (cfg, passed / len(atk) * 100 if atk else 0, passed, len(atk),
               fpos, len(ctl), os.path.basename(fp)))

def main():
    ap = argparse.ArgumentParser(description="WAF efficacy / bypass-rate test harness")
    ap.add_argument("--target", help="base URL, e.g. https://trial.example.com")
    ap.add_argument("--host", help="Host header / SNI to send (defaults to target host)")
    ap.add_argument("--resolve", help="host:ip  -  connect to this IP but send --host (like curl --resolve)")
    ap.add_argument("--config", default="auto",
                    choices=["safeline", "cloudflare", "fastly", "direct", "auto"],
                    help="front-end being tested (selects the block fingerprint)")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.json"))
    ap.add_argument("--categories", help="comma list to restrict (controls always included)")
    ap.add_argument("--rate", type=float, default=0.25, help="requests/sec (default 0.25 = 4s spacing; stays under the SafeLine 429/anti-DDoS traps). Sequential, concurrency 1.")
    ap.add_argument("--max-rate", type=float, default=0.5, dest="max_rate", help="HARD guard: refuse to run above this req/s so the tool can never be turned into a flood. Raise deliberately only if you know the target's thresholds.")
    ap.add_argument("--jitter", type=float, default=0.7, help="extra random 0..J seconds between requests")
    ap.add_argument("--auth", help="HTTP basic auth 'user:pass' sent on every request (or set env WAFQA_AUTH to keep it off the command line)")
    ap.add_argument("--header", action="append", default=[], dest="headers", help="extra 'Name: Value' header on every request (repeatable)")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--insecure", action="store_true", help="skip TLS cert verification (temp/staging certs)")
    ap.add_argument("--runid", help="label for this run (default wafqa-<epoch>)")
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    ap.add_argument("--run", action="store_true", help="actually send (default is dry-run plan)")
    ap.add_argument("--compare", nargs="+", help="compare N result .json files, then exit")
    a = ap.parse_args()
    if a.compare:
        compare(a.compare); return
    if not a.target:
        ap.error("--target is required (or use --compare)")
    run(a)

if __name__ == "__main__":
    main()
