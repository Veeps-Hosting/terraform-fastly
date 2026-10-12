# WAF efficacy / bypass-rate test harness

Replays a corpus of **signature-shaped but benign** probes against a target and measures what fraction of attack
signatures a WAF layer **catches** vs **lets through**. Point it at the same application fronted different ways and
compare the catch rates:

| config | what it measures |
|---|---|
| `safeline`   | a semantic WAF (Signal-Sciences/SafeLine-class) — fingerprinted by body size |
| `fastly`     | Fastly Next-Gen WAF (what this module deploys) |
| `cloudflare` | Cloudflare WAF |
| `direct`     | origin only (no WAF) — how much the origin's own controls catch on their own |

The headline output is **"PASSED the WAF" = % of attack signatures that got through**, plus a **traffic-weighted**
version (weighted by a representative category distribution) and a **false-positive rate** on legitimate controls.

## Two-vantage comparison (the useful pattern)

Run the same corpus from two places to tell the WAF and the origin apart:

- **through the WAF** (from an external box): what the edge WAF blocks.
- **direct to the origin** (`--config direct`, `--resolve <vhost>:<origin-ip>` from a host the origin trusts): what
  the origin's own controls block on their own.

Diffing the two shows which origin controls are **redundant** (the WAF already blocks them) vs **non-redundant**
(they catch attacks the WAF passes). A key measured result: a semantic WAF blocks injection *payloads* but passes bare
attack *paths* (admin consoles, dotfiles, known-vuln script paths) that an origin **path denylist** catches — so an
origin path denylist is *not* duplicate, and must not be removed until the edge WAF's path rules are verified to cover
it.

## Safety — why this is a test, not an attack

- **Nothing exploits anything.** Payloads are *detection signatures* against benign/non-existent paths; network sinks
  are RFC-invalid (`*.invalid`) or link-local; command/code-injection use harmless tokens. Every request carries an
  `X-WAF-Test: <runid>` header + a `wafqa=<runid>` marker so the traffic is identifiable and excludable.
- **DoS-safe by design.** Sequential, concurrency 1, default **0.25 req/s (4s spacing)**, with a hard **`--max-rate`
  guard that refuses to run faster** — it cannot be turned into a flood. A full run is a few minutes. This is a
  *correctness* test, not a load/DoS test.
- **Dry-run by default.** Prints the plan and sends nothing until `--run`. Point it at temp/staging URLs.

## Usage

```bash
# dry-run plan (no traffic)
./waf_efficacy_test.py --target https://trial.example.com --config fastly

# through the WAF
./waf_efficacy_test.py --target https://trial.example.com --config fastly --run

# direct to the origin (trusted source IP), behind basic_auth:
WAFQA_AUTH='user:pass' ./waf_efficacy_test.py --target https://origin.example.com \
    --host origin.example.com --resolve origin.example.com:<ORIGIN-IP> --config direct --insecure --run

# compare result files
./waf_efficacy_test.py --compare out/*.json
```

Flags: `--rate` / `--max-rate` (DoS-safety), `--jitter`, `--auth user:pass` (or `WAFQA_AUTH` env to keep it off the
command line), `--header 'Name: Value'` (repeatable), `--categories`, `--insecure`, `--runid`, `--out`, `--compare`.
`run_all.sh` + `targets.conf` run all configured front-ends in sequence and print the comparison.

## How "blocked vs passed" is decided

Status code alone is ambiguous (a WAF-403 and an origin-403 look identical), so classification uses **status + body
size + fingerprint headers** per front-end (e.g. a SafeLine deny is `403` with a ~16 KB body; a Fastly NGWAF block is
`406`; an origin nginx deny is `403` with a small body; `401` is an origin basic_auth gate). The raw `status`,
`body_len`, and `blocker` are stored for every probe in the JSON/CSV so verdicts can be re-derived without re-running.
Always confirm the fingerprint against the shipped control probes first.

## Files
- `waf_efficacy_test.py` — the harness (stdlib only; runs anywhere with python3).
- `corpus.json` — the benign probe corpus (categories weighted to a representative distribution).
- `run_all.sh` / `targets.conf.example` — run all front-ends and compare.
- `out/` — per-run results (created on first `--run`).
