# terraform-fastly

Reusable Terraform modules for Fastly, driven by Terragrunt. Companion to
[`terraform-cloudflare`](https://github.com/Veeps-Hosting/terraform-cloudflare); same conventions (S3 backend via
`root.hcl`, per-leaf token from the environment, `manage_*` feature switches, secure baseline in `locals.tf`,
deployment-specific values in the private leaf only).

| Module | Purpose |
|---|---|
| [`service`](service/) | One application's Fastly CDN delivery service **and** native Next-Gen WAF (workspace): origin, TLS, health check, real-client-IP + origin-lockdown, cache, and a WAF posture that blocks attacks inline while staying safe for a dynamic CMS/web app. |

| Script | Purpose |
|---|---|
| [`scripts/tg-fastly`](scripts/tg-fastly) | `terragrunt` passthrough; forces HTTPS egress onto IPv4 when the `FASTLY_API_KEY` is IP-allowlisted. |
| [`scripts/waf_efficacy_check.sh`](scripts/waf_efficacy_check.sh) | Post-apply gate: runs a benign attack-pattern replay against the trial URL and fails if the bypass rate exceeds your baseline or any legitimate control request is blocked. |

One provider, one credential: `fastly/fastly ~> 9.8` reads `FASTLY_API_KEY` from the environment (set per-leaf via
Terragrunt `extra_arguments` env_vars; never on disk). The native NGWAF **workspace** model means the CDN service and
the WAF are the same provider — no separate Signal Sciences corp/credential.

Requires OpenTofu >= 1.12.0 and provider `fastly/fastly ~> 9.8`. Pin a tag in leaves: `//service?ref=0.1`.

## Documentation

| Doc | What it covers |
|---|---|
| [`service/README.md`](service/README.md) | The module contract: every `manage_*` switch, the inline-blocking rationale, the scoped CMS exclusion, usage, apply-time verify. |
| [`docs/architecture.md`](docs/architecture.md) | Component model, request-judgement order, module files, state/Terragrunt. |
| [`docs/security-posture.md`](docs/security-posture.md) | Threat model, per-category coverage, defence-in-depth layers, what is explicitly NOT covered, residual risks. |
| [`docs/operations.md`](docs/operations.md) | Staged rollout runbook (log → grade → block → ramp), cutover, rollback, troubleshooting. |
| [`docs/origin-wiring.md`](docs/origin-wiring.md) | Origin web-server requirements: trust the CDN, restore the real client IP, enforce the shared-secret gate, retire duplicate controls. |
| [`docs/virtual-patches-assessment.md`](docs/virtual-patches-assessment.md) | How Fastly NGWAF virtual patches work + a tiered CVE recommendation for a JVM/ColdFusion origin. |
| [`docs/variables.md`](docs/variables.md) | Full input reference (generated from `service/variables.tf`). |
| [`examples/trial.hcl`](examples/trial.hcl) | A sanitized Terragrunt leaf for a staging trial. |
