# Security Policy

## Supported versions

Guard is pre-1.0. Only the latest release and `main` receive security fixes.

## Reporting a vulnerability

**Do not open a public issue.**

- Preferred: GitHub private vulnerability reporting — *Security → Report a vulnerability* on https://github.com/bakhod1r/guard.
- Include: affected version/commit, component (`identity`, `session`, `access`, `apikey`, `ratelimit`, `ginguard`, `adminui`, `kernel/migrations`), reproduction steps or PoC, impact, and any suggested fix.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage and severity (CVSS v3.1) | 7 days |
| Fix for Critical/High | 30 days |
| Fix for Medium/Low | next release |

We coordinate disclosure with the reporter, publish a GitHub Security Advisory (and request a CVE / Go vulnerability database entry when applicable), and credit reporters who wish to be named.

## Scope

In scope: authentication/authorization bypass, session or API key disclosure, CSRF/XSS in the admin panel, SQL injection, rate-limit bypass in Guard code, unsafe defaults.

Out of scope: vulnerabilities requiring a misconfiguration explicitly documented as unsafe (e.g. `InsecureCookie: true` in production, untrusted proxy headers — see `docs/production.md`), findings in `examples/` credentials meant for local use, and denial of service by volumetric traffic.

## Safe harbor

Good-faith research that avoids privacy violations, data destruction and service disruption, and that follows this policy, will not be pursued legally.
