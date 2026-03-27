# Security Policy

## Supported Versions

This project currently supports the latest released minor version of the current major series.

| Version | Supported |
|---------|-----------|
| 1.3.x   | ✅ Yes    |
| < 1.3   | ❌ No     |

## Reporting a Vulnerability

Please report security issues responsibly and **do not** open a public GitHub issue with exploit details.

Preferred reporting channel (private):
1. Use GitHub Security Advisories / "Report a vulnerability" (if enabled for this repository).

Fallback (if private reporting is not available):
1. Open a GitHub issue with **minimal details** (high-level description only) and ask maintainers to provide a private channel.
2. Alternatively, contact the repository owner via their GitHub profile.

If you are a maintainer of this project, you should add a dedicated security contact address (e.g. security@your-domain) here.

## What to Include

- Affected version(s)
- Steps to reproduce (ideally minimal PoC)
- Impact assessment (confidentiality/integrity/availability)
- Any logs or stack traces that help triage
- Whether the issue is exploitable remotely and under what conditions

## Response Targets

Best-effort targets:
- Acknowledge within 72 hours
- Provide a status update within 7 days
- Provide a fix or mitigation plan as soon as practical

## Coordinated Disclosure

We prefer coordinated disclosure. Please allow a reasonable period for a fix before publishing details.

## CVE / GHSA Policy

- For high-impact vulnerabilities, maintainers may request a CVE.
- For moderate/low issues, a GitHub Security Advisory (GHSA) may be used instead.
- The project may publish release notes describing security fixes without disclosing exploit details.

## Operator Security Recommendations

### TSIG secrets and config files
- The RFC2136/TSIG profile config contains the TSIG secret (base64). Store it with restrictive permissions (0600) and root ownership where applicable.
- Never commit TSIG secrets to Git.
- Prefer dedicated least-privilege TSIG keys limited to the minimal zone and RR types required.

### Running in automation (Certbot hooks)
- Run the tool non-interactively using a pre-created config file and a fixed profile name.
- Avoid passing secrets via command line arguments (they can leak via process lists, audit logs, etc.).

### DNSSEC / DANE considerations
- DANE TLSA security relies on DNSSEC. Ensure your zone is DNSSEC-signed and that clients validate DNSSEC.
- Be careful with TTL and rollout timing during certificate/key rotations.

### Live TLS probe caveats
- Any optional live TLS probing used for convenience should not be mistaken for full PKIX validation unless explicitly implemented.
- Use short timeouts and treat probe failures as warnings unless your operational policy requires strict validation.
