# tlsa-rfc2136-client

Interactive and automation-friendly TLSA record generator and RFC2136 publisher for DANE deployments.

This tool scans local certificate material, validates that a certificate matches the exact service hostname, generates TLSA records, publishes them to authoritative DNS servers with RFC2136 + TSIG, verifies the published result, and can optionally compare the live service certificate against the generated TLSA plan.

## Version

Current documented release: **1.1**

## What it does

- Scans a certificate directory or certificate file (`.pem`, `.crt`, `.cer`)
- Detects leaf certificates, CA certificates, and bundle/fullchain files
- Validates the exact service hostname against the matching certificate
- Supports all standard TLSA tuples:
  - usage: `0..3`
  - selector: `0..1`
  - matching type: `0..2`
- Prevents impossible tuple selections based on the available certificate material
- Recommends practical tuples such as `3 1 1`
- Supports an automatic sensible mode for common end-entity DANE records
- Publishes TLSA records via RFC2136 with TSIG authentication
- Verifies the authoritative DNS result after publication
- Detects and automatically tries to fix the classic wrong-owner RFC2136 symptom on some servers
- Can re-run validation without publishing again
- Can compare the live TLS endpoint against the generated TLSA plan
- Can export the final record set in BIND format for documentation only
- Stores reusable RFC2136 profiles and supports create, use, edit, and delete
- Supports non-interactive flags for automation

## Important TLSA scope note

TLSA records apply to the **exact service hostname, port, and transport**.

A TLSA record for:

```text
_5061._tcp.pbx.example.com.
```

applies only to:
- host: `pbx.example.com`
- port: `5061`
- transport: `tcp`

It does **not** automatically apply to:
- `example.com`
- `mail.example.com`
- `pbx.internal.example.com`
- any other port
- any other transport

If your service is on a subdomain, publish the TLSA record for that exact subdomain, not for the zone apex unless clients actually connect to the apex hostname.

## Requirements

- Python 3.10+
- `cryptography`
- `dnspython`

Install with pip:

```bash
python3 -m pip install -r requirements.txt
```

Or on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-cryptography python3-dnspython
```

## Repository layout

```text
tlsa-rfc2136-client/
├── tlsa_rfc2136_interactive.py
├── README.md
├── CHANGELOG.md
├── requirements.txt
├── .gitignore
└── tests/
    └── test_tlsa_rfc2136.py
```

## Supported command-line flags

### Core behavior

- `--dry-run`
  - Generate and validate locally only
  - Skips RFC2136 publication and authoritative DNS verification

- `--validate-only`
  - Skip RFC2136 publication
  - Regenerate the expected TLSA record set
  - Query authoritative DNS and validate what is already published

- `--mode interactive`
  - Manual workflow
  - Lets you choose the certificate material and TLSA tuple

- `--mode auto-sensible`
  - Automatic workflow
  - Generates a practical DANE-EE record set from matching leaf certificates
  - Sensible tuples currently used:
    - `3 1 1`
    - `3 1 2`
    - `3 0 1`

### Non-interactive input flags

- `--config-file PATH`
  - Path to the RFC2136 profile config file

- `--cert-path PATH`
  - Certificate directory or certificate file to scan

- `--host NAME`
  - Exact service hostname

- `--port NUMBER`
  - Service port for the TLSA owner name

- `--transport tcp|udp|sctp`
  - Transport for the TLSA owner name

- `--ttl NUMBER`
  - TTL for the TLSA RRset

- `--profile NAME`
  - Select a saved RFC2136 profile by name without prompting

### Output and verification flags

- `--export-file PATH`
  - Write documentation-only BIND output to the specified file without prompting

- `--no-export`
  - Skip the BIND export prompt entirely

- `--live-check`
  - Run the live TLS endpoint check without prompting

- `--no-live-check`
  - Skip the live TLS endpoint check entirely

- `--verbose`
  - Enable verbose logging

## Typical commands

Interactive dry run:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run
```

Interactive publish:

```bash
python3 tlsa_rfc2136_interactive.py --mode interactive
```

Auto-sensible dry run:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run --mode auto-sensible
```

Validation only against authoritative DNS:

```bash
python3 tlsa_rfc2136_interactive.py --validate-only --mode interactive
```

Automated dry run with all main parameters supplied:

```bash
python3 tlsa_rfc2136_interactive.py \
  --dry-run \
  --mode interactive \
  --cert-path /etc/letsencrypt/live/mk-homelab.net \
  --host pbx.mk-homelab.net \
  --port 5061 \
  --transport tcp \
  --ttl 3600 \
  --no-export \
  --no-live-check
```

Automated validation-only run using a saved profile:

```bash
python3 tlsa_rfc2136_interactive.py \
  --validate-only \
  --mode interactive \
  --config-file /root/.config/tlsa-rfc2136/config.json \
  --profile default \
  --cert-path /etc/letsencrypt/live/mk-homelab.net \
  --host pbx.mk-homelab.net \
  --port 5061 \
  --transport tcp \
  --ttl 3600 \
  --no-export \
  --live-check
```

## How the script works

### 1. Certificate discovery

The script scans the supplied certificate path and looks for PEM-style certificates. It groups discovered material into:
- leaf certificates
- CA certificates
- bundles/fullchains

Only materials that contain a leaf certificate matching the exact service hostname can be selected for end-entity TLSA generation.

### 2. Host validation

The hostname is validated against the certificate SAN entries and, if needed, the common name. Wildcards are supported for one label, such as `*.example.com` matching `pbx.example.com`.

### 3. TLSA planning

In interactive mode, the script:
- shows which TLSA tuples are possible
- blocks impossible combinations
- recommends common tuples

In auto-sensible mode, it generates a practical DANE-EE RRset automatically.

### 4. Local self-check

Before any DNS publication, the script verifies that the generated TLSA data matches the selected certificate material.

### 5. RFC2136 profile handling

The script stores reusable profiles for DNS updates. Profiles contain:
- nameserver list
- zone
- TSIG key name
- TSIG secret
- TSIG algorithm
- timeout
- default TTL
- verification retry settings

Profiles can be created, reused, edited, and deleted.

Default config file location:

```text
~/.config/tlsa-rfc2136/config.json
```

### 6. RFC2136 publication

When not using `--dry-run` or `--validate-only`, the script publishes the TLSA RRset using RFC2136 dynamic updates over TCP with TSIG authentication.

It sends owner names relative to the configured zone to avoid the doubled-owner problem seen on some DNS servers.

### 7. Authoritative verification

After publication, the script queries the configured authoritative servers directly and compares the returned TLSA RRset with the expected result.

If the classic wrong-owner symptom is detected, the script attempts to:
- delete the wrong owner
- republish the correct owner
- verify again

### 8. Live TLS endpoint validation

If enabled, the script opens a real TLS connection to the target service and regenerates tuple-aware TLSA associations from the live certificate. This is more accurate than simply comparing whole certificate fingerprints.

### 9. Documentation export

The BIND export is optional and for documentation only. It is not used for publication.

## TLSA recommendations

The script recommends these practical tuples when possible:

- `3 1 1`
  - Common default
  - End-entity cert
  - SPKI selector
  - SHA-256 matching

- `3 1 2`
  - Like `3 1 1`, but SHA-512

- `3 0 1`
  - Pins the whole leaf certificate instead of only the public key

- `2 1 1`
  - Useful when you intentionally want DANE-TA from a CA public key in the scanned bundle

## Profile management

The interactive profile menu supports:
- use a saved profile
- create a new profile
- edit a saved profile
- delete a saved profile

You can also skip the menu in automation with:

```bash
--profile PROFILE_NAME
```

## Testing

Syntax check:

```bash
python3 -m py_compile tlsa_rfc2136_interactive.py
```

Run unit tests:

```bash
python3 -m unittest discover -s tests -v
```

The included tests cover:
- wildcard hostname matching
- TLSA tuple generation logic
- RFC2136 owner-name handling

## Exit codes

- `0` = success
- `1` = general error
- `2` = publication and/or validation did not fully succeed
- `130` = interrupted by user

## Security notes

- TSIG secrets are hidden during input
- TSIG secrets are stored in the local config file if you save a profile
- The script validates TSIG secrets as Base64 at input time
- Keep the config file private
- Do not commit saved RFC2136 profile files to Git

## Known operational notes

- Live endpoint validation currently only applies to `tcp`
- `--validate-only` is ideal after waiting for propagation or after correcting records manually
- DNSSEC is still required for real DANE validation by clients
- The documentation export does not change publication behavior

## Example output

```text
_5061._tcp.pbx.mk-homelab.net. 3600 IN TLSA 3 1 1 <association-data>
```

## License

MIT License
