# tlsa-rfc2136-client

Interactive and automation-friendly TLSA record generator and RFC2136 publisher for DANE deployments.

This project is **Certbot-first** in version **1.3**:
- the default certificate scan path is **`/etc/letsencrypt/live`**
- the workflow is designed to work out of the box with typical **Certbot live-directory layouts**
- you can still override the path and use any PEM/CRT/CER file or directory

## Version

Current documented release: **1.3**

## What the tool does

The script:

- scans a certificate directory or certificate file (`.pem`, `.crt`, `.cer`)
- detects leaf certificates, CA certificates, and bundle/fullchain files
- validates the exact service hostname against the matching certificate
- supports all standard TLSA tuples:
  - usage: `0..3`
  - selector: `0..1`
  - matching type: `0..2`
- prevents impossible tuple selections based on the available certificate material
- supports **interactive mode** for manually choosing one TLSA tuple
- supports **auto-sensible mode** for generating sensible DANE-EE records:
  - when scanning a directory, prefers wildcard certificates over exact-match certificates of the same key family
  - when a cert file is given directly via `--cert-path`, uses that file without scanning the directory
  - with `--tuples`, the tuple selection is fully non-interactive
- publishes TLSA records via RFC2136 with TSIG authentication
- verifies the authoritative DNS result after publication
- detects and automatically tries to fix the classic wrong-owner RFC2136 symptom on supported workflows
- can re-run validation without publishing again
- can compare the live TLS endpoint against the generated TLSA plan
- can export the final record set in BIND format for documentation only
- stores reusable RFC2136 profiles and supports:
  - create
  - use
  - edit
  - delete
- supports fully non-interactive operation for Certbot post-renewal hooks and other automation

## Project default tuple preference

The project preference order is:

1. **`3 1 2`** — project default
2. **`3 1 1`** — alternative recommendation
3. **`3 0 1`** — additional sensible option

Important:
- this default is a **project choice**
- it is **not** a protocol limitation
- both `3 1 2` and `3 1 1` are supported equally by the tool

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
├── LICENSE
├── requirements.txt
├── .gitignore
└── tests/
    └── test_tlsa_rfc2136.py
```

## Supported command-line flags

Output from `python3 tlsa_rfc2136_interactive.py --help` is reflected here.

### Core behavior

- `-h`, `--help`
  - Show help and exit

- `--dry-run`
  - Generate and validate locally
  - Skip RFC2136 publication
  - Skip authoritative DNS verification

- `--validate-only`
  - Skip RFC2136 publication
  - Regenerate the expected TLSA record set
  - Query authoritative DNS and validate what is already published

- `--mode interactive`
  - Manual single-plan workflow
  - Lets you choose the certificate material and TLSA tuple

- `--mode auto-sensible`
  - Automatic bulk workflow
  - Selects matching leaf certificates by key family
  - Prefers wildcard certificates over exact-match certificates of the same key family when scanning a directory
  - When a cert file is given via `--cert-path`, uses that file directly
  - Unless `--tuples` is supplied, prompts you to publish:
    - only the project default tuple (`3 1 2`)
    - all sensible tuples (`3 1 2`, `3 1 1`, `3 0 1`)
    - or a custom subset of those sensible tuples

### Non-interactive input flags

- `--config-file PATH`
  - Path to the saved RFC2136 profile config file

- `--cert-path PATH`
  - Certificate directory or certificate file to scan
  - If you do not supply this, the interactive prompt defaults to:
    - `/etc/letsencrypt/live`

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

- `--tuples default|all`
  - Only valid with `--mode auto-sensible`
  - Selects the tuple set to publish without prompting
  - `default` — publish only `3 1 2`
  - `all` — publish `3 1 2`, `3 1 1`, and `3 0 1`
  - If omitted, the interactive tuple selection menu is shown

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

## Interactive workflow

### 1. Certificate path

If you do not provide `--cert-path`, the script prompts for a path and defaults to:

```text
/etc/letsencrypt/live
```

That makes the default workflow convenient for Certbot-managed systems.

### 2. Host / service input

The tool asks for:

- exact service host
- service port
- transport (`tcp`, `udp`, or `sctp`)
- TTL

It then builds the TLSA owner name in the usual form:

```text
_<port>._<transport>.<host>.
```

Example:

```text
_5061._tcp.pbx.example.com.
```

### 3. TLSA scope reminder

The script prints a reminder explaining that the generated TLSA owner name applies only to the exact service endpoint.

### 4. Certificate discovery

The script scans the supplied certificate path and looks for PEM-style certificates. It groups discovered material into:
- leaf certificates
- CA certificates
- bundles/fullchains

Only materials that contain a leaf certificate matching the exact service hostname can be selected for end-entity TLSA generation.

### 5. Tuple selection behavior

#### In interactive mode

The script:
- shows the TLSA capability mask for the selected material
- lists all standard tuples that are possible with that material
- lists recommended tuples
- defaults to **`3 1 2`** if possible
- offers **`3 1 1`** as the alternative recommendation
- still lets you manually choose any valid tuple supported by the material

#### In auto-sensible mode

The script:
- finds the best matching leaf material by key family
- when scanning a directory, prefers wildcard certificates (e.g. `*.example.com`) over exact-match host certificates of the same key family
- when a specific cert file is given via `--cert-path`, uses that file directly
- prints a summary of the automatically chosen certificate material
- unless `--tuples` is supplied, prompts you to choose what to publish:
  - **Default only**
    - publish only `3 1 2`
  - **All sensible tuples**
    - publish `3 1 2`, `3 1 1`, `3 0 1`
  - **Custom subset**
    - choose one or more of those tuples manually

This is especially useful in environments with multiple certificate families, such as RSA and ECDSA.

## RFC2136 profile handling

The tool stores reusable RFC2136 / TSIG settings in a JSON config file.

Default location:

```text
~/.config/tlsa-rfc2136/config.json
```

Typical stored values include:

- profile name
- authoritative DNS server list
- DNS port
- zone
- TSIG key name
- TSIG key secret
- TSIG algorithm
- timeout
- default TTL
- verification attempts / delay
- whether updates should be sent to all configured servers

The interactive profile menu supports:
- use a saved profile
- create a new profile
- edit a saved profile
- delete a saved profile

Because the file contains the TSIG secret, it should stay protected.

## Publication and verification

### RFC2136 publication

The script:
1. creates one or more TLSA plans
2. publishes the RRset via RFC2136 using TSIG
3. reports per-server update status

### Authoritative DNS verification

After publication, the script:
- directly queries the configured authoritative nameserver(s)
- compares the returned TLSA RRset against the generated plans
- reports:
  - `OK`
  - `MISMATCH`
  - `QUERY FAILED`

### Wrong-owner auto-correction

The script includes wrong-owner detection and recovery logic for the common doubled-owner problem, where a server may end up with something like:

```text
_5061._tcp.pbx.example.com.example.com
```

When the symptom is detected in supported workflows, the tool can:
- detect the wrong owner
- remove it
- republish the correct owner
- verify again

### Validate-only mode

`--validate-only` lets you:
- skip publication
- regenerate the expected TLSA plan(s)
- query authoritative DNS
- confirm whether the live authoritative data matches the expected data

This is useful after:
- propagation
- manual DNS changes
- scripted renewals
- troubleshooting

## Live TLS endpoint verification

The live check:
- opens a real TLS connection to the target host and port
- reads the currently presented server certificate
- compares the tuple-aware TLSA association of the live certificate with the generated plan(s)

This is stronger than only comparing whole certificate fingerprints and is useful for checking whether the running service really matches the generated TLSA data.

## Documentation export

At the end, the tool can write the generated TLSA RRset to a BIND-style text file.

Example line:

```text
_5061._tcp.pbx.example.com. 3600 IN TLSA 3 1 2 <association-data>
```

This export is:
- optional
- for documentation/reference
- not used by the script for publication

## Tests

The repository includes unit tests for core logic, including:
- wildcard hostname matching
- TLSA tuple handling
- RFC2136 owner-name handling

Run them with:

```bash
python3 -m unittest discover -s tests -v
```

## Example commands

### Interactive dry run

```bash
python3 tlsa_rfc2136_interactive.py --dry-run
```

### Interactive publish

```bash
python3 tlsa_rfc2136_interactive.py --mode interactive
```

### Auto-sensible dry run (interactive tuple selection)

```bash
python3 tlsa_rfc2136_interactive.py --dry-run --mode auto-sensible
```

### Auto-sensible dry run (unattended, project default tuple)

```bash
python3 tlsa_rfc2136_interactive.py \
  --dry-run \
  --mode auto-sensible \
  --tuples default \
  --cert-path /etc/letsencrypt/live/example.com \
  --host example.com \
  --port 443 \
  --transport tcp \
  --ttl 3600 \
  --no-export \
  --no-live-check
```

### Validation only against authoritative DNS

```bash
python3 tlsa_rfc2136_interactive.py --validate-only --mode interactive
```

### Fully unattended validation (Certbot post-renewal hook style)

```bash
python3 tlsa_rfc2136_interactive.py \
  --validate-only \
  --mode auto-sensible \
  --tuples default \
  --config-file /root/.config/tlsa-rfc2136/config.json \
  --profile default \
  --cert-path /etc/letsencrypt/live/example.com \
  --host example.com \
  --port 443 \
  --transport tcp \
  --ttl 3600 \
  --no-export \
  --no-live-check
```

### Fully unattended publish (Certbot post-renewal hook style)

```bash
python3 tlsa_rfc2136_interactive.py \
  --mode auto-sensible \
  --tuples default \
  --config-file /root/.config/tlsa-rfc2136/config.json \
  --profile default \
  --cert-path /etc/letsencrypt/live/example.com \
  --host example.com \
  --port 443 \
  --transport tcp \
  --ttl 3600 \
  --no-export \
  --no-live-check
```

### Verbose troubleshooting run

```bash
python3 tlsa_rfc2136_interactive.py --verbose
```

## Exit behavior

The script uses these exit codes:

- `0`
  - success

- `1`
  - general runtime error

- `2`
  - publication or validation completed, but one or more verification checks still failed

- `130`
  - interrupted by user (`Ctrl+C`)

## Notes

- The tool is optimized for **Certbot live directories**, but it is not limited to Certbot.
- Private key files that do not contain certificates are skipped automatically.
- Publication verification checks the authoritative DNS result, not just local generation.
- The `3 1 2` default preference is a **project preference**, not a DANE protocol requirement.
- When using `--mode auto-sensible` with `--tuples` and all other automation flags, the script runs with no interactive prompts.
