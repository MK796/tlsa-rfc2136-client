# tlsa-rfc2136-client

Interactive and automation-friendly TLSA record generator and RFC2136 publisher for DANE deployments.

Version documented in this file: **2.0.0**

This project is **Certbot-first**:

- default certificate scan path: `/etc/letsencrypt/live`
- workflow designed around typical Certbot live-directory layouts
- still supports arbitrary PEM / CRT / CER files and directories
- now includes modern packaging metadata and supporting files
- now includes a ready-to-use Certbot deploy-hook script

## What the tool does

The tool can:

- scan a certificate directory or single certificate file
- classify discovered certificate material into leaf / CA / bundle / fullchain
- validate the exact hostname against matching leaf certificates
- generate TLSA records from:
  - usage `0..3`
  - selector `0..1`
  - matching type `0..2`
- block impossible tuple selections based on the selected material
- run in:
  - **interactive** mode
  - **auto-sensible** mode
- publish TLSA records via RFC2136 using TSIG
- verify authoritative DNS after publication
- detect and attempt wrong-owner correction
- export final records in BIND format
- run optional live endpoint matching
- manage reusable RFC2136 profiles
- run optional warn-only DNSSEC / DANE sanity checks
- support fully unattended automation

## Version and repository files

This release expects these files to exist in the repository root:

```text
tlsa-rfc2136-client/
├── tlsa_rfc2136_interactive.py
├── certbot-deploy-hook-tlsa-rfc2136.sh
├── pyproject.toml
├── MANIFEST.in
├── PACKAGING.md
├── SECURITY.md
├── README.md
├── CHANGELOG.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

## Requirements

- Python 3.10+
- `cryptography`
- `dnspython`

## Download the repository

### Option 1: Clone with Git

```bash
git clone https://github.com/MK796/tlsa-rfc2136-client.git
cd tlsa-rfc2136-client
```

### Option 2: Download as ZIP

1. Open the repository on GitHub
2. Click **Code**
3. Click **Download ZIP**
4. Extract the archive
5. Change into the extracted directory

Example:

```bash
cd /path/to/tlsa-rfc2136-client
```

## Installation

### Install from a source checkout

```bash
python3 -m pip install .
```

### Upgrade

```bash
python3 -m pip install --upgrade .
```

### Editable install

```bash
python3 -m pip install --editable .
```

### Uninstall

```bash
python3 -m pip uninstall tlsa-rfc2136-client
```

See `PACKAGING.md` for build and distribution instructions.

## Package names and entrypoints

- package name: `tlsa-rfc2136-client`
- importable module: `tlsa_rfc2136_interactive`
- console commands:
  - `tlsa-rfc2136-client`
  - `tlsa-rfc2136`

You can also run the script directly:

```bash
python3 tlsa_rfc2136_interactive.py --help
```

## Important TLSA scope note

TLSA records apply to the **exact** service triplet:

- hostname
- port
- transport

Example:

```text
_5061._tcp.pbx.example.com.
```

That record applies only to:

- host `pbx.example.com`
- port `5061`
- transport `tcp`

It does **not** automatically apply to:

- `example.com`
- `mail.example.com`
- another port
- another transport

## Project tuple preference

Preferred order:

1. `3 1 2` — project default
2. `3 1 1` — alternative recommendation
3. `3 0 1` — additional sensible option

Important:

- this is a **project preference**
- it is **not** a protocol limitation

## Command-line flags

### Core workflow

- `--dry-run`
  - generate and validate locally
  - do not publish
  - do not query authoritative DNS

- `--validate-only`
  - skip publication
  - regenerate the expected TLSA set
  - compare it against authoritative DNS

- `--mode interactive`
  - manual single-plan workflow

- `--mode auto-sensible`
  - automatic sensible bulk workflow

### Input / selection

- `--config-file PATH`
  - path to the RFC2136 profile config JSON

- `--cert-path PATH`
  - file or directory to scan for PEM / CRT / CER material

- `--host NAME`
  - exact service hostname

- `--port NUMBER`
  - service port used to derive the TLSA owner name

- `--transport tcp|udp|sctp`
  - service transport used to derive the TLSA owner name

- `--ttl NUMBER`
  - TTL for the TLSA RRset

- `--profile NAME`
  - select a saved RFC2136 profile non-interactively

- `--tuples default|all`
  - valid only with `--mode auto-sensible`
  - `default` = publish only `3 1 2`
  - `all` = publish `3 1 2`, `3 1 1`, `3 0 1`

### Output / verification

- `--export-file PATH`
  - write documentation-only BIND output to a fixed file

- `--no-export`
  - skip export prompting

- `--live-check`
  - force the live TLS endpoint comparison

- `--no-live-check`
  - skip the live TLS endpoint comparison

- `--verbose`
  - enable verbose logging

### Sanity-check flags

- `--sanity-checks`
  - enable warn-only DNSSEC / DANE plausibility checks

- `--no-sanity`
  - disable all sanity checks

- `--sanity-live`
  - run an additional warn-only live TLSA-vs-live-certificate comparison
  - independent of `--live-check`

## Interactive workflow

### 1. Certificate path

If `--cert-path` is not supplied, the script prompts and defaults to:

```text
/etc/letsencrypt/live
```

### 2. Service input

The tool asks for:

- exact host
- service port
- transport
- TTL

It then derives the owner name:

```text
_<port>._<transport>.<host>.
```

### 3. Certificate discovery

The script scans the path and groups certificate material into:

- leaf certificates
- CA certificates
- bundles / fullchains

Only materials with a matching leaf certificate can be used for end-entity record generation.

### 4. Tuple selection

#### Interactive mode

The script:

- shows the TLSA capability mask
- lists all possible tuples
- lists recommended tuples
- prefers `3 1 2` when possible
- offers `3 1 1` as the alternative recommendation
- still lets you manually choose any valid tuple

#### Auto-sensible mode

The script:

- selects the best matching material by key family
- prefers wildcard certificates of the same key family when scanning a directory
- uses the explicitly given cert file directly when `--cert-path` points to a file
- prepares sensible DANE-EE record sets

## RFC2136 profile handling

The tool stores reusable RFC2136 / TSIG settings in a JSON config file.

Default location:

```text
~/.config/tlsa-rfc2136/config.json
```

Stored values typically include:

- profile name
- authoritative servers
- DNS port
- zone
- TSIG key name
- TSIG secret
- TSIG algorithm
- timeout
- default TTL
- verification attempts
- verification delay
- whether all configured servers should be updated

The profile flow supports:

- create
- use
- edit
- delete

## Publication and verification

### Publication

The script:

1. builds one or more TLSA plans
2. publishes them via RFC2136 using TSIG
3. reports per-server publication status

### Authoritative verification

After publication, the script:

- queries the configured authoritative servers directly
- compares the returned RRset against the generated plans
- reports:
  - `OK`
  - `MISMATCH`
  - `QUERY FAILED`

### Wrong-owner correction

The script contains logic to detect and attempt to correct the classic doubled-owner symptom.

### Validate-only mode

`--validate-only` lets you compare current authoritative DNS against the expected regenerated TLSA plan without publishing again.

## Sanity checks

Version 2.0.0 includes optional warn-only sanity checks.

They can warn about:

- owner-name mismatches
- tuple compatibility issues, such as SHA-512 without SHA-256 fallback
- PKIX usages `0` / `1` when DANE-only behavior may have been expected
- weak or missing DNSSEC signals for the configured zone
- optional live mismatch warnings

These checks are intended to improve operator awareness without changing the normal publish / validation flow.

## Live TLS endpoint comparison

The live check:

- opens a real TLS connection to the target service
- retrieves the currently presented certificate
- compares tuple-aware association data against the generated plans

### Important caveat

This convenience probe is **not** full PKIX validation. It is used to fetch the presented certificate for TLSA matching purposes.

## BIND export

At the end, the script can optionally export the generated TLSA RRset in BIND format.

Example:

```text
_5061._tcp.pbx.example.com. 3600 IN TLSA 3 1 2 <association-data>
```

This export is for documentation only.

## Main internal dataclasses

- `CertificateMaterial`
- `RFC2136Profile`
- `TLSARecordPlan`
- `SanityWarning`

## Main internal functions

### Discovery / selection

- `discover_certificate_materials()`
- `pick_end_entity_certificate()`
- `choose_discovered_material()`
- `choose_best_matching_materials_by_family()`

### TLSA planning

- `generate_tlsa_association()`
- `build_plan()`
- `run_interactive_mode()`
- `run_auto_sensible_mode()`
- `print_record_plan_summary()`

### Profile handling

- `load_saved_profiles()`
- `save_profiles()`
- `create_or_edit_profile()`
- `choose_or_manage_profile()`

### RFC2136 and verification

- `publish_tlsa_records()`
- `verify_publication()`
- `verify_plans_against_dns()`
- `try_fix_wrong_owner()`
- `delete_wrong_owner_if_present()`

### Live checks and warnings

- `validate_live_endpoint_against_plans()`
- `fetch_live_leaf_certificate()`
- `sanity_check_owner()`
- `sanity_check_tuple_plausibility()`
- `sanity_check_dnssec()`
- `sanity_check_live_warn_only()`

### Orchestration

- `main()`

## Certbot deploy-hook script

The repository now includes:

```text
certbot-deploy-hook-tlsa-rfc2136.sh
```

This script is meant for **deploy-hook / post-renewal automation**.

### Goals

It is designed to be:

- non-interactive
- retry-capable
- safe for logging
- protected against parallel execution via `flock`
- suitable for unattended renewals

### Certbot-provided environment

The script expects the usual Certbot deploy-hook environment, especially:

- `RENEWED_LINEAGE`
- `RENEWED_DOMAINS`

### Supported hook environment overrides

- `LOG_TAG`
- `LOG_FILE`
- `LOCK_FILE`
- `TLSA_CMD`
- `TLSA_CONFIG_FILE`
- `TLSA_PROFILE`
- `TLSA_PORT`
- `TLSA_TRANSPORT`
- `TLSA_TTL`
- `TLSA_MODE`
- `TLSA_TUPLES`
- `TLSA_LIVE_CHECK`
- `STRICT`
- `MAX_RETRIES`
- `BACKOFF_S`
- optional `TLSA_HOST`
- optional `TLSA_CERT_PATH`

### Install the hook

Example:

```bash
sudo install -m 0750 certbot-deploy-hook-tlsa-rfc2136.sh /etc/letsencrypt/renewal-hooks/deploy/
```

### Typical usage

The hook:

1. verifies that it is running inside a Certbot deploy-hook context
2. derives the host from `TLSA_HOST` or the first entry in `RENEWED_DOMAINS`
3. points certificate input to `RENEWED_LINEAGE`
4. runs `tlsa-rfc2136-client` non-interactively
5. retries on transient failure
6. can run an additional validate-only pass on exit code `2`
7. logs to file and syslog

### Example hook environment

```bash
export TLSA_CONFIG_FILE=/etc/tlsa-rfc2136/config.json
export TLSA_PROFILE=default
export TLSA_PORT=443
export TLSA_TRANSPORT=tcp
export TLSA_TTL=3600
export TLSA_MODE=auto-sensible
export TLSA_TUPLES=default
export TLSA_LIVE_CHECK=0
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

### Auto-sensible dry run

```bash
python3 tlsa_rfc2136_interactive.py --dry-run --mode auto-sensible
```

### Auto-sensible unattended dry run

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

### Fully unattended publish

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

### Publish with sanity checks

```bash
python3 tlsa_rfc2136_interactive.py \
  --mode auto-sensible \
  --tuples all \
  --config-file /root/.config/tlsa-rfc2136/config.json \
  --profile default \
  --cert-path /etc/letsencrypt/live/example.com \
  --host example.com \
  --port 443 \
  --transport tcp \
  --ttl 3600 \
  --sanity-checks \
  --sanity-live \
  --no-export \
  --no-live-check
```

### Validate-only against authoritative DNS

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

## Exit codes

- `0`
  - success

- `1`
  - runtime error

- `2`
  - publication or validation completed, but one or more verification checks still failed

- `130`
  - interrupted by user

## Related files

- `pyproject.toml`
  - packaging metadata and console entrypoints

- `MANIFEST.in`
  - source distribution file list

- `PACKAGING.md`
  - build / install / uninstall notes

- `SECURITY.md`
  - disclosure policy and operator guidance

- `certbot-deploy-hook-tlsa-rfc2136.sh`
  - optional Certbot deploy-hook automation script

## Notes

- the tool is optimized for Certbot live directories but not limited to Certbot
- the live certificate probe is convenience-oriented and not a substitute for strict PKIX validation
- authoritative DNS verification checks what is actually published, not only what was generated locally
