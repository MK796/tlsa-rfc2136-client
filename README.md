# TLSA RFC2136 Interactive

Interactive Python tool to generate TLSA records from PEM certificate material, optionally publish them via RFC2136 dynamic DNS updates, verify publication against authoritative nameservers, optionally correct a common wrong-owner publication mistake, and optionally export BIND-format record lines for documentation.

## What it does

- Scans a certificate directory or a single PEM/CRT/CER file.
- Detects leaf certificates, CA certificates, key types, and whether a file looks like a fullchain bundle.
- Validates the entered hostname against the matching leaf certificate.
- Generates valid TLSA record data for standard TLSA tuples.
- Prevents impossible tuple combinations for the selected certificate material.
- Recommends sensible tuples such as `3 1 1`.
- Can publish the record set via RFC2136 using TSIG.
- Sends RFC2136 owner names **relative to the selected zone**, which avoids accidental doubled names such as `_5061._tcp.host.example.com.example.com`.
- Verifies the published record set directly against the configured authoritative DNS servers.
- Detects the common “zone suffix appended twice” / wrong-owner publication symptom and can automatically correct it during publish mode.
- Can optionally run in validation-only mode so you can re-check authoritative DNS later without publishing again.
- Can optionally compare the live certificate currently presented by the service to the certificate used for TLSA generation.
- Can save and reuse RFC2136/TSIG profiles.
- Can optionally write BIND-format record lines to a text file for documentation.

## Supported start flags

The current script exposes these CLI flags:

### `--dry-run`
Generate and validate everything locally, but do **not** publish via RFC2136 and do **not** query authoritative DNS for publication verification.

Example:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run
```

### `--validate-only`
Skip RFC2136 publication and only validate the generated TLSA record set against the configured authoritative DNS servers.

Use this when:

- you already published the record earlier
- you want to re-check propagation or correctness later
- you want to run the optional live TLS probe again without sending another update

Example:

```bash
python3 tlsa_rfc2136_interactive.py --validate-only
```

### `--mode interactive`
Manual mode. You choose a single certificate material and a single valid TLSA tuple.

This is the default.

Example:

```bash
python3 tlsa_rfc2136_interactive.py --mode interactive
```

### `--mode auto-sensible`
Automatic mode. The script looks for matching leaf certificates by key family and generates a curated, sensible DANE-EE RRset for them.

At the moment, this mode tries to generate these tuples when possible:

- `3 1 1`
- `3 1 2`
- `3 0 1`

Example:

```bash
python3 tlsa_rfc2136_interactive.py --mode auto-sensible
```

### Combined examples

Dry-run with manual selection:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run --mode interactive
```

Dry-run with automatic sensible RRset generation:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run --mode auto-sensible
```

Validation-only with automatic sensible RRset generation:

```bash
python3 tlsa_rfc2136_interactive.py --validate-only --mode auto-sensible
```

## How the script works

## 1. Reads certificate material

At startup, the script asks for:

- the config file path
- a certificate directory or certificate file
- the exact service hostname
- service port
- transport protocol
- TTL

It then scans the provided path for `*.pem`, `*.crt`, and `*.cer` files and extracts PEM certificates from them.

## 2. Detects available certificate material

For each discovered file, it determines:

- whether it contains a leaf certificate
- whether it contains CA certificates
- whether it looks like a fullchain/bundle
- key type, for example RSA or ECDSA
- DNS names found in SAN/CN

## 3. Validates the hostname

The entered hostname must match at least one discovered **leaf** certificate. If not, the script reprompts.

## 4. Builds the TLSA owner name

The owner name is built as:

```text
_<port>._<transport>.<hostname>
```

Example:

```text
_5061._tcp.pbx.example.com.
```

## Important scope note

TLSA records apply only to the exact combination of:

- hostname
- port
- transport

That means:

- `_5061._tcp.example.com.` applies to a service on `example.com:5061/tcp`
- it does **not** automatically apply to `pbx.example.com`
- it also does **not** apply to other ports on the same host

So if your service actually runs on `pbx.example.com`, publish the TLSA record for `pbx.example.com`, not for the zone apex `example.com`.

## 5. Chooses TLSA settings

In `interactive` mode, the script:

- shows the available TLSA option mask
- shows which tuples are possible for the selected material
- blocks impossible combinations
- recommends sensible combinations
- lets you choose one tuple

In `auto-sensible` mode, the script:

- looks for matching leaf certificates by key family
- prefers fullchain material where useful
- generates a sensible RRset automatically

## 6. Generates the TLSA association data

Depending on the tuple, the script uses either:

- the full DER certificate (`selector 0`)
- the DER SubjectPublicKeyInfo (`selector 1`)

Then it applies the matching type:

- `0` = exact bytes
- `1` = SHA-256
- `2` = SHA-512

## 7. Performs a local self-check

Before any publication, the script confirms that the generated TLSA data matches the certificate material it used.

## 8. Optionally publishes via RFC2136

If `--dry-run` is **not** used, the script then:

- loads or creates an RFC2136 profile
- confirms the TLSA owner name is inside the selected zone
- converts the owner name to a **zone-relative RFC2136 name** before sending the update
- publishes the TLSA RRset via RFC2136 using TSIG
- verifies the resulting RRset directly from the configured authoritative servers

## 9. Wrong-owner detection and automatic correction

Some DNS servers or buggy client logic can end up creating a record under a doubled owner name, for example:

```text
_5061._tcp.pbx.example.com.example.com.
```

instead of the intended:

```text
_5061._tcp.pbx.example.com.
```

The current script avoids that by sending zone-relative names for RFC2136 updates.

In addition, if publish mode detects that the expected TLSA RRset landed under the wrong doubled owner name, it will:

- report the wrong owner name it found
- delete the wrong owner name
- re-publish the expected RRset under the correct owner name
- verify again

In `--validate-only` mode, the script reports this condition but does **not** change DNS.

## 10. Validation-only mode

`--validate-only` regenerates the expected TLSA record set from the chosen certificate material and then checks whether the authoritative DNS servers already serve exactly that RRset.

This is useful after:

- waiting for secondaries to catch up
- fixing DNS manually in the server UI
- rechecking a service without publishing again

## 11. Optional documentation export

The script can optionally write the final TLSA RRset in BIND zone-file format to a text file.

This export is **for documentation purposes only** right now. The script does **not** use this file for publication.

## 12. Optional live TLS probe

If you choose it, the script opens a real TLS connection to the target service and compares the live certificate presented by the server with the certificate used during TLSA generation.

## RFC2136 profiles

The script can save reusable RFC2136/TSIG profiles containing:

- profile name
- authoritative DNS servers
- DNS port
- zone
- TSIG key name
- TSIG key secret
- TSIG algorithm
- timeout
- default TTL
- whether to update all configured servers
- verification attempts and delay

### Default storage location

By default, profiles are stored in:

```text
~/.config/tlsa-rfc2136/config.json
```

When run as `root`, that typically becomes:

```text
/root/.config/tlsa-rfc2136/config.json
```

The script writes this file with restrictive permissions because it contains the TSIG secret.

## Installation

### Debian / Ubuntu packages

```bash
sudo apt update
sudo apt install -y python3 python3-cryptography python3-dnspython
```

### Or with pip

```bash
python3 -m pip install cryptography dnspython
```

### Make executable

```bash
chmod +x tlsa_rfc2136_interactive.py
```

## Usage examples

Manual dry-run:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run
```

Manual publish mode:

```bash
python3 tlsa_rfc2136_interactive.py
```

Validation-only mode:

```bash
python3 tlsa_rfc2136_interactive.py --validate-only
```

Auto-sensible dry-run:

```bash
python3 tlsa_rfc2136_interactive.py --dry-run --mode auto-sensible
```

Auto-sensible publish mode:

```bash
python3 tlsa_rfc2136_interactive.py --mode auto-sensible
```

## Exit codes

- `0` = success
- `1` = fatal error
- `2` = completed, but DNS or live verification did not fully succeed
- `130` = aborted with Ctrl+C

## Notes and practical behavior

- The script reprompts in many places instead of aborting immediately.
- Invalid transports such as `5061` are rejected until a valid transport like `tcp` is entered.
- Directory paths entered where a file path is required are rejected and reprompted.
- Impossible TLSA tuples are shown as unavailable and cannot be selected.
- In `auto-sensible` mode, duplicate RRset entries are removed.
- The live TLS probe is optional because a server may present only one certificate path depending on negotiation.
- TSIG secrets are hidden while you type or paste them.

