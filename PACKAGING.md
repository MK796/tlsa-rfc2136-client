# Packaging / Installation Notes

This repository ships a console tool to generate TLSA records and publish them via RFC2136.

## Names and entrypoints

- PyPI package name: `tlsa-rfc2136-client`
- Importable module: `tlsa_rfc2136_interactive`
- Console commands:
  - `tlsa-rfc2136-client`
  - `tlsa-rfc2136` (alias)

## Supported Python versions

- Python 3.10+

## Build (sdist + wheel)

Install build tooling:

    python -m pip install --upgrade pip build

Build:

    python -m build

Artifacts will be created in `dist/`.

## Install from local checkout

    python -m pip install .

Upgrade an existing installation:

    python -m pip install --upgrade .

Install editable (developer mode):

    python -m pip install --editable .

## Uninstall

    python -m pip uninstall tlsa-rfc2136-client

## Run

    tlsa-rfc2136-client --help
