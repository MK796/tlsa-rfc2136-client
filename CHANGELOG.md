# Changelog

All notable changes to this project will be documented in this file.

## [1.1] - 2026-03-24

### Added
- `--validate-only` mode to re-check authoritative DNS without publishing again
- Non-interactive automation flags:
  - `--config-file`
  - `--cert-path`
  - `--host`
  - `--port`
  - `--transport`
  - `--ttl`
  - `--profile`
  - `--export-file`
  - `--no-export`
  - `--live-check`
  - `--no-live-check`
  - `--verbose`
- Unit tests for:
  - wildcard hostname matching
  - TLSA tuple handling
  - RFC2136 owner-name handling
- Explicit RFC2136 profile management actions:
  - create
  - use
  - edit
  - delete
- Automatic detection and recovery for the wrong-owner RFC2136 symptom on supported workflows

### Changed
- Refactored the script to use typed dataclasses instead of loose dictionaries
- Improved live endpoint validation to compare tuple-aware TLSA associations instead of only whole certificate fingerprints
- Improved input reprompting and validation behavior across the interactive flow
- Normalized TSIG algorithm handling for common input variants
- Updated README to document all current flags and workflows

### Fixed
- Fixed RFC2136 owner handling by sending owner names relative to the configured zone
- Added early validation for TSIG Base64 secrets to avoid delayed runtime failures
- Prevented several user-input failure cases from aborting without a reprompt

## [1.0] - 2026-03-24

### Added
- Interactive TLSA record generation
- Certificate scanning and hostname validation
- RFC2136 publishing with TSIG
- Authoritative DNS verification
- Optional BIND-format documentation export
- Optional live TLS endpoint comparison
- Auto-sensible TLSA generation mode
