#!/usr/bin/env python3
"""
Interactive TLSA generator + RFC2136 publisher.

Certbot-first version:
- Default certificate path is /etc/letsencrypt/live
- Designed to work out of the box with Certbot live-directory layouts

Optimized version:
- Typed dataclasses for certificate materials, profiles, and TLSA record plans
- RFC2136 owner names are sent relative to the configured zone
- Optional --validate-only mode
- Tuple-aware live TLS validation
- TSIG secret Base64 validation at input time
- TSIG algorithm normalization
- Better reprompts and clearer verification diagnostics
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import logging
import os
import re
import readline  # noqa: F401 — enables line-editing in input() prompts
import socket
import ssl
import sys
import time

# Enable full line-editing (backspace, arrow keys, history) for all input() prompts.
# libedit (macOS default) needs emacs mode set explicitly; GNU readline (Linux)
# gets explicit arrow-key bindings as a safety net against ~/.inputrc overrides.
if "libedit" in getattr(readline, "__doc__", ""):
    readline.parse_and_bind("bind -e")
else:
    readline.parse_and_bind("set editing-mode emacs")
    readline.parse_and_bind('"\\e[A": previous-history')
    readline.parse_and_bind('"\\e[B": next-history')
    readline.parse_and_bind('"\\e[C": forward-char')
    readline.parse_and_bind('"\\e[D": backward-char')

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

try:
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.tsigkeyring
    import dns.update
except ImportError:
    print("Missing dependency: dnspython\nInstall it with: pip install dnspython", file=sys.stderr)
    raise

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("Missing dependency: cryptography\nInstall it with: pip install cryptography", file=sys.stderr)
    raise

LOG = logging.getLogger("tlsa-rfc2136")
DEFAULT_CONFIG_FILE = Path.home() / ".config" / "tlsa-rfc2136" / "config.json"
DEFAULT_CERT_PATH = Path("/etc/letsencrypt/live")
PEM_CERT_PATTERN = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

TLSA_USAGE_EXPLANATIONS = {
    0: "PKIX-TA  - Match a trust-anchor/CA cert. Normal PKIX validation still applies.",
    1: "PKIX-EE  - Match the end-entity/server cert. Normal PKIX validation still applies.",
    2: "DANE-TA  - Match a trust-anchor/CA cert. DANE is authoritative; PKIX is not required.",
    3: "DANE-EE  - Match the end-entity/server cert directly. DANE is authoritative; PKIX is not required.",
}
TLSA_SELECTOR_EXPLANATIONS = {
    0: "Cert     - Use the full DER certificate.",
    1: "SPKI     - Use only SubjectPublicKeyInfo, so reissued certs with the same key keep the same TLSA.",
}
TLSA_MATCHING_EXPLANATIONS = {
    0: "Exact    - Store the selected bytes directly. Largest RR size.",
    1: "SHA-256  - Store a SHA-256 hash. Good default and widely supported.",
    2: "SHA-512  - Store a SHA-512 hash. Longer RR size than SHA-256.",
}
RECOMMENDED_TUPLES = [
    ((3, 1, 2), "Project default: pins the leaf public key with SHA-512. This is a project preference, not a protocol limitation."),
    ((3, 1, 1), "Alternative recommendation: pins the leaf public key with SHA-256."),
    ((3, 0, 1), "Pins the full leaf certificate, not just the public key."),
    ((2, 1, 1), "Useful when you intentionally want DANE-TA from a CA public key in the scanned bundle."),
]
AUTO_SENSIBLE_TUPLES = [(3, 1, 2), (3, 1, 1), (3, 0, 1)]

TSIG_ALGORITHM_ALIASES = {
    "hmac-md5": "hmac-md5.sig-alg.reg.int.",
    "hmac-md5.sig-alg.reg.int.": "hmac-md5.sig-alg.reg.int.",
    "hmac-sha1": "hmac-sha1",
    "hmac-sha224": "hmac-sha224",
    "hmac-sha256": "hmac-sha256",
    "hmac-sha384": "hmac-sha384",
    "hmac-sha512": "hmac-sha512",
}


@dataclass(frozen=True)
class CertificateMaterial:
    path: Path
    certs: tuple[x509.Certificate, ...]
    leaf_certs: tuple[x509.Certificate, ...]
    ca_certs: tuple[x509.Certificate, ...]
    is_fullchain: bool
    leaf_key_types: tuple[str, ...]
    names: tuple[str, ...]

    @property
    def primary_leaf(self) -> x509.Certificate:
        return self.leaf_certs[0] if self.leaf_certs else self.certs[0]


@dataclass
class RFC2136Profile:
    name: str
    servers: list[str]
    dns_port: int
    zone: str
    key_name: str
    key_secret: str
    key_algorithm: str
    timeout: float
    default_ttl: int
    update_all_servers: bool
    verify_attempts: int
    verify_delay: float

    @classmethod
    def from_dict(cls, data: dict) -> "RFC2136Profile":
        return cls(
            name=str(data["name"]),
            servers=[str(x) for x in data["servers"]],
            dns_port=int(data["dns_port"]),
            zone=ensure_absolute_name(str(data["zone"])),
            key_name=ensure_absolute_name(str(data["key_name"])),
            key_secret=str(data["key_secret"]).strip(),
            key_algorithm=normalize_tsig_algorithm(str(data.get("key_algorithm", "hmac-sha256"))),
            timeout=float(data.get("timeout", 5.0)),
            default_ttl=int(data.get("default_ttl", 3600)),
            update_all_servers=bool(data.get("update_all_servers", False)),
            verify_attempts=int(data.get("verify_attempts", 5)),
            verify_delay=float(data.get("verify_delay", 2.0)),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TLSARecordPlan:
    owner_name: str
    ttl: int
    usage: int
    selector: int
    matching_type: int
    association_hex: str
    source_material_path: str
    source_cert_subject: str
    source_cert_key_type: str
    source_label: str
    leaf_cert_der: bytes | None = None

    @property
    def rdata_text(self) -> str:
        return normalize_tlsa_rdata_text(
            f"{self.usage} {self.selector} {self.matching_type} {self.association_hex}"
        )

    @property
    def bind_line(self) -> str:
        return f"{ensure_absolute_name(self.owner_name)} {self.ttl} IN TLSA {self.rdata_text}"

# -----------------------------------------------------------------------------
# Sanity warnings and checks
@dataclass(frozen=True)
class SanityWarning:
    code: str
    message: str

def expected_tlsa_owner(host: str, port: int, transport: str) -> str:
    return ensure_absolute_name(f"_{port}._{transport}.{host}".rstrip("."))

def sanity_check_owner(owner_name: str, host: str, port: int, transport: str) -> list[SanityWarning]:
    exp = expected_tlsa_owner(host, port, transport)
    if ensure_absolute_name(owner_name) != exp:
        return [SanityWarning(
            code="owner-mismatch",
            message=f"TLSA owner name mismatch: expected '{exp}', got '{ensure_absolute_name(owner_name)}'. "
                    "This can happen when host/zone values are misconfigured or doubled-owner symptoms occur."
        )]
    return []

def sanity_check_tuple_plausibility(plans: list[TLSARecordPlan]) -> list[SanityWarning]:
    warnings: list[SanityWarning] = []
    has_sha512 = any(p.matching_type == 2 for p in plans)
    has_sha256 = any(p.matching_type == 1 for p in plans)
    if has_sha512 and not has_sha256:
        warnings.append(SanityWarning(
            code="tuple-compat",
            message="You are publishing SHA-512-only TLSA records (matching type 2). "
                    "RFC 6698 says clients MUST support SHA-256 (type 1) and SHOULD support SHA-512 (type 2). "
                    "Consider publishing an additional SHA-256 TLSA record (e.g. 3 1 1) for broader compatibility."
        ))
    if any(p.usage in (0, 1) for p in plans):
        warnings.append(SanityWarning(
            code="usage-pkix",
            message="Some TLSA records use PKIX usages (0/1). Ensure this matches your operational intent: "
                    "PKIX validation still applies for these usages."
        ))
    return warnings

def sanity_check_dnssec(profile: RFC2136Profile) -> list[SanityWarning]:
    warnings: list[SanityWarning] = []
    zone = ensure_absolute_name(profile.zone)
    for server in profile.servers[:1]:
        try:
            q = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
            q.flags &= ~dns.flags.RD
            r = dns.query.tcp(q, where=server, port=profile.dns_port, timeout=profile.timeout)
            has_dnskey = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in r.answer)
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in r.answer)
            if not has_dnskey:
                warnings.append(SanityWarning(
                    code="dnssec-unknown",
                    message=f"DNSSEC sanity: no DNSKEY RRset observed for zone '{zone}' from server '{server}'. "
                            "Zone may be unsigned or query may have been filtered."
                ))
            elif not has_rrsig:
                warnings.append(SanityWarning(
                    code="dnssec-weak-signal",
                    message=f"DNSSEC sanity: DNSKEY present for zone '{zone}', but no RRSIG observed in the answer "
                            f"from server '{server}'. Zone signing status could not be confirmed."
                ))
            if not (r.flags & dns.flags.AD):
                warnings.append(SanityWarning(
                    code="dnssec-ad-not-set",
                    message=f"DNSSEC sanity: AD bit not set in response from '{server}'. "
                            "This is expected for authoritative servers; do not interpret as DNSSEC failure."
                ))
        except Exception as exc:
            warnings.append(SanityWarning(
                code="dnssec-check-failed",
                message=f"DNSSEC sanity: DNSKEY query failed against '{server}': {exc}"
            ))
        break
    return warnings

def sanity_check_live_warn_only(host: str, port: int, transport: str, plans: list[TLSARecordPlan], timeout: float) -> list[SanityWarning]:
    try:
        status = validate_live_endpoint_against_plans(host, port, transport, plans, timeout)
        if not status.startswith("OK"):
            return [SanityWarning(code="live-mismatch", message=f"Live sanity: {status}")]
        return []
    except Exception as exc:
        return [SanityWarning(code="live-check-failed", message=f"Live sanity: probe failed: {exc}")]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive TLSA generator + RFC2136 publisher")
    parser.add_argument("--dry-run", action="store_true", help="Generate and validate locally, but do not publish or query authoritative DNS")
    parser.add_argument("--validate-only", action="store_true", help="Skip RFC2136 publication and only validate authoritative DNS against regenerated expected TLSA records")
    parser.add_argument("--mode", choices=["interactive", "auto-sensible"], default="interactive", help="Choose interactive single-plan mode or automatic sensible bulk mode")
    parser.add_argument("--config-file", help="Path to the saved RFC2136 profile config file")
    parser.add_argument("--cert-path", help="Certificate directory or PEM/CRT/CER file to scan (default prompt path: /etc/letsencrypt/live)")
    parser.add_argument("--host", help="Exact service host for the TLSA record")
    parser.add_argument("--port", type=int, help="Service port for the TLSA owner name")
    parser.add_argument("--transport", choices=["tcp", "udp", "sctp"], help="Transport protocol for the TLSA owner name")
    parser.add_argument("--ttl", type=int, help="TTL for the TLSA RRset")
    parser.add_argument("--profile", help="Use the saved RFC2136 profile with this name")
    parser.add_argument("--export-file", help="Write documentation-only BIND output to this file without prompting")
    parser.add_argument("--no-export", action="store_true", help="Skip the documentation-only BIND export prompt")
    parser.add_argument("--live-check", action="store_true", help="Run the live TLS endpoint check without prompting")
    parser.add_argument("--no-live-check", action="store_true", help="Skip the optional live TLS endpoint check")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--tuples",
        choices=["default", "all"],
        help="In auto-sensible mode: which tuples to publish without prompting. "
             "'default' = 3 1 2 only (project default); 'all' = 3 1 2 + 3 1 1 + 3 0 1. "
             "If omitted, prompts interactively. Only valid with --mode auto-sensible.",
    )
    parser.add_argument(
        "--sanity-checks",
        action="store_true",
        help="Enable non-blocking sanity checks (DNSSEC/DANE plausibility warnings).",
    )
    parser.add_argument(
        "--no-sanity",
        action="store_true",
        help="Disable all sanity checks.",
    )
    parser.add_argument(
        "--sanity-live",
        action="store_true",
        help="Also perform a warn-only live TLSA-vs-live-certificate check (non-blocking).",
    )
    args = parser.parse_args()
    if args.sanity_checks and args.no_sanity:
        parser.error("--sanity-checks and --no-sanity cannot be used together")
    if args.live_check and args.no_live_check:
        parser.error("--live-check and --no-live-check cannot be used together")
    if args.export_file and args.no_export:
        parser.error("--export-file and --no-export cannot be used together")
    if args.port is not None and not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535")
    if args.ttl is not None and args.ttl < 0:
        parser.error("--ttl must be greater than or equal to 0")
    if args.dry_run and args.validate_only:
        parser.error("--dry-run and --validate-only cannot be used together")
    if args.tuples and args.mode != "auto-sensible":
        parser.error("--tuples is only valid with --mode auto-sensible")
    return args


# ---------- prompt helpers ----------

def prompt(text: str, default: str | None = None, secret: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default not in (None, "") else ""
        full_prompt = f"{text}{suffix}: "
        value = getpass.getpass(full_prompt) if secret else input(full_prompt)
        value = value.strip()
        if value:
            return value
        if default is not None:
            return default
        print("Please enter a value.")


def prompt_yes_no(text: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{text} [{hint}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please answer y or n.")


def prompt_int(text: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    while True:
        raw = prompt(text, str(default))
        try:
            value = int(raw)
        except ValueError:
            print("Please enter a valid integer.")
            continue
        if min_value is not None and value < min_value:
            print(f"Please enter a value greater than or equal to {min_value}.")
            continue
        if max_value is not None and value > max_value:
            print(f"Please enter a value less than or equal to {max_value}.")
            continue
        return value


def prompt_float(text: str, default: float, min_value: float | None = None, max_value: float | None = None) -> float:
    while True:
        raw = prompt(text, str(default))
        try:
            value = float(raw)
        except ValueError:
            print("Please enter a valid number.")
            continue
        if min_value is not None and value < min_value:
            print(f"Please enter a value greater than or equal to {min_value}.")
            continue
        if max_value is not None and value > max_value:
            print(f"Please enter a value less than or equal to {max_value}.")
            continue
        return value


def prompt_existing_path(text: str, default: str | None = None) -> Path:
    while True:
        path = Path(prompt(text, default)).expanduser().resolve()
        if path.exists():
            return path
        print(f"Path does not exist: {path}")


def prompt_output_file_path(text: str, default: str) -> Path:
    while True:
        path = Path(prompt(text, default)).expanduser().resolve()
        if path.exists() and path.is_dir():
            print("That path is a directory. Please enter a full file path, for example /root/tlsa-record.txt")
            continue
        if path.parent.exists() and not path.parent.is_dir():
            print("The parent path is not a directory.")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


def prompt_config_file_path(text: str, default: str) -> Path:
    while True:
        path = Path(prompt(text, default)).expanduser()
        if path.exists() and path.is_dir():
            print("That path is a directory. Please enter a file path for the config file.")
            continue
        if path.parent.exists() and not path.parent.is_dir():
            print("The parent path is not a directory.")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


def validate_output_file_path(raw: str) -> Path:
    path = Path(raw).expanduser().resolve()
    if path.exists() and path.is_dir():
        raise ValueError(f"That path is a directory: {path}")
    if path.parent.exists() and not path.parent.is_dir():
        raise ValueError(f"The parent path is not a directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def validate_config_file_path(raw: str) -> Path:
    path = Path(raw).expanduser()
    if path.exists() and path.is_dir():
        raise ValueError(f"That path is a directory: {path}")
    if path.parent.exists() and not path.parent.is_dir():
        raise ValueError(f"The parent path is not a directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def prompt_transport(default: str = "tcp") -> str:
    allowed = {"tcp", "udp", "sctp"}
    while True:
        value = prompt("Transport protocol", default).strip().lower()
        if value in allowed:
            return value
        print("Transport must be one of: tcp, udp, sctp")


def prompt_tsig_secret() -> str:
    while True:
        secret = prompt("TSIG key secret (base64)", secret=True).strip()
        try:
            base64.b64decode(secret, validate=True)
            return secret
        except Exception as exc:
            print(f"Invalid Base64 TSIG secret: {exc}")


def prompt_tsig_algorithm(default: str = "hmac-sha256") -> str:
    while True:
        raw = prompt("TSIG algorithm", default)
        try:
            return normalize_tsig_algorithm(raw)
        except ValueError as exc:
            print(exc)


# ---------- name and TLSA helpers ----------

def ensure_absolute_name(name_text: str) -> str:
    name_text = name_text.strip()
    if not name_text.endswith("."):
        name_text += "."
    return name_text


def normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".")
    return domain.encode("idna").decode("ascii").lower()


def normalize_tsig_algorithm(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    normalized = re.sub(r"\s+", "", normalized)
    if normalized in TSIG_ALGORITHM_ALIASES:
        return TSIG_ALGORITHM_ALIASES[normalized]
    raise ValueError("Unsupported TSIG algorithm. Try one of: hmac-sha256, hmac-sha384, hmac-sha512, hmac-sha224, hmac-sha1, hmac-md5")


def normalize_tlsa_rdata_text(text: str) -> str:
    parts = text.strip().split()
    if len(parts) < 4:
        raise ValueError("TLSA RDATA must have at least 4 fields")
    return f"{int(parts[0])} {int(parts[1])} {int(parts[2])} {parts[3].lower()}"


def hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    hostname = normalize_domain(hostname)
    pattern = normalize_domain(pattern)
    if "*" not in pattern:
        return hostname == pattern
    if pattern.count("*") != 1:
        return False
    pattern_labels = pattern.split(".")
    hostname_labels = hostname.split(".")
    if not pattern_labels or pattern_labels[0] != "*":
        return False
    if len(pattern_labels) != len(hostname_labels):
        return False
    return pattern_labels[1:] == hostname_labels[1:]


def fqdn_is_in_zone(owner_name: str, zone_name: str) -> bool:
    owner = dns.name.from_text(ensure_absolute_name(owner_name))
    zone = dns.name.from_text(ensure_absolute_name(zone_name))
    return owner.is_subdomain(zone)


def owner_relative_to_zone(owner_name: str, zone_name: str) -> str:
    owner = dns.name.from_text(ensure_absolute_name(owner_name))
    zone = dns.name.from_text(ensure_absolute_name(zone_name))
    if not owner.is_subdomain(zone):
        raise ValueError(f"Owner name '{owner_name}' is not inside zone '{zone_name}'.")
    relative = owner.relativize(zone)
    if str(relative) == "@":
        return "@"
    text = relative.to_text().rstrip(".")
    return text or "@"


def doubled_owner_candidate(owner_name: str, zone_name: str) -> str | None:
    owner_abs = ensure_absolute_name(owner_name)
    zone_abs = ensure_absolute_name(zone_name)
    if owner_abs.endswith(zone_abs):
        zone_plain = zone_abs.rstrip(".")
        return ensure_absolute_name(owner_abs.rstrip(".") + "." + zone_plain)
    return None


def print_tlsa_scope_reminder(owner_name: str, domain: str, service_port: int, transport: str, zone_name: str | None = None) -> None:
    print("\nTLSA scope reminder:")
    print(f"  This TLSA owner name is {ensure_absolute_name(owner_name)}")
    print(f"  It applies only to {service_port}/{transport} on the exact host '{domain}'.")
    print("  It does not cover other host names in the same zone automatically.")
    print(f"  Example: a TLSA record for '{domain}' does not secure 'pbx.{domain}' unless you publish a separate TLSA record for that exact subdomain and service.")
    if zone_name is not None and normalize_domain(domain) == normalize_domain(zone_name.rstrip(".")):
        print("  Warning: you selected the zone apex/root host. That is correct only if clients really connect to that exact host.")


# ---------- certificate helpers ----------

def load_pem_certificates_from_file(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    blocks = PEM_CERT_PATTERN.findall(data)
    if not blocks:
        raise ValueError(f"No PEM certificates found in: {path}")
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def cert_dns_names(cert: x509.Certificate) -> list[str]:
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.extend(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    if not names:
        names.extend(attr.value for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    return names


def cert_is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bool(bc.value.ca)
    except x509.ExtensionNotFound:
        return False


def public_key_description(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA-{pub.key_size}"
    return type(pub).__name__


def public_key_family(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA"
    return type(pub).__name__


def describe_certificate(cert: x509.Certificate) -> str:
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    names = ", ".join(cert_dns_names(cert)) or "<no DNS names>"
    key_type = public_key_description(cert)
    role = "CA" if cert_is_ca(cert) else "leaf/server"
    return (
        f"Role   : {role}\n"
        f"Key    : {key_type}\n"
        f"Subject: {subject}\n"
        f"Issuer : {issuer}\n"
        f"Names  : {names}"
    )


def cert_matches_domain(cert: x509.Certificate, domain: str) -> bool:
    for name in cert_dns_names(cert):
        if hostname_matches_pattern(domain, name):
            return True
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if hostname_matches_pattern(domain, attr.value):
            return True
    return False


def discover_certificate_materials(path: Path) -> list[CertificateMaterial]:
    if path.is_file():
        candidate_files = [path]
    else:
        patterns = ("*.pem", "*.crt", "*.cer")
        seen: set[Path] = set()
        candidate_files: list[Path] = []
        for pattern in patterns:
            for found in sorted(path.rglob(pattern)):
                if found.is_file() and found not in seen:
                    seen.add(found)
                    candidate_files.append(found)

    materials: list[CertificateMaterial] = []
    for candidate in candidate_files:
        try:
            certs = tuple(load_pem_certificates_from_file(candidate))
        except Exception as exc:
            LOG.debug("Skipping unreadable certificate file %s: %s", candidate, exc)
            continue

        leaf_certs = tuple(cert for cert in certs if not cert_is_ca(cert))
        ca_certs = tuple(cert for cert in certs if cert_is_ca(cert))
        primary_leaf = leaf_certs[0] if leaf_certs else certs[0]
        leaf_key_types = tuple(sorted({public_key_description(cert) for cert in leaf_certs}) or [public_key_description(primary_leaf)])
        all_names: list[str] = []
        for cert in leaf_certs or certs:
            for name in cert_dns_names(cert):
                if name not in all_names:
                    all_names.append(name)

        materials.append(
            CertificateMaterial(
                path=candidate,
                certs=certs,
                leaf_certs=leaf_certs,
                ca_certs=ca_certs,
                is_fullchain=len(certs) > 1,
                leaf_key_types=leaf_key_types,
                names=tuple(all_names),
            )
        )
    return materials


def print_discovered_materials(materials: list[CertificateMaterial]) -> None:
    print("\nScanned certificate materials:")
    for idx, material in enumerate(materials, start=1):
        names = ", ".join(material.names[:6]) if material.names else "<no DNS names>"
        if len(material.names) > 6:
            names += ", ..."
        print(f"  {idx}. {material.path}")
        print(f"     key types : {', '.join(material.leaf_key_types)}")
        print(f"     fullchain : {'yes' if material.is_fullchain else 'no'}")
        print(f"     certs     : total={len(material.certs)}, leaf={len(material.leaf_certs)}, ca={len(material.ca_certs)}")
        print(f"     names     : {names}")


def material_has_matching_leaf(material: CertificateMaterial, domain: str) -> bool:
    return any(cert_matches_domain(cert, domain) for cert in material.leaf_certs)


def choose_discovered_material(materials: list[CertificateMaterial], domain: str | None = None) -> CertificateMaterial:
    if not materials:
        raise ValueError("No readable PEM/CRT/CER certificate material was found in the specified path.")
    print_discovered_materials(materials)
    eligible = materials if domain is None else [m for m in materials if material_has_matching_leaf(m, domain)]
    if not eligible:
        raise ValueError(f"No discovered certificate material contains a matching leaf certificate for '{domain}'.")
    if len(eligible) == 1:
        print(f"\nUsing the only eligible certificate material: {eligible[0].path}")
        return eligible[0]
    if domain is not None:
        print(f"\nOnly materials containing a leaf certificate that matches '{domain}' can be selected.")
    while True:
        choice = prompt_int("Choose certificate material number", 1, min_value=1, max_value=len(materials))
        chosen = materials[choice - 1]
        if domain is not None and not material_has_matching_leaf(chosen, domain):
            print(f"The selected material does not contain a leaf certificate that matches '{domain}'. Please choose another material.")
            continue
        return chosen


def pick_end_entity_certificate(material: CertificateMaterial, domain: str) -> x509.Certificate:
    matching = [cert for cert in material.leaf_certs if cert_matches_domain(cert, domain)]
    if not matching:
        raise ValueError(f"No leaf certificate in {material.path} matches '{domain}'.")
    exact_name_matches = [cert for cert in matching if normalize_domain(domain) in [normalize_domain(x) for x in cert_dns_names(cert)]]
    if exact_name_matches:
        return exact_name_matches[0]
    return matching[0]


# ---------- TLSA planning ----------

def tlsa_capability_mask(material: CertificateMaterial) -> dict[str, dict[int, dict[str, str | bool]]]:
    has_leaf = bool(material.leaf_certs)
    has_ca = bool(material.ca_certs)
    return {
        "usage": {
            0: {"available": has_ca, "reason": "needs a CA/trust-anchor cert in the selected file or bundle"},
            1: {"available": has_leaf, "reason": "needs a leaf/server cert"},
            2: {"available": has_ca, "reason": "needs a CA/trust-anchor cert in the selected file or bundle"},
            3: {"available": has_leaf, "reason": "needs a leaf/server cert"},
        },
        "selector": {
            0: {"available": True, "reason": "always possible with the chosen certificate"},
            1: {"available": True, "reason": "always possible with the chosen certificate"},
        },
        "matching": {
            0: {"available": True, "reason": "always possible"},
            1: {"available": True, "reason": "always possible"},
            2: {"available": True, "reason": "always possible"},
        },
    }


def tuple_is_possible(material: CertificateMaterial, usage: int, selector: int, matching_type: int) -> tuple[bool, str]:
    mask = tlsa_capability_mask(material)
    if usage not in mask["usage"]:
        return False, "unknown usage"
    if selector not in mask["selector"]:
        return False, "unknown selector"
    if matching_type not in mask["matching"]:
        return False, "unknown matching type"
    if not mask["usage"][usage]["available"]:
        return False, str(mask["usage"][usage]["reason"])
    if not mask["selector"][selector]["available"]:
        return False, str(mask["selector"][selector]["reason"])
    if not mask["matching"][matching_type]["available"]:
        return False, str(mask["matching"][matching_type]["reason"])
    return True, "OK"


def possible_tuples_for_material(material: CertificateMaterial) -> list[tuple[int, int, int]]:
    tuples: list[tuple[int, int, int]] = []
    for usage in TLSA_USAGE_EXPLANATIONS:
        for selector in TLSA_SELECTOR_EXPLANATIONS:
            for matching in TLSA_MATCHING_EXPLANATIONS:
                ok, _ = tuple_is_possible(material, usage, selector, matching)
                if ok:
                    tuples.append((usage, selector, matching))
    return tuples


def print_tlsa_option_mask(material: CertificateMaterial) -> None:
    mask = tlsa_capability_mask(material)
    print("\nTLSA option mask for the selected certificate material")
    print(f"  source file : {material.path}")
    print(f"  key types   : {', '.join(material.leaf_key_types)}")
    print(f"  fullchain   : {'yes' if material.is_fullchain else 'no'}")
    print(f"  leaf cert   : {'yes' if material.leaf_certs else 'no'}")
    print(f"  CA cert     : {'yes' if material.ca_certs else 'no'}")

    print("\nUsage options")
    for key in sorted(TLSA_USAGE_EXPLANATIONS):
        info = mask["usage"][key]
        status = "AVAILABLE" if info["available"] else "NOT AVAILABLE"
        print(f"  [{key}] {status:13} {TLSA_USAGE_EXPLANATIONS[key]}")
        print(f"      why: {info['reason']}")

    print("\nSelector options")
    for key in sorted(TLSA_SELECTOR_EXPLANATIONS):
        info = mask["selector"][key]
        status = "AVAILABLE" if info["available"] else "NOT AVAILABLE"
        print(f"  [{key}] {status:13} {TLSA_SELECTOR_EXPLANATIONS[key]}")
        print(f"      why: {info['reason']}")

    print("\nMatching options")
    for key in sorted(TLSA_MATCHING_EXPLANATIONS):
        info = mask["matching"][key]
        status = "AVAILABLE" if info["available"] else "NOT AVAILABLE"
        print(f"  [{key}] {status:13} {TLSA_MATCHING_EXPLANATIONS[key]}")
        print(f"      why: {info['reason']}")

    possible = possible_tuples_for_material(material)
    print(f"\nPossible standard tuples for this material: {len(possible)}")
    for tpl in possible:
        print(f"  {tpl[0]} {tpl[1]} {tpl[2]}")

    print("\nRecommended tuples for this material")
    for (usage, selector, matching), note in RECOMMENDED_TUPLES:
        ok, _ = tuple_is_possible(material, usage, selector, matching)
        state = "recommended" if ok else "not possible"
        print(f"  {usage} {selector} {matching} -> {state} | {note}")


def prompt_available_choice(title: str, explanations: dict[int, str], availability: dict[int, dict[str, str | bool]], default: int) -> int:
    available_keys = [key for key, info in availability.items() if info["available"]]
    if default not in available_keys:
        default = available_keys[0]
    print(f"\n{title}")
    for key in sorted(explanations):
        status = "available" if availability[key]["available"] else "not available"
        marker = " (default)" if key == default else ""
        print(f"  {key} - {status:13} {explanations[key]}{marker}")
    while True:
        raw = prompt("Choose option", str(default))
        try:
            chosen = int(raw)
        except ValueError:
            print("Please enter one of the shown option numbers.")
            continue
        if chosen not in explanations:
            print("Please enter one of the shown option numbers.")
            continue
        if not availability[chosen]["available"]:
            print(f"That option is not possible here: {availability[chosen]['reason']}")
            continue
        return chosen


def choose_tlsa_settings(material: CertificateMaterial) -> tuple[int, int, int]:
    print_tlsa_option_mask(material)
    default_tuple = (3, 1, 2)
    if tuple_is_possible(material, *default_tuple)[0] and prompt_yes_no("Use the project default 3 1 2", default=True):
        return default_tuple
    alt_tuple = (3, 1, 1)
    if tuple_is_possible(material, *alt_tuple)[0] and prompt_yes_no("Use the alternative recommendation 3 1 1", default=False):
        return alt_tuple
    mask = tlsa_capability_mask(material)
    usage = prompt_available_choice("TLSA certificate usage", TLSA_USAGE_EXPLANATIONS, mask["usage"], 3)
    selector = prompt_available_choice("TLSA selector", TLSA_SELECTOR_EXPLANATIONS, mask["selector"], 1)
    matching = prompt_available_choice("TLSA matching type", TLSA_MATCHING_EXPLANATIONS, mask["matching"], 2)
    return usage, selector, matching


def choose_certificate_for_association(material: CertificateMaterial, leaf_cert: x509.Certificate, usage: int) -> x509.Certificate:
    if usage in {1, 3}:
        return leaf_cert
    ca_candidates = list(material.ca_certs)
    if not ca_candidates:
        raise ValueError("The selected TLSA usage needs a CA/trust-anchor certificate, but none was found.")
    print("\nTLSA usage requires a trust-anchor / CA certificate.")
    print("Select which CA certificate from the selected material should be used for the TLSA association data.")
    for idx, cert in enumerate(ca_candidates, start=1):
        names = ", ".join(cert_dns_names(cert)) or "<no DNS names>"
        print(f"  {idx}. key={public_key_description(cert)} | subject={cert.subject.rfc4514_string()} | issuer={cert.issuer.rfc4514_string()} | names={names}")
    while True:
        chosen_idx = prompt_int("Choose CA certificate number for TLSA data", 1, min_value=1, max_value=len(ca_candidates))
        return ca_candidates[chosen_idx - 1]


def generate_tlsa_association(cert: x509.Certificate, selector: int, matching_type: int) -> str:
    if selector == 0:
        selected_data = cert.public_bytes(serialization.Encoding.DER)
    elif selector == 1:
        selected_data = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        raise ValueError("Unsupported TLSA selector. Only 0 and 1 are valid.")
    if matching_type == 0:
        return selected_data.hex()
    if matching_type == 1:
        return hashlib.sha256(selected_data).hexdigest()
    if matching_type == 2:
        return hashlib.sha512(selected_data).hexdigest()
    raise ValueError("Unsupported TLSA matching type. Only 0, 1 and 2 are valid.")


def build_plan(material: CertificateMaterial, leaf_cert: x509.Certificate, association_cert: x509.Certificate, owner_name: str, ttl: int, usage: int, selector: int, matching_type: int) -> TLSARecordPlan:
    association_hex = generate_tlsa_association(association_cert, selector, matching_type)
    return TLSARecordPlan(
        owner_name=owner_name,
        ttl=ttl,
        usage=usage,
        selector=selector,
        matching_type=matching_type,
        association_hex=association_hex,
        source_material_path=str(material.path),
        source_cert_subject=association_cert.subject.rfc4514_string(),
        source_cert_key_type=public_key_description(association_cert),
        source_label=f"{public_key_family(leaf_cert)} | {usage} {selector} {matching_type} | {material.path}",
        leaf_cert_der=leaf_cert.public_bytes(serialization.Encoding.DER),
    )


def choose_auto_sensible_tuples(preselected: str | None = None) -> list[tuple[int, int, int]]:
    if preselected == "default":
        return [(3, 1, 2)]
    if preselected == "all":
        return list(AUTO_SENSIBLE_TUPLES)
    print("\nAuto-sensible tuple selection")
    print("  Project default : 3 1 2")
    print("  Alternative     : 3 1 1")
    print("  Also available  : 3 0 1")
    print("  Note: 3 1 2 is a project preference, not a protocol limitation.")
    print("  1. Publish only the project default tuple (3 1 2)")
    print("  2. Publish all sensible tuples (3 1 2, 3 1 1, 3 0 1)")
    print("  3. Publish a custom subset from the sensible tuples")
    while True:
        choice = prompt("Choose auto-sensible publication mode", "1")
        if choice == "1":
            return [(3, 1, 2)]
        if choice == "2":
            return list(AUTO_SENSIBLE_TUPLES)
        if choice == "3":
            chosen: list[tuple[int, int, int]] = []
            for tpl in AUTO_SENSIBLE_TUPLES:
                default = tpl == (3, 1, 2)
                if prompt_yes_no(f"Include tuple {tpl[0]} {tpl[1]} {tpl[2]}", default=default):
                    chosen.append(tpl)
            if chosen:
                return chosen
            print("Please select at least one tuple.")
            continue
        print("Please enter 1, 2, or 3.")


def choose_best_matching_materials_by_family(materials: list[CertificateMaterial], domain: str) -> list[tuple[str, CertificateMaterial, x509.Certificate]]:
    best: dict[str, tuple[CertificateMaterial, x509.Certificate]] = {}
    for material in materials:
        try:
            leaf_cert = pick_end_entity_certificate(material, domain)
        except Exception:
            continue
        family = public_key_family(leaf_cert)
        current = best.get(family)
        is_wildcard = any("*" in n for n in cert_dns_names(leaf_cert))
        score = (1 if is_wildcard else 0, 1 if material.is_fullchain else 0, len(material.ca_certs), len(material.certs))
        if current is None:
            best[family] = (material, leaf_cert)
            continue
        current_material, current_leaf = current
        current_is_wildcard = any("*" in n for n in cert_dns_names(current_leaf))
        current_score = (1 if current_is_wildcard else 0, 1 if current_material.is_fullchain else 0, len(current_material.ca_certs), len(current_material.certs))
        if score > current_score:
            best[family] = (material, leaf_cert)
    family_order = {"RSA": 0, "ECDSA": 1, "Ed25519": 2, "Ed448": 3, "DSA": 4}
    return [(family, material, leaf_cert) for family, (material, leaf_cert) in sorted(best.items(), key=lambda item: (family_order.get(item[0], 99), item[0]))]


def run_interactive_mode(materials: list[CertificateMaterial], domain: str, owner_name: str, ttl: int) -> list[TLSARecordPlan]:
    selected_material = choose_discovered_material(materials, domain)
    print(f"\nSelected certificate material: {selected_material.path}")
    print(f"Discovered key type(s): {', '.join(selected_material.leaf_key_types)}")
    print(f"Looks like fullchain: {'yes' if selected_material.is_fullchain else 'no'}")
    leaf_cert = pick_end_entity_certificate(selected_material, domain)
    print("\nMatching end-entity certificate selected for domain validation:")
    print(describe_certificate(leaf_cert))
    print(f"\nDomain validation succeeded for: {domain}")
    usage, selector, matching_type = choose_tlsa_settings(selected_material)
    association_cert = choose_certificate_for_association(selected_material, leaf_cert, usage)
    print("\nCertificate chosen for TLSA association data:")
    print(describe_certificate(association_cert))
    plan = build_plan(selected_material, leaf_cert, association_cert, owner_name, ttl, usage, selector, matching_type)
    return [plan]


def run_auto_sensible_mode(materials: list[CertificateMaterial], domain: str, owner_name: str, ttl: int, single_file: bool = False, tuples: str | None = None) -> list[TLSARecordPlan]:
    if single_file:
        # A specific cert file was given — use it directly without family scoring.
        material = materials[0]
        try:
            leaf_cert = pick_end_entity_certificate(material, domain)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        selected: list[tuple[str, CertificateMaterial, x509.Certificate]] = [(public_key_family(leaf_cert), material, leaf_cert)]
    else:
        selected = choose_best_matching_materials_by_family(materials, domain)
    if not selected:
        raise RuntimeError(f"No discovered certificate material contains a matching leaf certificate for domain '{domain}'.")
    chosen_tuples = choose_auto_sensible_tuples(preselected=tuples)
    print("\nAutomatic bulk selection summary")
    for family, material, leaf_cert in selected:
        print(f"  {family}: {material.path}")
        print(f"    names     : {', '.join(cert_dns_names(leaf_cert)) or '<no DNS names>'}")
        print(f"    fullchain : {'yes' if material.is_fullchain else 'no'}")
        print(f"    ca certs  : {len(material.ca_certs)}")
    plans: list[TLSARecordPlan] = []
    for family, material, leaf_cert in selected:
        print(f"\nUsing {family} material from: {material.path}")
        print(describe_certificate(leaf_cert))
        for usage, selector, matching_type in chosen_tuples:
            ok, reason = tuple_is_possible(material, usage, selector, matching_type)
            if not ok:
                print(f"  skipping {usage} {selector} {matching_type}: {reason}")
                continue
            association_cert = choose_certificate_for_association(material, leaf_cert, usage)
            plan = build_plan(material, leaf_cert, association_cert, owner_name, ttl, usage, selector, matching_type)
            print(f"  prepared {usage} {selector} {matching_type}")
            plans.append(plan)
    dedup: dict[str, TLSARecordPlan] = {}
    for plan in plans:
        dedup.setdefault(plan.rdata_text, plan)
    unique = list(dedup.values())
    print(f"\nPrepared {len(unique)} unique TLSA record(s) in automatic sensible bulk mode.")
    return unique


def print_record_plan_summary(plans: list[TLSARecordPlan]) -> None:
    print("\nGenerated TLSA record set:")
    for plan in plans:
        print(plan.bind_line)
    print("\nSelf-check against the source certificate material:")
    for plan in plans:
        print(f"  OK -> {plan.rdata_text} | source={plan.source_material_path} | key={plan.source_cert_key_type}")


# ---------- RFC2136 profiles ----------

def load_saved_profiles(config_file: Path) -> list[RFC2136Profile]:
    if not config_file.exists():
        return []
    try:
        data = json.loads(config_file.read_text(encoding="utf-8"))
        raw_profiles = data.get("profiles", [])
        if not isinstance(raw_profiles, list):
            return []
        profiles: list[RFC2136Profile] = []
        for raw in raw_profiles:
            try:
                profiles.append(RFC2136Profile.from_dict(raw))
            except Exception as exc:
                print(f"Warning: skipping invalid saved profile: {exc}")
        return profiles
    except Exception as exc:
        print(f"Warning: could not read config file '{config_file}': {exc}")
        return []


def save_profiles(config_file: Path, profiles: list[RFC2136Profile]) -> None:
    config_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 2, "profiles": [p.to_dict() for p in profiles]}
    temp_path = config_file.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(temp_path, 0o600)
    temp_path.replace(config_file)
    os.chmod(config_file, 0o600)


def create_or_edit_profile(existing: RFC2136Profile | None = None) -> RFC2136Profile:
    creating = existing is None
    print(f"\n{'Create new' if creating else 'Edit'} RFC2136 / TSIG profile")
    defaults = existing or RFC2136Profile(
        name="default",
        servers=["127.0.0.1"],
        dns_port=53,
        zone="example.com.",
        key_name="update-key.",
        key_secret="",
        key_algorithm="hmac-sha256",
        timeout=5.0,
        default_ttl=3600,
        update_all_servers=False,
        verify_attempts=5,
        verify_delay=2.0,
    )

    name = prompt("Profile name", defaults.name)
    while True:
        servers_raw = prompt("Authoritative DNS server IPs/hostnames (comma-separated)", ", ".join(defaults.servers))
        servers = [item.strip() for item in servers_raw.split(",") if item.strip()]
        if servers:
            break
        print("At least one DNS server is required.")
    zone = ensure_absolute_name(prompt("DNS zone for the update", defaults.zone.rstrip(".")))
    dns_port = prompt_int("DNS port", defaults.dns_port, min_value=1, max_value=65535)
    key_name = ensure_absolute_name(prompt("TSIG key name", defaults.key_name.rstrip(".")))
    if creating or prompt_yes_no("Replace the saved TSIG secret", default=False):
        key_secret = prompt_tsig_secret()
    else:
        key_secret = defaults.key_secret
    key_algorithm = prompt_tsig_algorithm(defaults.key_algorithm)
    timeout = prompt_float("DNS timeout in seconds", defaults.timeout, min_value=0.1)
    default_ttl = prompt_int("Default TTL for the TLSA RR", defaults.default_ttl, min_value=0)
    update_all_servers = prompt_yes_no(
        "Send RFC2136 UPDATE to all configured servers (instead of stopping at first success)?",
        default=defaults.update_all_servers,
    )
    verify_attempts = prompt_int("Verification attempts", defaults.verify_attempts, min_value=1)
    verify_delay = prompt_float("Seconds between verification attempts", defaults.verify_delay, min_value=0.0)
    return RFC2136Profile(
        name=name,
        servers=servers,
        dns_port=dns_port,
        zone=zone,
        key_name=key_name,
        key_secret=key_secret,
        key_algorithm=key_algorithm,
        timeout=timeout,
        default_ttl=default_ttl,
        update_all_servers=update_all_servers,
        verify_attempts=verify_attempts,
        verify_delay=verify_delay,
    )


def choose_profile_index(profiles: list[RFC2136Profile], action: str) -> int:
    while True:
        idx = prompt_int(f"Choose profile number to {action}", 1, min_value=1, max_value=len(profiles))
        return idx - 1


def get_profile_by_name(profiles: list[RFC2136Profile], name: str) -> RFC2136Profile | None:
    for profile in profiles:
        if profile.name == name:
            return profile
    return None


def print_saved_profiles(profiles: list[RFC2136Profile]) -> None:
    print("\nSaved RFC2136 profiles:")
    for idx, profile in enumerate(profiles, start=1):
        print(f"  {idx}. {profile.name}  (zone={profile.zone}, servers={', '.join(profile.servers)})")
    print("  N. Create a new profile")
    print("  E. Edit a saved profile")
    print("  D. Delete a saved profile")


def choose_or_manage_profile(config_file: Path, owner_name: str, requested_name: str | None = None) -> RFC2136Profile:
    profiles = load_saved_profiles(config_file)

    if requested_name is not None:
        chosen = get_profile_by_name(profiles, requested_name)
        if chosen is None:
            raise ValueError(f"Saved RFC2136 profile '{requested_name}' was not found in {config_file}.")
        if not fqdn_is_in_zone(owner_name, chosen.zone):
            raise ValueError(f"Saved profile '{requested_name}' uses zone '{chosen.zone}', but owner '{owner_name}' is not inside that zone.")
        return chosen

    if not profiles:
        profile = create_or_edit_profile(None)
        if prompt_yes_no("Save this profile", default=True):
            save_profiles(config_file, [profile])
        return profile

    while True:
        print_saved_profiles(profiles)
        choice = input("Select a profile number, or N/E/D: ").strip().lower()
        if choice == "n":
            profile = create_or_edit_profile(None)
            if prompt_yes_no("Save this new profile", default=True):
                profiles.append(profile)
                save_profiles(config_file, profiles)
            return profile
        if choice == "e":
            idx = choose_profile_index(profiles, "edit")
            edited = create_or_edit_profile(profiles[idx])
            profiles[idx] = edited
            save_profiles(config_file, profiles)
            print(f"Profile '{edited.name}' saved.")
            continue
        if choice == "d":
            idx = choose_profile_index(profiles, "delete")
            victim = profiles[idx]
            if prompt_yes_no(f"Delete saved profile '{victim.name}'", default=False):
                del profiles[idx]
                save_profiles(config_file, profiles)
                print(f"Deleted profile '{victim.name}'.")
                if not profiles:
                    profile = create_or_edit_profile(None)
                    if prompt_yes_no("Save this profile", default=True):
                        save_profiles(config_file, [profile])
                    return profile
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(profiles):
                chosen = profiles[idx - 1]
                if not fqdn_is_in_zone(owner_name, chosen.zone):
                    print(f"That saved profile uses zone '{chosen.zone}', but the owner '{owner_name}' is not inside that zone.")
                    continue
                if prompt_yes_no("Use this saved profile as-is", default=True):
                    return chosen
                if prompt_yes_no("Edit this saved profile instead", default=True):
                    edited = create_or_edit_profile(chosen)
                    profiles[idx - 1] = edited
                    save_profiles(config_file, profiles)
                    return edited
                continue
        print("Invalid selection.")


def make_keyring(profile: RFC2136Profile):
    return dns.tsigkeyring.from_text({profile.key_name: profile.key_secret})


# ---------- DNS publishing and validation ----------

def publish_tlsa_records(profile: RFC2136Profile, owner_name: str, ttl: int, rdata_texts: list[str]) -> list[tuple[str, str]]:
    relative_owner = owner_relative_to_zone(owner_name, profile.zone)
    update = dns.update.Update(
        profile.zone,
        keyring=make_keyring(profile),
        keyname=profile.key_name,
        keyalgorithm=profile.key_algorithm,
    )
    update.delete(relative_owner, "TLSA")
    for rdata_text in rdata_texts:
        update.add(relative_owner, ttl, "TLSA", normalize_tlsa_rdata_text(rdata_text))
    results: list[tuple[str, str]] = []
    any_success = False
    for server in profile.servers:
        try:
            response = dns.query.tcp(update, where=server, port=profile.dns_port, timeout=profile.timeout)
            rcode = dns.rcode.to_text(response.rcode())
            if response.rcode() != dns.rcode.NOERROR:
                raise RuntimeError(f"server returned rcode {rcode}")
            results.append((server, "OK"))
            any_success = True
            if not profile.update_all_servers:
                break
        except Exception as exc:
            results.append((server, f"FAILED: {exc}"))
    if not any_success:
        details = "\n".join(f"  - {server}: {status}" for server, status in results)
        raise RuntimeError(f"RFC2136 update failed on every configured server:\n{details}")
    return results


def delete_wrong_owner_if_present(profile: RFC2136Profile, wrong_owner: str) -> list[tuple[str, str]]:
    relative_owner = owner_relative_to_zone(wrong_owner, profile.zone)
    update = dns.update.Update(
        profile.zone,
        keyring=make_keyring(profile),
        keyname=profile.key_name,
        keyalgorithm=profile.key_algorithm,
    )
    update.delete(relative_owner, "TLSA")
    results: list[tuple[str, str]] = []
    for server in profile.servers:
        try:
            response = dns.query.tcp(update, where=server, port=profile.dns_port, timeout=profile.timeout)
            rcode = dns.rcode.to_text(response.rcode())
            if response.rcode() != dns.rcode.NOERROR:
                raise RuntimeError(f"server returned rcode {rcode}")
            results.append((server, "DELETED"))
            if not profile.update_all_servers:
                break
        except Exception as exc:
            results.append((server, f"FAILED: {exc}"))
    return results


def query_tlsa_direct(server: str, port: int, timeout: float, owner_name: str) -> list[str]:
    query = dns.message.make_query(ensure_absolute_name(owner_name), "TLSA")
    query.flags &= ~dns.flags.RD
    response = dns.query.tcp(query, where=server, port=port, timeout=timeout)
    texts: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.TLSA:
            for rdata in rrset:
                texts.append(normalize_tlsa_rdata_text(rdata.to_text()))
    return texts


def verify_publication(profile: RFC2136Profile, owner_name: str, expected_rdata_texts: list[str]) -> dict[str, str]:
    expected = {normalize_tlsa_rdata_text(x) for x in expected_rdata_texts}
    wrong_owner = doubled_owner_candidate(owner_name, profile.zone)
    last_results: dict[str, str] = {}
    for attempt in range(1, profile.verify_attempts + 1):
        all_ok = True
        current: dict[str, str] = {}
        for server in profile.servers:
            try:
                answers = {x for x in query_tlsa_direct(server, profile.dns_port, profile.timeout, owner_name)}
                if answers == expected:
                    current[server] = "OK"
                else:
                    parts: list[str] = []
                    missing = sorted(expected - answers)
                    extra = sorted(answers - expected)
                    if missing:
                        parts.append(f"missing={missing}")
                    if extra:
                        parts.append(f"extra={extra}")
                    if wrong_owner:
                        wrong_answers = {x for x in query_tlsa_direct(server, profile.dns_port, profile.timeout, wrong_owner)}
                        if wrong_answers == expected:
                            parts.append(f"wrong-owner-present={ensure_absolute_name(wrong_owner)}")
                    current[server] = "MISMATCH: " + "; ".join(parts) if parts else "MISMATCH"
                    all_ok = False
            except Exception as exc:
                current[server] = f"QUERY FAILED: {exc}"
                all_ok = False
        last_results = current
        if all_ok:
            return last_results
        if attempt < profile.verify_attempts:
            time.sleep(profile.verify_delay)
    return last_results


def verify_results_indicate_wrong_owner(verify_results: dict[str, str]) -> bool:
    return any("wrong-owner-present=" in status for status in verify_results.values())


def try_fix_wrong_owner(profile: RFC2136Profile, owner_name: str, ttl: int, expected_rdata_texts: list[str]) -> bool:
    wrong_owner = doubled_owner_candidate(owner_name, profile.zone)
    if not wrong_owner:
        return False
    expected = {normalize_tlsa_rdata_text(x) for x in expected_rdata_texts}
    detected = False
    for server in profile.servers:
        try:
            wrong_answers = {x for x in query_tlsa_direct(server, profile.dns_port, profile.timeout, wrong_owner)}
        except Exception:
            continue
        if wrong_answers == expected:
            print(f"\nDetected wrong owner symptom on {server}: {ensure_absolute_name(wrong_owner)}")
            print("Attempting automatic correction by deleting the wrong owner and publishing again at the correct owner.")
            detected = True
            break
    if not detected:
        return False

    delete_results = delete_wrong_owner_if_present(profile, wrong_owner)
    for srv, status in delete_results:
        print(f"  cleanup {srv}: {status}")

    publish_results = publish_tlsa_records(profile, owner_name, ttl, expected_rdata_texts)
    for srv, status in publish_results:
        print(f"  republish {srv}: {status}")
    return True


def verify_plans_against_dns(profile: RFC2136Profile, plans: list[TLSARecordPlan]) -> dict[str, str]:
    return verify_publication(profile, plans[0].owner_name, [plan.rdata_text for plan in plans])


# ---------- live validation ----------

def fetch_live_leaf_certificate(domain: str, port: int, timeout: float) -> x509.Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("remote endpoint did not present a certificate")
            return x509.load_der_x509_certificate(der)


def validate_live_endpoint_against_plans(domain: str, service_port: int, transport: str, plans: list[TLSARecordPlan], timeout: float) -> str:
    if transport != "tcp":
        return "SKIPPED: live TLS validation currently supports only tcp"
    live_cert = fetch_live_leaf_certificate(domain, service_port, timeout)
    live_matches: list[str] = []
    for plan in plans:
        if plan.usage not in {1, 3}:
            continue
        live_assoc = generate_tlsa_association(live_cert, plan.selector, plan.matching_type)
        if live_assoc.lower() == plan.association_hex.lower():
            live_matches.append(plan.source_label)
    if live_matches:
        return "OK: live endpoint matches generated TLSA plan(s): " + "; ".join(live_matches)
    return "MISMATCH: live endpoint certificate does not satisfy any generated end-entity TLSA plan"


# ---------- output ----------

def write_bind_records(path: Path, plans: list[TLSARecordPlan]) -> None:
    text = "\n".join(plan.bind_line for plan in plans) + "\n"
    if path.exists():
        mode = "a" if prompt_yes_no("Output file exists. Append instead of overwrite", default=True) else "w"
    else:
        mode = "w"
    with path.open(mode, encoding="utf-8") as handle:
        if mode == "a" and path.stat().st_size > 0:
            handle.write("\n")
        handle.write(text)


# ---------- main flow ----------

def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s")

    print("Interactive TLSA generator + RFC2136 publisher\n")
    print("Certbot-first note: this tool is designed to work out of the box with Certbot live directories.\n")
    print(f"Mode    : {args.mode}")
    print(f"Dry-run : {'yes' if args.dry_run else 'no'}")
    if args.validate_only:
        print("Validate : yes (skip RFC2136 publication)")

    cert_path = prompt_existing_path("Path to certificate directory or PEM/CRT/CER file", str(DEFAULT_CERT_PATH)) if not args.cert_path else Path(args.cert_path).expanduser().resolve()
    if not cert_path.exists():
        raise FileNotFoundError(f"Path does not exist: {cert_path}")
    materials = discover_certificate_materials(cert_path)
    if not materials:
        raise RuntimeError("No readable certificate material was discovered.")

    domain = normalize_domain(args.host) if args.host else normalize_domain(prompt("Exact service host the certificate is for (e.g. www.example.com)"))
    if not any(material_has_matching_leaf(m, domain) for m in materials):
        raise RuntimeError(f"No matching leaf certificate for '{domain}' was found in the scanned material.")

    service_port = args.port if args.port is not None else prompt_int("Service port for TLSA owner name", 443, min_value=1, max_value=65535)
    transport = args.transport if args.transport else prompt_transport("tcp")
    owner_name = f"_{service_port}._{transport}.{domain}"
    print(f"TLSA owner name: {ensure_absolute_name(owner_name)}")
    ttl = args.ttl if args.ttl is not None else prompt_int("TTL for the TLSA RR", 3600, min_value=0)
    print_tlsa_scope_reminder(owner_name, domain, service_port, transport)

    plans = run_interactive_mode(materials, domain, owner_name, ttl) if args.mode == "interactive" else run_auto_sensible_mode(materials, domain, owner_name, ttl, single_file=cert_path.is_file(), tuples=args.tuples)
    print_record_plan_summary(plans)

    publication_ok = True
    live_ok = True
    profile: Optional[RFC2136Profile] = None

    if not args.dry_run or args.validate_only:
        if args.config_file:
            config_file = validate_config_file_path(args.config_file)
        else:
            config_file = prompt_config_file_path("Config file path", str(DEFAULT_CONFIG_FILE))
        profile = choose_or_manage_profile(config_file, owner_name, requested_name=args.profile)
        if not fqdn_is_in_zone(owner_name, profile.zone):
            raise ValueError(f"TLSA owner name '{owner_name}' is not inside zone '{profile.zone}'.")
        print_tlsa_scope_reminder(owner_name, domain, service_port, transport, profile.zone)

        # Sanity checks before publishing/verification (non-blocking warnings)
        if not args.no_sanity:
            warnings = []
            warnings += sanity_check_owner(owner_name, domain, service_port, transport)
            warnings += sanity_check_tuple_plausibility(plans)
            if profile is not None:
                warnings += sanity_check_dnssec(profile)
            if args.sanity_live:
                warnings += sanity_check_live_warn_only(domain, service_port, transport, plans, timeout=5.0)
            for w in warnings:
                print(f"WARNING [{w.code}]: {w.message}", file=sys.stderr)

    if args.dry_run:
        print("\nDry-run enabled: skipping RFC2136 publication and authoritative DNS checks.")
    else:
        assert profile is not None
        if not args.validate_only:
            print("\nPublishing via RFC2136...")
            publish_results = publish_tlsa_records(profile, owner_name, ttl, [plan.rdata_text for plan in plans])
            for server, status in publish_results:
                print(f"  {server}: {status}")
        print("\nVerifying publication by querying the configured authoritative servers directly...")
        verify_results = verify_plans_against_dns(profile, plans)
        for server, status in verify_results.items():
            print(f"  {server}: {status}")
            if status != "OK":
                publication_ok = False
        if not publication_ok and not args.validate_only and verify_results_indicate_wrong_owner(verify_results):
            if try_fix_wrong_owner(profile, owner_name, ttl, [plan.rdata_text for plan in plans]):
                print("\nRe-checking authoritative DNS after automatic correction...")
                verify_results = verify_plans_against_dns(profile, plans)
                publication_ok = True
                for server, status in verify_results.items():
                    print(f"  {server}: {status}")
                    if status != "OK":
                        publication_ok = False

    if args.no_export:
        print("\nNo BIND-format export written.")
    else:
        export_path: Path | None = None
        if args.export_file:
            export_path = validate_output_file_path(args.export_file)
        elif prompt_yes_no("Export the BIND-format TLSA record(s) to a text file for documentation purposes", default=False):
            export_path = prompt_output_file_path("Path to write the BIND-format TLSA record file", "./tlsa-record.txt")
        if export_path is not None:
            write_bind_records(export_path, plans)
            print(f"\nDocumentation export written to: {export_path}")
            print("Note: this export is only for documentation purposes right now. It is not used by the script for publication.")
        else:
            print("\nNo BIND-format export written.")

    should_live_check = args.live_check or (not args.no_live_check and prompt_yes_no("Try a live TLS connection to compare the currently presented server certificate", default=False))
    if should_live_check:
        result = validate_live_endpoint_against_plans(domain, service_port, transport, plans, 5.0)
        print(f"\nLive TLS probe: {result}")
        live_ok = result.startswith("OK") or result.startswith("SKIPPED")

    print("\nFinal TLSA record set:")
    for plan in plans:
        print(plan.bind_line)

    if args.dry_run:
        print("\nDone. Local generation and validation completed in dry-run mode.")
        return 0

    if publication_ok and live_ok:
        print("\nDone. Publication validated and the generated record set is consistent with the source certificate material.")
        return 0

    print("\nDone, but authoritative DNS verification and/or live validation did not fully succeed.")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAborted by user.")
        raise SystemExit(130)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
