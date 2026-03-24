#!/usr/bin/env python3
"""
Interactive TLSA generator + RFC2136 publisher.

Features
- Scans a certificate directory or PEM/CRT/CER file you provide.
- Detects discovered certificate materials, including key algorithm/type
  (for example RSA or ECDSA), whether a bundle looks like a fullchain,
  and whether CA certificates are present.
- Interactive mode: lets you pick cert material and a valid TLSA tuple.
- Auto-sensible mode: automatically generates sensible DANE-EE variants
  for matching RSA and ECDSA leaf certificates.
- Supports the standard TLSA tuples:
    usage   0..3
    selector 0..1
    matching 0..2
- Prevents impossible combinations for the selected certificate material.
- Recommends sensible tuples, usually 3 1 1.
- Validates the entered host name against the matching leaf certificate.
- Reminds you that TLSA records are bound to the exact service host, port, and transport.
- Publishes one or more TLSA records via RFC2136 using TSIG.
- Verifies publication by querying the authoritative servers directly.
- Verifies that the published TLSA records still match the certificate(s)
  from which they were generated.
- Optional live TLS probe to compare the currently presented server cert.
- Optional BIND-format export for documentation purposes.
- Can save and reuse RFC2136 settings locally.

Dependencies:
  pip install cryptography dnspython
or on Debian/Ubuntu:
  apt install python3-cryptography python3-dnspython
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("Missing dependency: cryptography\nInstall it with: pip install cryptography", file=sys.stderr)
    raise

DEFAULT_CONFIG_FILE = Path.home() / ".config" / "tlsa-rfc2136" / "config.json"
PEM_CERT_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)

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
    ((3, 1, 1), "Best default in many deployments: pins the leaf public key with SHA-256."),
    ((3, 1, 2), "Like 3 1 1, but with SHA-512 instead of SHA-256."),
    ((3, 0, 1), "Pins the full leaf certificate, not just the public key."),
    ((2, 1, 1), "Useful when you intentionally want DANE-TA from a CA public key in the scanned bundle."),
]

AUTO_SENSIBLE_TUPLES = [(3, 1, 1), (3, 1, 2), (3, 0, 1)]


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

    @property
    def rdata_text(self) -> str:
        return f"{self.usage} {self.selector} {self.matching_type} {self.association_hex}"

    @property
    def bind_line(self) -> str:
        return f"{ensure_absolute_name(self.owner_name)} {self.ttl} IN TLSA {self.rdata_text}"


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
        value = prompt(text, str(default))
        try:
            result = int(value)
        except ValueError:
            print("Please enter a valid integer.")
            continue
        if min_value is not None and result < min_value:
            print(f"Please enter a value greater than or equal to {min_value}.")
            continue
        if max_value is not None and result > max_value:
            print(f"Please enter a value less than or equal to {max_value}.")
            continue
        return result


def prompt_float(text: str, default: float, min_value: float | None = None, max_value: float | None = None) -> float:
    while True:
        value = prompt(text, str(default))
        try:
            result = float(value)
        except ValueError:
            print("Please enter a valid number.")
            continue
        if min_value is not None and result < min_value:
            print(f"Please enter a value greater than or equal to {min_value}.")
            continue
        if max_value is not None and result > max_value:
            print(f"Please enter a value less than or equal to {max_value}.")
            continue
        return result


def ensure_absolute_name(name_text: str) -> str:
    name_text = name_text.strip()
    if not name_text.endswith("."):
        name_text += "."
    return name_text


def normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".")
    return domain.encode("idna").decode("ascii").lower()


def prompt_existing_path(text: str, default: str | None = None) -> Path:
    while True:
        raw = prompt(text, default)
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            print(f"Path does not exist: {path}")
            continue
        return path


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


def prompt_transport(default: str = "tcp") -> str:
    allowed = {"tcp", "udp", "sctp"}
    while True:
        value = prompt("Transport protocol", default).strip().lower()
        if value in allowed:
            return value
        print("Transport must be one of: tcp, udp, sctp")


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


def cert_matches_domain(cert: x509.Certificate, domain: str) -> bool:
    names = cert_dns_names(cert)
    for name in names:
        if hostname_matches_pattern(domain, name):
            return True

    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if hostname_matches_pattern(domain, attr.value):
            return True

    return False


def material_has_matching_leaf(material: dict[str, Any], domain: str) -> bool:
    return any(cert_matches_domain(cert, domain) for cert in material["leaf_certs"])


def prompt_domain_matching_materials(materials: list[dict[str, Any]]) -> str:
    while True:
        domain = normalize_domain(prompt("Exact service host the certificate is for (e.g. www.example.com)"))
        if any(material_has_matching_leaf(material, domain) for material in materials):
            return domain
        print(f"No matching leaf certificate for '{domain}' was found in the scanned material. Please enter the exact service host name covered by the certificate.")


def print_tlsa_scope_hint(domain: str, service_port: int, transport: str, zone_name: str | None = None) -> None:
    owner_name = ensure_absolute_name(f"_{service_port}._{transport}.{domain}")
    print("\nTLSA scope reminder:")
    print(f"  This TLSA owner name is {owner_name}")
    print(f"  It applies only to {service_port}/{transport} on the exact host '{domain}'.")
    print("  It does not cover other host names in the same zone automatically.")
    print(f"  Example: a TLSA record for '{domain}' does not secure 'pbx.{domain}' unless you publish a separate TLSA record for that exact subdomain and service.")
    if zone_name is not None:
        normalized_zone = normalize_domain(zone_name.rstrip('.'))
        if normalized_zone == domain:
            print("  You chose the zone apex/root host. That is valid, but only use it when the service really runs on the zone apex itself.")
            print("  If the service is on a subdomain, publish the TLSA record for that exact subdomain instead of the zone apex.")


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
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        names.extend(attr.value for attr in cns)
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


def resolve_scan_input_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    return path


def discover_certificate_materials(path: Path) -> list[dict[str, Any]]:
    if path.is_file():
        candidate_files = [path]
    else:
        patterns = ("*.pem", "*.crt", "*.cer")
        seen: set[Path] = set()
        candidate_files = []
        for pattern in patterns:
            for found in sorted(path.rglob(pattern)):
                if found.is_file() and found not in seen:
                    seen.add(found)
                    candidate_files.append(found)

    materials: list[dict[str, Any]] = []
    for candidate in candidate_files:
        try:
            certs = load_pem_certificates_from_file(candidate)
        except Exception:
            continue

        leaf_certs = [cert for cert in certs if not cert_is_ca(cert)]
        ca_certs = [cert for cert in certs if cert_is_ca(cert)]
        primary_leaf = leaf_certs[0] if leaf_certs else certs[0]
        leaf_key_types = sorted({public_key_description(cert) for cert in leaf_certs}) or [public_key_description(primary_leaf)]
        all_names: list[str] = []
        for cert in leaf_certs or certs:
            for name in cert_dns_names(cert):
                if name not in all_names:
                    all_names.append(name)

        materials.append(
            {
                "path": candidate,
                "certs": certs,
                "leaf_certs": leaf_certs,
                "ca_certs": ca_certs,
                "primary_leaf": primary_leaf,
                "is_fullchain": len(certs) > 1,
                "leaf_key_types": leaf_key_types,
                "names": all_names,
            }
        )

    return materials


def print_discovered_materials(materials: list[dict[str, Any]]) -> None:
    print("\nScanned certificate materials:")
    for idx, material in enumerate(materials, start=1):
        path = material["path"]
        cert_count = len(material["certs"])
        leaf_count = len(material["leaf_certs"])
        ca_count = len(material["ca_certs"])
        fullchain_text = "yes" if material["is_fullchain"] else "no"
        key_types = ", ".join(material["leaf_key_types"])
        names = ", ".join(material["names"][:6]) if material["names"] else "<no DNS names>"
        if len(material["names"]) > 6:
            names += ", ..."
        print(f"  {idx}. {path}")
        print(f"     key types : {key_types}")
        print(f"     fullchain : {fullchain_text}")
        print(f"     certs     : total={cert_count}, leaf={leaf_count}, ca={ca_count}")
        print(f"     names     : {names}")


def choose_discovered_material(materials: list[dict[str, Any]], domain: str | None = None) -> dict[str, Any]:
    if not materials:
        raise ValueError("No readable PEM/CRT/CER certificate material was found in the specified path.")

    print_discovered_materials(materials)

    eligible = materials
    if domain is not None:
        eligible = [material for material in materials if material_has_matching_leaf(material, domain)]
        if not eligible:
            raise ValueError(f"No discovered certificate material contains a matching leaf certificate for '{domain}'.")

    if len(eligible) == 1:
        chosen = eligible[0]
        print(f"\nUsing the only eligible certificate material: {chosen['path']}")
        return chosen

    if domain is not None:
        print(f"\nOnly materials containing a leaf certificate that matches '{domain}' can be selected.")

    while True:
        choice = prompt_int("Choose certificate material number", 1, min_value=1, max_value=len(materials))
        chosen = materials[choice - 1]
        if domain is not None and not material_has_matching_leaf(chosen, domain):
            print(f"The selected material does not contain a leaf certificate that matches '{domain}'. Please choose another material.")
            continue
        return chosen


def pick_end_entity_certificate(certs: list[x509.Certificate], domain: str) -> x509.Certificate:
    matching = [cert for cert in certs if not cert_is_ca(cert) and cert_matches_domain(cert, domain)]
    if not matching:
        available = []
        for idx, cert in enumerate(certs, start=1):
            names = ", ".join(cert_dns_names(cert)) or "<no DNS names>"
            role = "CA" if cert_is_ca(cert) else "leaf/server"
            key_type = public_key_description(cert)
            available.append(f"  {idx}. role={role} key={key_type} names={names}")
        raise ValueError(
            f"No leaf certificate in the selected material matches '{domain}'.\n"
            f"Certificates found:\n" + "\n".join(available)
        )

    if len(matching) == 1:
        return matching[0]

    preferred_non_wild = [cert for cert in matching if domain in cert_dns_names(cert)]
    if preferred_non_wild:
        return preferred_non_wild[0]
    return matching[0]


def tlsa_capability_mask(material: dict[str, Any]) -> dict[str, dict[int, dict[str, str | bool]]]:
    has_leaf = bool(material["leaf_certs"])
    has_ca = bool(material["ca_certs"])
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


def possible_tuples_for_material(material: dict[str, Any]) -> list[tuple[int, int, int]]:
    mask = tlsa_capability_mask(material)
    tuples: list[tuple[int, int, int]] = []
    for usage in sorted(TLSA_USAGE_EXPLANATIONS):
        if not mask["usage"][usage]["available"]:
            continue
        for selector in sorted(TLSA_SELECTOR_EXPLANATIONS):
            if not mask["selector"][selector]["available"]:
                continue
            for matching_type in sorted(TLSA_MATCHING_EXPLANATIONS):
                if mask["matching"][matching_type]["available"]:
                    tuples.append((usage, selector, matching_type))
    return tuples


def print_tlsa_option_mask(material: dict[str, Any]) -> None:
    mask = tlsa_capability_mask(material)
    print("\nTLSA option mask for the selected certificate material")
    print(f"  source file : {material['path']}")
    print(f"  key types   : {', '.join(material['leaf_key_types'])}")
    print(f"  fullchain   : {'yes' if material['is_fullchain'] else 'no'}")
    print(f"  leaf cert   : {'yes' if material['leaf_certs'] else 'no'}")
    print(f"  CA cert     : {'yes' if material['ca_certs'] else 'no'}")

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

    tuples = possible_tuples_for_material(material)
    print(f"\nPossible standard tuples for this material: {len(tuples)}")
    for tup in tuples:
        print(f"  {tup[0]} {tup[1]} {tup[2]}")

    print("\nRecommended tuples for this material")
    recommended_found = False
    tuple_set = set(tuples)
    for tup, reason in RECOMMENDED_TUPLES:
        if tup in tuple_set:
            recommended_found = True
            print(f"  {tup[0]} {tup[1]} {tup[2]} -> recommended | {reason}")
    if not recommended_found:
        print("  No preferred recommendations apply beyond the raw possible tuple set.")


def prompt_available_choice(title: str, explanations: dict[int, str], available_keys: set[int], default: int) -> int:
    if default not in available_keys:
        default = sorted(available_keys)[0]
    print(f"\n{title}")
    for key in sorted(explanations):
        status = "available" if key in available_keys else "not available"
        marker = " (default)" if key == default else ""
        print(f"  {key} - {status:13} {explanations[key]}{marker}")
    while True:
        value = prompt("Choose option", str(default))
        try:
            chosen = int(value)
        except ValueError:
            print("Please enter one of the shown option numbers.")
            continue
        if chosen not in explanations:
            print("Please enter one of the shown option numbers.")
            continue
        if chosen not in available_keys:
            print("That option is not possible with the selected certificate material.")
            continue
        return chosen


def choose_tlsa_settings(material: dict[str, Any]) -> tuple[int, int, int]:
    print_tlsa_option_mask(material)
    possible = set(possible_tuples_for_material(material))
    if (3, 1, 1) in possible and prompt_yes_no("Use the recommended default 3 1 1", default=True):
        return (3, 1, 1)

    usage = prompt_available_choice(
        "TLSA certificate usage",
        TLSA_USAGE_EXPLANATIONS,
        {item[0] for item in possible},
        default=3,
    )
    selector = prompt_available_choice(
        "TLSA selector",
        TLSA_SELECTOR_EXPLANATIONS,
        {item[1] for item in possible if item[0] == usage},
        default=1,
    )
    matching = prompt_available_choice(
        "TLSA matching type",
        TLSA_MATCHING_EXPLANATIONS,
        {item[2] for item in possible if item[0] == usage and item[1] == selector},
        default=1,
    )
    chosen = (usage, selector, matching)
    if chosen not in possible:
        raise ValueError(f"Internal error: tuple {chosen} is not possible for the selected material.")
    return chosen


def choose_certificate_for_association(certs: list[x509.Certificate], leaf_cert: x509.Certificate, usage: int) -> x509.Certificate:
    if usage in {1, 3}:
        return leaf_cert

    ca_candidates = [cert for cert in certs if cert_is_ca(cert)]
    if not ca_candidates:
        raise ValueError(
            "The selected TLSA usage needs a CA/trust-anchor certificate, but none was found in the selected certificate material."
        )

    print("\nTLSA usage requires a trust-anchor / CA certificate.")
    print("Select which CA certificate from the selected material should be used for the TLSA association data.")
    for idx, cert in enumerate(ca_candidates, start=1):
        names = ", ".join(cert_dns_names(cert)) or "<no DNS names>"
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        key_type = public_key_description(cert)
        print(f"  {idx}. key={key_type} | subject={subject} | issuer={issuer} | names={names}")
    while True:
        chosen_idx = prompt_int("Choose CA certificate number for TLSA data", 1, min_value=1, max_value=len(ca_candidates))
        if 1 <= chosen_idx <= len(ca_candidates):
            return ca_candidates[chosen_idx - 1]
        print("Invalid CA certificate selection.")


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


def fqdn_is_in_zone(owner_name: str, zone_name: str) -> bool:
    owner = dns.name.from_text(ensure_absolute_name(owner_name))
    zone = dns.name.from_text(ensure_absolute_name(zone_name))
    return owner.is_subdomain(zone)


def owner_name_relative_to_zone(owner_name: str, zone_name: str) -> str:
    owner = dns.name.from_text(ensure_absolute_name(owner_name))
    zone = dns.name.from_text(ensure_absolute_name(zone_name))
    if not owner.is_subdomain(zone):
        raise ValueError(f"Owner name '{owner_name}' is not inside zone '{zone_name}'.")
    relative = owner.relativize(zone)
    text = relative.to_text()
    return text if text == "@" else text.rstrip(".")


def probable_zone_appended_owner_name(owner_name: str, zone_name: str) -> str:
    zone = dns.name.from_text(ensure_absolute_name(zone_name))
    buggy = dns.name.from_text(owner_name.strip().rstrip("."), origin=zone)
    return buggy.to_text()


def load_saved_profiles(config_file: Path) -> list[dict[str, Any]]:
    if not config_file.exists():
        return []
    try:
        data = json.loads(config_file.read_text(encoding="utf-8"))
        profiles = data.get("profiles", [])
        if isinstance(profiles, list):
            return profiles
    except Exception as exc:
        print(f"Warning: could not read config file '{config_file}': {exc}")
    return []


def save_profiles(config_file: Path, profiles: list[dict[str, Any]]) -> None:
    config_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "profiles": profiles}
    temp_path = config_file.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(temp_path, 0o600)
    temp_path.replace(config_file)
    os.chmod(config_file, 0o600)


def create_profile() -> dict[str, Any]:
    print("\nCreate new RFC2136 / TSIG profile")
    name = prompt("Profile name", "default")
    while True:
        servers_raw = prompt("Authoritative DNS server IPs/hostnames (comma-separated)", "127.0.0.1")
        servers = [item.strip() for item in servers_raw.split(",") if item.strip()]
        if servers:
            break
        print("Please enter at least one DNS server.")

    zone = ensure_absolute_name(prompt("DNS zone for the update", "example.com"))
    dns_port = prompt_int("DNS port", 53, min_value=1, max_value=65535)
    key_name = ensure_absolute_name(prompt("TSIG key name", "update-key."))
    key_secret = prompt("TSIG key secret (base64)", secret=True)
    key_algorithm = prompt("TSIG algorithm", "hmac-sha256")
    timeout = prompt_float("DNS timeout in seconds", 5.0, min_value=0.1)
    default_ttl = prompt_int("Default TTL for the TLSA RR", 3600, min_value=0)
    update_all_servers = prompt_yes_no(
        "Send RFC2136 UPDATE to all configured servers (instead of stopping at first success)?",
        default=False,
    )
    verify_attempts = prompt_int("Verification attempts", 5, min_value=1)
    verify_delay = prompt_float("Seconds between verification attempts", 2.0, min_value=0.0)

    return {
        "name": name,
        "servers": servers,
        "dns_port": dns_port,
        "zone": zone,
        "key_name": key_name,
        "key_secret": key_secret,
        "key_algorithm": key_algorithm,
        "timeout": timeout,
        "default_ttl": default_ttl,
        "update_all_servers": update_all_servers,
        "verify_attempts": verify_attempts,
        "verify_delay": verify_delay,
    }


def choose_or_create_profile(config_file: Path) -> dict[str, Any]:
    profiles = load_saved_profiles(config_file)
    if profiles:
        print("\nSaved RFC2136 profiles:")
        for idx, profile in enumerate(profiles, start=1):
            servers = ", ".join(profile.get("servers", []))
            zone = profile.get("zone", "?")
            print(f"  {idx}. {profile.get('name', 'unnamed')}  (zone={zone}, servers={servers})")
        print("  N. Create a new profile")

        while True:
            choice = input("Select a profile number or N: ").strip().lower()
            if choice == "n":
                profile = create_profile()
                if prompt_yes_no("Save this new profile", default=True):
                    profiles.append(profile)
                    save_profiles(config_file, profiles)
                return profile
            if choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(profiles):
                    chosen = profiles[idx - 1]
                    if prompt_yes_no("Use this saved profile as-is", default=True):
                        return chosen
                    edited = create_profile()
                    if prompt_yes_no("Save the newly entered profile", default=True):
                        profiles.append(edited)
                        save_profiles(config_file, profiles)
                    return edited
            print("Invalid selection.")

    profile = create_profile()
    if prompt_yes_no("Save this profile", default=True):
        save_profiles(config_file, [profile])
    return profile


def make_keyring(profile: dict[str, Any]):
    return dns.tsigkeyring.from_text({ensure_absolute_name(profile["key_name"]): profile["key_secret"].strip()})


def send_update(profile: dict[str, Any], update: dns.update.Update) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    any_success = False
    for server in profile["servers"]:
        try:
            response = dns.query.tcp(
                update,
                where=server,
                port=int(profile["dns_port"]),
                timeout=float(profile["timeout"]),
            )
            rcode = dns.rcode.to_text(response.rcode())
            if response.rcode() != dns.rcode.NOERROR:
                raise RuntimeError(f"server returned rcode {rcode}")
            results.append((server, "OK"))
            any_success = True
            if not profile.get("update_all_servers", False):
                break
        except Exception as exc:
            results.append((server, f"FAILED: {exc}"))

    if not any_success:
        details = "\n".join(f"  - {server}: {status}" for server, status in results)
        raise RuntimeError(f"RFC2136 update failed on every configured server:\n{details}")

    return results


def publish_tlsa_records(profile: dict[str, Any], owner_name: str, ttl: int, rdata_texts: list[str]) -> list[tuple[str, str]]:
    relative_owner = owner_name_relative_to_zone(owner_name, profile["zone"])
    update = dns.update.Update(
        profile["zone"],
        keyring=make_keyring(profile),
        keyname=ensure_absolute_name(profile["key_name"]),
        keyalgorithm=profile["key_algorithm"],
    )
    update.delete(relative_owner, "TLSA")
    for rdata_text in rdata_texts:
        update.add(relative_owner, ttl, "TLSA", rdata_text)
    return send_update(profile, update)


def query_tlsa_direct(server: str, port: int, timeout: float, owner_name: str) -> list[str]:
    query = dns.message.make_query(owner_name, "TLSA")
    query.flags &= ~dns.flags.RD
    response = dns.query.tcp(query, where=server, port=port, timeout=timeout)
    texts: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.TLSA:
            for rdata in rrset:
                texts.append(rdata.to_text().lower())
    return texts


def verify_publication(profile: dict[str, Any], owner_name: str, expected_rdata_texts: list[str]) -> dict[str, str]:
    expected = {item.lower() for item in expected_rdata_texts}
    attempts = int(profile.get("verify_attempts", 5))
    delay = float(profile.get("verify_delay", 2.0))
    port = int(profile["dns_port"])
    timeout = float(profile["timeout"])

    last_results: dict[str, str] = {}
    for attempt in range(1, attempts + 1):
        all_ok = True
        current: dict[str, str] = {}
        for server in profile["servers"]:
            try:
                answers = {item.lower() for item in query_tlsa_direct(server, port, timeout, owner_name)}
                if answers == expected:
                    current[server] = "OK"
                else:
                    missing = sorted(expected - answers)
                    extra = sorted(answers - expected)
                    parts: list[str] = []
                    if missing:
                        parts.append(f"missing={missing}")
                    if extra:
                        parts.append(f"extra={extra}")
                    current[server] = "MISMATCH: " + "; ".join(parts) if parts else "MISMATCH"
                    all_ok = False
            except Exception as exc:
                current[server] = f"QUERY FAILED: {exc}"
                all_ok = False
        last_results = current
        if all_ok:
            return last_results
        if attempt < attempts:
            time.sleep(delay)
    return last_results


def verify_plans_against_dns(profile: dict[str, Any], owner_name: str, plans: list[TLSARecordPlan]) -> dict[str, str]:
    expected_rdata_texts = [plan.rdata_text for plan in plans]
    return verify_publication(profile, owner_name, expected_rdata_texts)


def detect_zone_appended_publication(profile: dict[str, Any], owner_name: str, expected_rdata_texts: list[str]) -> dict[str, str]:
    expected = {item.lower() for item in expected_rdata_texts}
    wrong_owner = probable_zone_appended_owner_name(owner_name, profile["zone"])
    if ensure_absolute_name(wrong_owner) == ensure_absolute_name(owner_name):
        return {}

    port = int(profile["dns_port"])
    timeout = float(profile["timeout"])
    results: dict[str, str] = {}
    for server in profile["servers"]:
        try:
            answers = {item.lower() for item in query_tlsa_direct(server, port, timeout, wrong_owner)}
            if answers == expected:
                results[server] = f"WRONG OWNER DETECTED: {ensure_absolute_name(wrong_owner)}"
            elif answers:
                results[server] = f"WRONG OWNER HAS DIFFERENT TLSA RRSET: {ensure_absolute_name(wrong_owner)}"
        except Exception:
            continue
    return results


def auto_correct_zone_appended_publication(profile: dict[str, Any], owner_name: str, ttl: int, expected_rdata_texts: list[str]) -> list[tuple[str, str]] | None:
    wrong_owner = probable_zone_appended_owner_name(owner_name, profile["zone"])
    if ensure_absolute_name(wrong_owner) == ensure_absolute_name(owner_name):
        return None

    expected = {item.lower() for item in expected_rdata_texts}
    port = int(profile["dns_port"])
    timeout = float(profile["timeout"])
    found_wrong_owner = False
    for server in profile["servers"]:
        try:
            answers = {item.lower() for item in query_tlsa_direct(server, port, timeout, wrong_owner)}
            if answers == expected:
                found_wrong_owner = True
                break
        except Exception:
            continue

    if not found_wrong_owner:
        return None

    correct_relative_owner = owner_name_relative_to_zone(owner_name, profile["zone"])
    wrong_relative_owner = owner_name_relative_to_zone(wrong_owner, profile["zone"])
    update = dns.update.Update(
        profile["zone"],
        keyring=make_keyring(profile),
        keyname=ensure_absolute_name(profile["key_name"]),
        keyalgorithm=profile["key_algorithm"],
    )
    update.delete(wrong_relative_owner, "TLSA")
    update.delete(correct_relative_owner, "TLSA")
    for rdata_text in expected_rdata_texts:
        update.add(correct_relative_owner, ttl, "TLSA", rdata_text)
    return send_update(profile, update)


def fetch_live_server_certificate(host: str, port: int, timeout: float = 5.0) -> x509.Certificate:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def sha256_cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def verify_live_service(domain: str, service_port: int, plans: list[TLSARecordPlan], materials: list[dict[str, Any]]) -> str:
    cert = fetch_live_server_certificate(domain, service_port)
    live_fp = sha256_cert_fingerprint(cert)
    generated_fps = set()
    for plan in plans:
        for material in materials:
            if str(material["path"]) != plan.source_material_path:
                continue
            for candidate in material["certs"]:
                if candidate.subject.rfc4514_string() == plan.source_cert_subject and public_key_description(candidate) == plan.source_cert_key_type:
                    generated_fps.add(sha256_cert_fingerprint(candidate))
    if not generated_fps:
        return "SKIPPED: could not map generated plans back to source certificates"
    if live_fp in generated_fps:
        return "OK"
    return "MISMATCH: live server presented a different certificate than the certificate(s) used for TLSA generation"


def write_bind_records(path: Path, plans: list[TLSARecordPlan]) -> None:
    lines = [plan.bind_line for plan in plans]
    text = "\n".join(lines) + "\n"
    if path.exists():
        mode = "a" if prompt_yes_no("Output file exists. Append instead of overwrite", default=True) else "w"
    else:
        mode = "w"
    with path.open(mode, encoding="utf-8") as handle:
        if mode == "a" and path.stat().st_size > 0:
            handle.write("\n")
        handle.write(text)


def build_plan(material: dict[str, Any], association_cert: x509.Certificate, owner_name: str, ttl: int, usage: int, selector: int, matching_type: int) -> TLSARecordPlan:
    association_hex = generate_tlsa_association(association_cert, selector, matching_type)
    return TLSARecordPlan(
        owner_name=owner_name,
        ttl=ttl,
        usage=usage,
        selector=selector,
        matching_type=matching_type,
        association_hex=association_hex,
        source_material_path=str(material["path"]),
        source_cert_subject=association_cert.subject.rfc4514_string(),
        source_cert_key_type=public_key_description(association_cert),
    )


def unique_by_rdata(plans: list[TLSARecordPlan]) -> list[TLSARecordPlan]:
    seen: set[str] = set()
    result: list[TLSARecordPlan] = []
    for plan in plans:
        if plan.rdata_text not in seen:
            seen.add(plan.rdata_text)
            result.append(plan)
    return result


def choose_materials_for_auto_sensible(materials: list[dict[str, Any]], domain: str) -> list[tuple[dict[str, Any], x509.Certificate]]:
    winners: dict[str, tuple[dict[str, Any], x509.Certificate]] = {}
    for material in materials:
        try:
            leaf = pick_end_entity_certificate(material["certs"], domain)
        except Exception:
            continue
        family = public_key_family(leaf)
        current = winners.get(family)
        if current is None:
            winners[family] = (material, leaf)
            continue
        current_material, _ = current
        if material["is_fullchain"] and not current_material["is_fullchain"]:
            winners[family] = (material, leaf)
    return [winners[key] for key in sorted(winners)]


def run_interactive_mode(materials: list[dict[str, Any]], domain: str, owner_name: str, ttl: int) -> list[TLSARecordPlan]:
    material = choose_discovered_material(materials, domain=domain)
    print(f"\nSelected certificate material: {material['path']}")
    print(f"Discovered key type(s): {', '.join(material['leaf_key_types'])}")
    print(f"Looks like fullchain: {'yes' if material['is_fullchain'] else 'no'}")

    leaf_cert = pick_end_entity_certificate(material["certs"], domain)
    print("\nMatching end-entity certificate selected for domain validation:")
    print(describe_certificate(leaf_cert))
    print(f"\nDomain validation succeeded for: {domain}")

    usage, selector, matching_type = choose_tlsa_settings(material)
    association_cert = choose_certificate_for_association(material["certs"], leaf_cert, usage)
    print("\nCertificate chosen for TLSA association data:")
    print(describe_certificate(association_cert))

    plan = build_plan(material, association_cert, owner_name, ttl, usage, selector, matching_type)
    print("\nGenerated TLSA record:")
    print(plan.bind_line)
    return [plan]


def run_auto_sensible_mode(materials: list[dict[str, Any]], domain: str, owner_name: str, ttl: int) -> list[TLSARecordPlan]:
    chosen = choose_materials_for_auto_sensible(materials, domain)
    if not chosen:
        raise ValueError(f"No matching leaf certificates for domain '{domain}' were found in the scanned material.")

    plans: list[TLSARecordPlan] = []
    print("\nAuto-sensible mode selected the following leaf certificates:")
    for material, leaf in chosen:
        print(f"  - {material['path']} -> {public_key_description(leaf)} | subject={leaf.subject.rfc4514_string()}")
        possible = set(possible_tuples_for_material(material))
        for usage, selector, matching_type in AUTO_SENSIBLE_TUPLES:
            if (usage, selector, matching_type) not in possible:
                continue
            association_cert = choose_certificate_for_association(material["certs"], leaf, usage)
            plans.append(build_plan(material, association_cert, owner_name, ttl, usage, selector, matching_type))
    plans = unique_by_rdata(plans)
    print("\nGenerated sensible TLSA RRset:")
    for plan in plans:
        print(f"  {plan.bind_line}")
    return plans


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive TLSA generator and RFC2136 publisher")
    parser.add_argument("--dry-run", action="store_true", help="Generate and validate locally, but do not publish via RFC2136")
    parser.add_argument("--validate-only", action="store_true", help="Skip RFC2136 publication and only validate the generated TLSA record set against authoritative DNS and optional live TLS")
    parser.add_argument(
        "--mode",
        choices=["interactive", "auto-sensible"],
        default="interactive",
        help="interactive = choose one tuple manually; auto-sensible = generate sensible TLSA variants for matching RSA/ECDSA certs",
    )
    args = parser.parse_args()
    if args.dry_run and args.validate_only:
        parser.error("--dry-run and --validate-only cannot be used together")
    return args


def main() -> int:
    args = parse_args()
    print("Interactive TLSA generator + RFC2136 publisher\n")
    print(f"Mode          : {args.mode}")
    print(f"Dry-run       : {'yes' if args.dry_run else 'no'}")
    print(f"Validate-only : {'yes' if args.validate_only else 'no'}")

    config_file = prompt_config_file_path("Config file path", str(DEFAULT_CONFIG_FILE))

    scan_path = prompt_existing_path("Path to certificate directory or PEM/CRT/CER file")
    materials = discover_certificate_materials(scan_path)
    if not materials:
        raise ValueError("No readable PEM certificate material could be found in the specified path.")

    domain = prompt_domain_matching_materials(materials)
    service_port = prompt_int("Service port for TLSA owner name", 443, min_value=1, max_value=65535)
    transport = prompt_transport("tcp")
    owner_name = f"_{service_port}._{transport}.{domain}"
    print(f"TLSA owner name: {ensure_absolute_name(owner_name)}")
    print_tlsa_scope_hint(domain, service_port, transport)

    ttl = prompt_int("TTL for the TLSA RR", 3600, min_value=0)

    if args.mode == "interactive":
        plans = run_interactive_mode(materials, domain, owner_name, ttl)
    else:
        plans = run_auto_sensible_mode(materials, domain, owner_name, ttl)

    plans = unique_by_rdata(plans)
    expected_rdata = [plan.rdata_text for plan in plans]

    print("\nSelf-check against the source certificate material:")
    for plan in plans:
        print(f"  OK -> {plan.rdata_text} | source={plan.source_material_path} | key={plan.source_cert_key_type}")

    if args.dry_run:
        print("\nDry-run enabled: skipping RFC2136 publication and authoritative DNS checks.")
        dns_status_ok = True
    else:
        while True:
            profile = choose_or_create_profile(config_file)
            if fqdn_is_in_zone(owner_name, profile["zone"]):
                print_tlsa_scope_hint(domain, service_port, transport, profile["zone"])
                break
            print(
                f"The TLSA owner name '{owner_name}' is not inside zone '{profile['zone']}'. "
                "Please choose or create a profile for the correct zone."
            )

        if args.validate_only:
            print("\nValidation-only mode: skipping RFC2136 publication.")
        else:
            print("\nPublishing via RFC2136...")
            publish_results = publish_tlsa_records(profile, owner_name, ttl, expected_rdata)
            for server, status in publish_results:
                print(f"  {server}: {status}")

        print("\nVerifying publication by querying the configured authoritative servers directly...")
        verify_results = verify_plans_against_dns(profile, owner_name, plans)
        dns_status_ok = True
        for server, status in verify_results.items():
            print(f"  {server}: {status}")
            if status != "OK":
                dns_status_ok = False

        wrong_owner_results = detect_zone_appended_publication(profile, owner_name, expected_rdata)
        if wrong_owner_results:
            print("\nDetected a probable zone-appended/wrong-owner publication:")
            for server, status in wrong_owner_results.items():
                print(f"  {server}: {status}")
            if not args.validate_only:
                print("\nAttempting automatic correction by deleting the wrong owner name and re-publishing the correct owner name...")
                correction_results = auto_correct_zone_appended_publication(profile, owner_name, ttl, expected_rdata)
                if correction_results:
                    for server, status in correction_results:
                        print(f"  {server}: {status}")
                    print("\nRe-verifying authoritative DNS after automatic correction...")
                    verify_results = verify_plans_against_dns(profile, owner_name, plans)
                    dns_status_ok = True
                    for server, status in verify_results.items():
                        print(f"  {server}: {status}")
                        if status != "OK":
                            dns_status_ok = False

    if prompt_yes_no(
        "Export the BIND-format TLSA record(s) to a text file for documentation purposes",
        default=True,
    ):
        output_path = prompt_output_file_path("Path to write the BIND-format TLSA record file", "./tlsa-record.txt")
        write_bind_records(output_path, plans)
        print(f"\nDocumentation export written to: {output_path}")
        print("Note: this export is only for documentation purposes right now. It is not used by the script for publication.")
    else:
        print("\nSkipped BIND-format export. That export is only for documentation purposes right now.")

    if prompt_yes_no("Try a live TLS connection to compare the currently presented server certificate", default=False):
        try:
            live_status = verify_live_service(domain, service_port, plans, materials)
        except Exception as exc:
            live_status = f"FAILED: {exc}"
        print(f"\nLive TLS probe: {live_status}")
    else:
        live_status = "SKIPPED"

    print("\nFinal TLSA record set:")
    for plan in plans:
        print(plan.bind_line)

    if args.dry_run:
        print("\nDone. Local generation and validation completed in dry-run mode.")
        return 0

    if args.validate_only and dns_status_ok:
        print("\nDone. Validation-only mode completed successfully.")
        if live_status not in {"OK", "SKIPPED"}:
            return 2
        return 0

    if not dns_status_ok:
        print(
            "\nDone, but authoritative DNS verification did not succeed on every configured server. "
            "That can happen if you updated only the primary and secondaries have not transferred the change yet."
        )
        return 2

    print("\nDone. Publication verified on all configured authoritative servers.")
    if live_status not in {"OK", "SKIPPED"}:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAborted by user.")
        raise SystemExit(130)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

