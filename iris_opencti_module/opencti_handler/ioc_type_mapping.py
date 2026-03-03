"""
Mapping from IRIS IOC type names to OpenCTI observable creation strategies.

Each entry describes how to translate an IRIS IOC into one or more
OpenCTI STIX Cyber Observables via pycti.

Strategies
----------
simple
    Uses ``simple_observable_key`` / ``simple_observable_value`` shorthand.
observable_data
    Builds an ``observableData`` dict (e.g. file hashes).
composite
    The IOC value contains multiple parts separated by ``|``.
    A ``parser`` callable splits the value and returns a list of
    ``(strategy, config, value)`` tuples to create individually.
"""

from __future__ import annotations

import re
from typing import Any


# ── Helper parsers for composite types ──────────────────────────

def _parse_ip_port(value: str) -> list[tuple[str, dict, str]]:
    """Strip the port from ``ip|port`` and return a single IP observable.

    Note: the port component is intentionally discarded because OpenCTI
    has no simple IP:port observable type.
    """
    ip_part = value.split("|")[0].strip()
    key = _detect_ip_version(ip_part)
    return [("simple", {"key": key}, ip_part)]


def _parse_domain_ip(value: str) -> list[tuple[str, dict, str]]:
    """Split ``domain|ip`` into two observables."""
    parts = value.split("|")
    if len(parts) != 2:
        return [("simple", {"key": "Domain-Name.value"}, value)]
    domain, ip = parts[0].strip(), parts[1].strip()
    ip_key = _detect_ip_version(ip)
    return [
        ("simple", {"key": "Domain-Name.value"}, domain),
        ("simple", {"key": ip_key}, ip),
    ]


def _parse_filename_hash(value: str, hash_algo: str) -> list[tuple[str, dict, str]]:
    """Split ``filename|hash`` into a file observable with both name and hash."""
    parts = value.split("|", 1)
    if len(parts) != 2:
        return [("simple", {"key": "File.name"}, value)]
    filename, hash_value = parts[0].strip(), parts[1].strip()
    return [(
        "observable_data",
        {"type": "file", "name": filename, "hashes": {_normalise_hash_name(hash_algo): hash_value}},
        value,
    )]


def _parse_hostname_port(value: str) -> list[tuple[str, dict, str]]:
    """Strip the port from ``hostname|port`` and return a single Hostname observable."""
    hostname = value.split("|")[0].strip()
    return [("simple", {"key": "Hostname.value"}, hostname)]


def _parse_regkey_value(value: str) -> list[tuple[str, dict, str]]:
    """Split ``regkey|value`` into a Windows-Registry-Key observable.

    The MISP format is ``HKLM\\Key\\Path|ValueName``.  OpenCTI accepts the
    registry key with an optional values list.
    """
    parts = value.split("|", 1)
    key_path = parts[0].strip()
    value_name = parts[1].strip() if len(parts) == 2 else None
    raw: dict[str, Any] = {"type": "windows-registry-key", "key": key_path}
    if value_name:
        raw["values"] = [{"name": value_name}]
    return [("observable_data_raw", {"builder": lambda _v, r=raw: r}, value)]


def _parse_filename_only(value: str) -> list[tuple[str, dict, str]]:
    """Extract just the filename from a ``filename|hash`` value.

    Used when the hash algorithm is not in OpenCTI\'s ``HashAlgorithm`` enum
    (SHA-224, SHA-384, SHA-512/224, SHA-512/256, SHA3-224, SHA3-384, TLSH,
    AUTHENTIHASH, ImpHash, ImpFuzzy, PEHASH, VHASH, TELFHASH, CDHASH).
    The hash portion is discarded to avoid a GraphQL validation failure;
    only the filename is pushed as a ``File.name`` observable.
    """
    filename = value.split("|")[0].strip()
    return [("simple", {"key": "File.name"}, filename)]


def _detect_ip_version(ip: str) -> str:
    """Return the appropriate simple_observable_key for an IP address."""
    if ":" in ip:
        return "IPv6-Addr.value"
    return "IPv4-Addr.value"


def _normalise_hash_name(algo: str) -> str:
    """Normalise hash algorithm names to the STIX 2.1 hash key format."""
    mapping = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha224": "SHA-224",
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
        "sha512/224": "SHA-512/224",
        "sha512/256": "SHA-512/256",
        "sha3-224": "SHA3-224",
        "sha3-256": "SHA3-256",
        "sha3-384": "SHA3-384",
        "sha3-512": "SHA3-512",
        "ssdeep": "SSDEEP",
        "tlsh": "TLSH",
        "authentihash": "AUTHENTIHASH",
        "impfuzzy": "ImpFuzzy",
        "imphash": "ImpHash",
        "pehash": "PEHASH",
        "vhash": "VHASH",
        "telfhash": "TELFHASH",
        "cdhash": "CDHASH",
    }
    return mapping.get(algo.lower(), algo.upper())


# ── Build a single-hash file observable_data ────────────────────

def _hash_observable(algo: str) -> dict:
    """Return a config dict for a file-hash observable_data strategy."""
    return {"hash_algo": algo}


# ── The mapping table ───────────────────────────────────────────

# Each value is a dict with:
#   strategy : "simple" | "observable_data" | "composite"
#   key      : simple_observable_key  (for "simple")
#   hash_algo: hash algorithm name    (for single hash observables)
#   parser   : callable(value) → list[(strategy, config, value)]  (for "composite")

IOC_TYPE_MAP: dict[str, dict[str, Any]] = {
    # ── IP addresses ────────────────────────────────────────────
    "ip-src": {"strategy": "simple", "key": "auto_ip"},
    "ip-dst": {"strategy": "simple", "key": "auto_ip"},
    "ip-src|port": {"strategy": "composite", "parser": _parse_ip_port},
    "ip-dst|port": {"strategy": "composite", "parser": _parse_ip_port},

    # ── Domains / Hostnames ─────────────────────────────────────
    "domain": {"strategy": "simple", "key": "Domain-Name.value"},
    "hostname": {"strategy": "simple", "key": "Hostname.value"},
    "domain|ip": {"strategy": "composite", "parser": _parse_domain_ip},

    # ── URLs ────────────────────────────────────────────────────
    "url": {"strategy": "simple", "key": "Url.value"},
    "uri": {"strategy": "simple", "key": "Url.value"},
    "link": {"strategy": "simple", "key": "Url.value"},

    # ── File hashes ─────────────────────────────────────────────
    # OpenCTI's HashAlgorithm enum (verified by live validation) accepts:
    # MD5, SHA-1, SHA-256, SHA-512, SSDEEP, SHA3-256, SHA3-512.
    # All other algorithms are rejected with a FUNCTIONAL_ERROR when submitted
    # as a StixFile hash; they fall back to Text.value below.
    "md5":        {"strategy": "observable_data", **_hash_observable("md5")},
    "sha1":       {"strategy": "observable_data", **_hash_observable("sha1")},
    "sha224":     {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "sha256":     {"strategy": "observable_data", **_hash_observable("sha256")},
    "sha384":     {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "sha512":     {"strategy": "observable_data", **_hash_observable("sha512")},
    "sha512/224": {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "sha512/256": {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "ssdeep":     {"strategy": "observable_data", **_hash_observable("ssdeep")},
    "tlsh":       {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "authentihash": {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum

    # ── Filenames ───────────────────────────────────────────────
    "filename": {"strategy": "simple", "key": "File.name"},
    "filename|md5": {
        "strategy": "composite",
        "parser": lambda v: _parse_filename_hash(v, "md5"),
    },
    "filename|sha1": {
        "strategy": "composite",
        "parser": lambda v: _parse_filename_hash(v, "sha1"),
    },
    "filename|sha256": {
        "strategy": "composite",
        "parser": lambda v: _parse_filename_hash(v, "sha256"),
    },
    "filename|sha512": {
        "strategy": "composite",
        "parser": lambda v: _parse_filename_hash(v, "sha512"),
    },

    # ── Email addresses ─────────────────────────────────────────
    "email": {"strategy": "simple", "key": "Email-Addr.value"},
    "email-addr": {"strategy": "simple", "key": "Email-Addr.value"},
    "email-src": {"strategy": "simple", "key": "Email-Addr.value"},
    "email-dst": {"strategy": "simple", "key": "Email-Addr.value"},

    # ── Network artefacts ───────────────────────────────────────
    "mac-address": {"strategy": "simple", "key": "Mac-Addr.value"},
    "AS": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {
            "type": "autonomous-system",
            "number": int(re.sub(r"[^0-9]", "", v)) if re.search(r"\d+", v) else 0,
        },
    },
    "as": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {
            "type": "autonomous-system",
            "number": int(re.sub(r"[^0-9]", "", v)) if re.search(r"\d+", v) else 0,
        },
    },

    # ── Registry keys ──────────────────────────────────────────
    "registry-key": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {"type": "windows-registry-key", "key": v},
    },

    # ── User agent ──────────────────────────────────────────────
    "user-agent": {"strategy": "simple", "key": "User-Agent.value"},

    # ── JA3 / network fingerprints ──────────────────────────────
    "ja3-fingerprint-md5": {"strategy": "simple", "key": "Text.value"},
    "jarm-fingerprint": {"strategy": "simple", "key": "Text.value"},
    "hassh-md5": {"strategy": "simple", "key": "Text.value"},
    "hasshserver-md5": {"strategy": "simple", "key": "Text.value"},
    "ssh-fingerprint": {"strategy": "simple", "key": "Text.value"},
    "community-id": {"strategy": "simple", "key": "Text.value"},

    # ── Generic text ────────────────────────────────────────────
    "text": {"strategy": "simple", "key": "Text.value"},

    # ── IP (generic) ────────────────────────────────────────────
    "ip-any": {"strategy": "simple", "key": "auto_ip"},

    # ── Hostname with port ──────────────────────────────────────
    "hostname|port": {"strategy": "composite", "parser": _parse_hostname_port},

    # ── Registry keys (MISP aliases) ────────────────────────────
    "regkey": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {"type": "windows-registry-key", "key": v},
    },
    "regkey|value": {"strategy": "composite", "parser": _parse_regkey_value},

    # ── MAC (EUI-64) ─────────────────────────────────────────────
    "mac-eui-64": {"strategy": "simple", "key": "Mac-Addr.value"},

    # ── SHA-3 hashes ────────────────────────────────────────────
    # Only SHA3-256 and SHA3-512 are in OpenCTI's HashAlgorithm enum.
    "sha3-224": {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "sha3-256": {"strategy": "observable_data", **_hash_observable("sha3-256")},
    "sha3-384": {"strategy": "simple", "key": "Text.value"},  # not in OpenCTI enum
    "sha3-512": {"strategy": "observable_data", **_hash_observable("sha3-512")},

    # ── PE / ELF / macOS fuzzy / import hashes ──────────────────
    # None of these are in OpenCTI's HashAlgorithm enum. Standalone instances
    # are stored as Text.value; filename|hash variants fall back to File.name
    # only via _parse_filename_only (hash portion discarded).
    "impfuzzy":  {"strategy": "simple", "key": "Text.value"},
    "imphash":   {"strategy": "simple", "key": "Text.value"},
    "pehash":    {"strategy": "simple", "key": "Text.value"},
    "vhash":     {"strategy": "simple", "key": "Text.value"},
    "telfhash":  {"strategy": "simple", "key": "Text.value"},
    "cdhash":    {"strategy": "simple", "key": "Text.value"},

    # ── X.509 certificate fingerprints ──────────────────────────
    "x509-fingerprint-md5": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {"type": "x509-certificate", "hashes": {"MD5": v}},
    },
    "x509-fingerprint-sha1": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {"type": "x509-certificate", "hashes": {"SHA-1": v}},
    },
    "x509-fingerprint-sha256": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {"type": "x509-certificate", "hashes": {"SHA-256": v}},
    },

    # ── Mutex ───────────────────────────────────────────────────
    "mutex": {"strategy": "simple", "key": "Mutex.name"},

    # ── File path ───────────────────────────────────────────────
    # STIX 2.1 §4.5: file-path describes a directory, not a File SCO.
    "file-path": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {"type": "directory", "path": v},
    },

    # ── Email aliases ───────────────────────────────────────────
    "dns-soa-email": {"strategy": "simple", "key": "Email-Addr.value"},
    "whois-registrant-email": {"strategy": "simple", "key": "Email-Addr.value"},
    "target-email": {"strategy": "simple", "key": "Email-Addr.value"},

    # ── User / account types ─────────────────────────────────────
    # STIX 2.1 §4.14  user-account SCO
    # Generic account identifiers — account_login is the most common field in
    # threat intelligence contexts (usernames, login names).
    "account": {"strategy": "simple", "key": "User-Account.account_login"},
    "target-user": {"strategy": "simple", "key": "User-Account.account_login"},
    # ePPN (eduPersonPrincipalName) is a globally-scoped unique user identifier
    # (format: user@org.edu) — distinct from email; maps to user_id.
    "eppn": {"strategy": "simple", "key": "User-Account.user_id"},
    # Platform-specific accounts carry account_type for richer OpenCTI filtering.
    "github-username": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {
            "type": "user-account",
            "account_type": "github",
            "account_login": v,
        },
    },
    "twitter-id": {
        "strategy": "observable_data_raw",
        "builder": lambda v: {
            "type": "user-account",
            "account_type": "twitter",
            "account_login": v,
        },
    },

    # ── Filename + additional hash variants ─────────────────────
    # filename|supported-hash → full File SCO with name + hash
    "filename|sha224":     {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|ssdeep":     {"strategy": "composite", "parser": lambda v: _parse_filename_hash(v, "ssdeep")},
    "filename|tlsh":       {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|authentihash": {"strategy": "composite", "parser": _parse_filename_only},  # enum
    "filename|impfuzzy":   {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|imphash":    {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|pehash":     {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|vhash":      {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|sha3-224":   {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|sha3-256":   {"strategy": "composite", "parser": lambda v: _parse_filename_hash(v, "sha3-256")},
    "filename|sha3-384":   {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|sha3-512":   {"strategy": "composite", "parser": lambda v: _parse_filename_hash(v, "sha3-512")},
    "filename|sha512/224": {"strategy": "composite", "parser": _parse_filename_only},    # enum
    "filename|sha512/256": {"strategy": "composite", "parser": _parse_filename_only},    # enum
}


def resolve_ioc_type(type_name: str) -> dict[str, Any] | None:
    """
    Look up the OpenCTI mapping for an IRIS IOC type name.

    Returns the mapping dict, or ``None`` if the type is not supported.
    Falls back to substring matching for domain-like types that IRIS may
    represent with custom names containing 'domain'.
    """
    # Exact match first
    mapping = IOC_TYPE_MAP.get(type_name)
    if mapping is not None:
        return mapping

    # Normalised lowercase match
    lower = type_name.lower().strip()
    mapping = IOC_TYPE_MAP.get(lower)
    if mapping is not None:
        return mapping

    # Heuristic fallbacks for common patterns
    if re.match(r"^ip[v-]", lower):
        return IOC_TYPE_MAP["ip-src"]
    if "domain" in lower:
        return IOC_TYPE_MAP["domain"]
    if "url" in lower:
        return IOC_TYPE_MAP["url"]
    if "hash" in lower or lower.startswith("sha"):
        return IOC_TYPE_MAP["sha256"]  # safe fallback

    return None


def build_observable_params(
    mapping: dict[str, Any],
    ioc_value: str,
    create_indicator: bool = True,
    marking_ids: list[str] | None = None,
    author_id: str | None = None,
    confidence: int = 50,
    description: str | None = None,
) -> list[dict[str, Any]]:
    """
    Turn a mapping + IOC value into a list of kwargs dicts ready for
    ``OpenCTIApiClient.stix_cyber_observable.create(**kwargs)``.

    Returns a list because composite types may produce multiple observables.
    """
    strategy = mapping["strategy"]

    base_kwargs: dict[str, Any] = {
        "createIndicator": create_indicator,
        "x_opencti_score": confidence,
    }
    if marking_ids:
        base_kwargs["objectMarking"] = marking_ids
    if author_id:
        base_kwargs["createdBy"] = author_id

    results: list[dict[str, Any]] = []

    if strategy == "simple":
        key = mapping["key"]
        if key == "auto_ip":
            key = _detect_ip_version(ioc_value)
        obs = {
            **base_kwargs,
            "simple_observable_key": key,
            "simple_observable_value": ioc_value,
        }
        if description:
            obs["simple_observable_description"] = description
        results.append(obs)

    elif strategy == "observable_data":
        if "hash_algo" in mapping:
            # Single-hash type (e.g. "md5", "sha256")
            hash_algo = mapping["hash_algo"]
            obs_data: dict[str, Any] = {
                "type": "file",
                "hashes": {_normalise_hash_name(hash_algo): ioc_value},
            }
        else:
            # Pre-built observableData dict (from composite parsers
            # like filename|hash)
            obs_data = {k: v for k, v in mapping.items() if k != "strategy"}
        if description:
            obs_data["x_opencti_description"] = description
        results.append({
            **base_kwargs,
            "observableData": obs_data,
        })

    elif strategy == "observable_data_raw":
        builder = mapping["builder"]
        raw_data = builder(ioc_value)
        if description:
            raw_data["x_opencti_description"] = description
        results.append({
            **base_kwargs,
            "observableData": raw_data,
        })

    elif strategy == "composite":
        parser = mapping["parser"]
        sub_items = parser(ioc_value)
        for sub_strategy, sub_config, sub_value in sub_items:
            sub_mapping = {"strategy": sub_strategy, **sub_config}
            results.extend(build_observable_params(
                sub_mapping, sub_value,
                create_indicator=create_indicator,
                marking_ids=marking_ids,
                author_id=author_id,
                confidence=confidence,
                description=description,
            ))

    return results
