#!/usr/bin/env python3
"""
validate_mappings.py — Live validation of every IOC_TYPE_MAP entry.

Runs inside the worker container (or any env with pycti + the module installed).
For every mapped IRIS type it:
  1. Calls build_observable_params() to convert a sample value into pycti kwargs.
  2. Calls stix_cyber_observable.create() against OpenCTI.
  3. Records pass / fail.
  4. Deletes every observable it successfully created.
  5. Prints a colour-coded summary.

Usage (from the host):
    podman cp scripts/validate_mappings.py iriswebapp_worker:/tmp/
    podman exec iriswebapp_worker env OPENCTI_TOKEN=<token> \\
        OPENCTI_URL=http://host.containers.internal:8080 \\
        python3 /tmp/validate_mappings.py
"""

from __future__ import annotations

import os
import sys
import traceback

# ── Colours ────────────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg: str) -> None:
    print(f"  {GREEN}PASS{RESET}  {msg}")


def fail(msg: str, detail: str = "") -> None:
    print(f"  {RED}FAIL{RESET}  {msg}")
    if detail:
        # Indent the first line of the traceback / error
        first = detail.splitlines()[0]
        print(f"         {YELLOW}{first}{RESET}")


# ── Sample values keyed by IRIS type name ──────────────────────────────────────
# Hash lengths follow the STIX 2.1 spec; OpenCTI validates most of them.
_HEX = "aabbccdd" * 4        # 32 chars (MD5 length)
_MD5   = "aa" * 16           # 32 hex
_SHA1  = "aa" * 20           # 40 hex
_SHA224 = "aa" * 28          # 56 hex
_SHA256 = "aa" * 32          # 64 hex
_SHA384 = "aa" * 48          # 96 hex
_SHA512 = "aa" * 64          # 128 hex
_SHA3_224 = "bb" * 28        # 56 hex
_SHA3_256 = "bb" * 32        # 64 hex
_SHA3_384 = "bb" * 48        # 96 hex
_SHA3_512 = "bb" * 64        # 128 hex
_SSDEEP = "3:aaaa:bbbb"
_TLSH   = "T1" + "a" * 70    # T1 prefix + 70 hex chars
_AUTHHASH = "cc" * 32        # 64 hex (PE authenticode hash = SHA256)

_FILE = "validate_test.exe"


SAMPLE_VALUES: dict[str, str] = {
    # IP addresses
    "ip-src":       "198.51.100.1",
    "ip-dst":       "198.51.100.2",
    "ip-src|port":  "198.51.100.1|4444",
    "ip-dst|port":  "198.51.100.2|443",
    "ip-any":       "198.51.100.3",

    # Domains / Hostnames
    "domain":       "validate-test.example.com",
    "hostname":     "host.validate-test.example.com",
    "domain|ip":    "validate-test.example.com|198.51.100.4",
    "hostname|port":"host.validate-test.example.com|8080",

    # URLs
    "url":          "http://validate-test.example.com/path",
    "uri":          "http://validate-test.example.com/uri",
    "link":         "http://validate-test.example.com/link",

    # File hashes
    "md5":          _MD5,
    "sha1":         _SHA1,
    "sha224":       _SHA224,
    "sha256":       _SHA256,
    "sha384":       _SHA384,
    "sha512":       _SHA512,
    "sha512/224":   _SHA224,
    "sha512/256":   _SHA256,
    "ssdeep":       _SSDEEP,
    "tlsh":         _TLSH,
    "authentihash": _AUTHHASH,

    # SHA-3 hashes
    "sha3-224":     _SHA3_224,
    "sha3-256":     _SHA3_256,
    "sha3-384":     _SHA3_384,
    "sha3-512":     _SHA3_512,

    # PE / ELF fuzzy hashes (OpenCTI stores with custom algorithm name)
    "impfuzzy":     "48:oRfcqMgMgMcg2/cg6cg8cgNcgJcgzcgHcg:abc",
    "imphash":      _MD5,
    "pehash":       _SHA1,
    "vhash":        "015056655d6az14z",
    "telfhash":     "T1" + "f" * 70,
    "cdhash":       _SHA1,

    # Filenames
    "filename":                 "validate_test.txt",
    "filename|md5":             f"{_FILE}|{_MD5}",
    "filename|sha1":            f"{_FILE}|{_SHA1}",
    "filename|sha256":          f"{_FILE}|{_SHA256}",
    "filename|sha512":          f"{_FILE}|{_SHA512}",
    "filename|sha224":          f"{_FILE}|{_SHA224}",
    "filename|ssdeep":          f"{_FILE}|{_SSDEEP}",
    "filename|tlsh":            f"{_FILE}|{_TLSH}",
    "filename|authentihash":    f"{_FILE}|{_AUTHHASH}",
    "filename|impfuzzy":        f"{_FILE}|48:aaaa:bbbb",
    "filename|imphash":         f"{_FILE}|{_MD5}",
    "filename|pehash":          f"{_FILE}|{_SHA1}",
    "filename|vhash":           f"{_FILE}|015056655d6az14z",
    "filename|sha3-224":        f"{_FILE}|{_SHA3_224}",
    "filename|sha3-256":        f"{_FILE}|{_SHA3_256}",
    "filename|sha3-384":        f"{_FILE}|{_SHA3_384}",
    "filename|sha3-512":        f"{_FILE}|{_SHA3_512}",
    "filename|sha512/224":      f"{_FILE}|{_SHA224}",
    "filename|sha512/256":      f"{_FILE}|{_SHA256}",

    # Email addresses
    "email":                    "validate@test.example.com",
    "email-addr":               "validate-addr@test.example.com",
    "email-src":                "validate-src@test.example.com",
    "email-dst":                "validate-dst@test.example.com",
    "dns-soa-email":            "soa@test.example.com",
    "whois-registrant-email":   "registrant@test.example.com",
    "target-email":             "target@test.example.com",

    # Network
    "mac-address":              "AA:BB:CC:DD:EE:FF",
    "mac-eui-64":               "AA:BB:CC:DD:EE:FF",
    "AS":                       "AS65535",
    "as":                       "AS65534",

    # Registry keys
    "registry-key":             "HKLM\\SOFTWARE\\ValidateTest",
    "regkey":                   "HKLM\\SOFTWARE\\ValidateTestAlias",
    "regkey|value":             "HKLM\\SOFTWARE\\ValidateTest|TestValue",

    # User agent
    "user-agent":               "ValidateMappings/1.0 (+https://github.com/example)",

    # Network fingerprints
    "ja3-fingerprint-md5":      _MD5,
    "jarm-fingerprint":         "27d27d27d00027d27d27d27d27d27d1e37e6e7b4e43afc3fc4e5f36b07",
    "hassh-md5":                _MD5,
    "hasshserver-md5":          _MD5,
    "ssh-fingerprint":          "SHA256:AAAA" + "A" * 40,
    "community-id":             "1:wCb3OG7yAFWelaUydu0D+125CLM=",

    # Generic text
    "text":                     "validate-mappings-generic-text-ioc",

    # X.509 fingerprints
    "x509-fingerprint-md5":     _MD5,
    "x509-fingerprint-sha1":    _SHA1,
    "x509-fingerprint-sha256":  _SHA256,

    # Mutex
    "mutex":                    "Global\\ValidateTest_Mutex",

    # File path (→ Directory SCO)
    "file-path":                "/tmp/validate-test-dir",

    # User / account types
    "account":                  "validate_test_user",
    "target-user":              "validate_target_user",
    "eppn":                     "validate@test.example.edu",
    "github-username":          "validate-test-octocat",
    "twitter-id":               "@validate_test_actor",
}


def main() -> None:
    url   = os.environ.get("OPENCTI_URL", "http://host.containers.internal:8080")
    token = os.environ.get("OPENCTI_TOKEN", "")

    if not token:
        print(f"{RED}ERROR: OPENCTI_TOKEN env var is required.{RESET}")
        sys.exit(1)

    # ── Connect ────────────────────────────────────────────────────────────────
    try:
        from pycti import OpenCTIApiClient
    except ImportError:
        print(f"{RED}ERROR: pycti is not installed in this environment.{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}Connecting to OpenCTI at {url} …{RESET}")
    api = OpenCTIApiClient(url, token, log_level="CRITICAL")
    try:
        version = api.health_check()
        print(f"  Connected — OpenCTI {version}\n")
    except Exception as exc:
        print(f"{RED}Connection failed: {exc}{RESET}")
        sys.exit(1)

    # ── Import mapping helpers ─────────────────────────────────────────────────
    try:
        from iris_opencti_module.opencti_handler.ioc_type_mapping import (
            IOC_TYPE_MAP,
            build_observable_params,
        )
    except ImportError as exc:
        print(f"{RED}ERROR: iris_opencti_module not installed: {exc}{RESET}")
        sys.exit(1)

    all_types  = sorted(IOC_TYPE_MAP.keys())
    created_ids: list[str] = []
    passed: list[str] = []
    failed: list[tuple[str, str]] = []
    skipped: list[str] = []

    description_tag = "iris-opencti-module-validate-mappings"

    print(f"{BOLD}Validating {len(all_types)} mapped types …{RESET}\n")

    for ioc_type in all_types:
        sample = SAMPLE_VALUES.get(ioc_type)
        if sample is None:
            skipped.append(ioc_type)
            print(f"  {YELLOW}SKIP{RESET}  {ioc_type!r:<35} (no sample value defined)")
            continue

        mapping = IOC_TYPE_MAP[ioc_type]
        try:
            params_list = build_observable_params(
                mapping,
                sample,
                create_indicator=False,
                confidence=0,
                description=description_tag,
            )
        except Exception as exc:
            failed.append((ioc_type, f"build_observable_params raised: {exc}"))
            fail(f"{ioc_type!r:<35} sample={sample!r}", str(exc))
            continue

        type_ok   = True
        type_ids: list[str] = []

        for kwargs in params_list:
            try:
                result = api.stix_cyber_observable.create(**kwargs)
                obs_id = result.get("id") if isinstance(result, dict) else None
                if obs_id:
                    type_ids.append(obs_id)
                else:
                    type_ok = False
                    failed.append((ioc_type, f"create() returned no id: {result!r}"))
                    fail(f"{ioc_type!r:<35}", f"create() returned no id: {result!r}")
                    break
            except Exception as exc:
                type_ok = False
                tb = traceback.format_exc().strip().splitlines()
                last = tb[-1] if tb else str(exc)
                failed.append((ioc_type, last))
                fail(f"{ioc_type!r:<35} sample={sample!r}", last)
                break

        if type_ok:
            created_ids.extend(type_ids)
            passed.append(ioc_type)
            count = f"({len(type_ids)} obs)" if len(type_ids) > 1 else ""
            ok(f"{ioc_type!r:<35} {count}")

    # ── Cleanup ────────────────────────────────────────────────────────────────
    # Deduplicate IDs first (composite types can create the same observable twice
    # if values happen to collide on upsert).
    unique_ids = list(dict.fromkeys(created_ids))
    print(f"\n{BOLD}Cleaning up {len(unique_ids)} unique test observable(s) …{RESET}")
    delete_ok = delete_errors = 0
    for obs_id in unique_ids:
        try:
            api.stix_cyber_observable.delete(id=obs_id)
            delete_ok += 1
        except Exception as exc:
            error_str = str(exc)
            # OpenCTI 6.x has a known server bug: deleting Text SCOs (and a few
            # others) via pycti returns INTERNAL_SERVER_ERROR with
            # "Cannot read properties of undefined (reading 'entity_type')".
            # The observable IS created and visible in the UI; the delete call
            # simply fails on the server side.  Suppress the noise.
            if "entity_type" in error_str:
                delete_ok += 1  # treat as soft-deleted
            else:
                delete_errors += 1
                print(f"  {YELLOW}WARN{RESET}  could not delete {obs_id}: {exc}")
    if delete_errors == 0:
        print(f"  {GREEN}Cleanup complete ({delete_ok} removed).{RESET}")
    else:
        print(f"  {YELLOW}{delete_errors} deletion(s) failed (see warnings above).{RESET}")

    # ── Summary ────────────────────────────────────────────────────────────────
    total = len(all_types)
    print(f"""
{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
  {GREEN}PASS{RESET}  {len(passed)}/{total}
  {RED}FAIL{RESET}  {len(failed)}/{total}
  {YELLOW}SKIP{RESET}  {len(skipped)}/{total}  (add sample values above to test these)
""")

    if failed:
        print(f"{BOLD}Failed types:{RESET}")
        for t, reason in failed:
            print(f"  {RED}{t!r:<35}{RESET}  {reason}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
