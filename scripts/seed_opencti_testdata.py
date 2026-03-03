#!/usr/bin/env python3
"""
Seed OpenCTI with realistic fake threat intelligence data.

Creates a connected graph of:
  - Observables (domains, IPs, file hashes)
  - Threat actors, intrusion sets, malware, campaigns
  - ATT&CK techniques
  - Relationships linking observables to threat context
  - Sightings from fictitious organisations
  - A Case Incident grouping everything

Run inside the IRIS worker container (has pycti installed):

    podman cp scripts/seed_opencti_testdata.py iriswebapp_worker:/tmp/
    podman exec -e OPENCTI_TOKEN=<your-token> iriswebapp_worker python3 /tmp/seed_opencti_testdata.py

Or from the host if pycti is installed:

    OPENCTI_TOKEN=<your-token> python3 scripts/seed_opencti_testdata.py
    OPENCTI_URL=http://localhost:8080 OPENCTI_TOKEN=<your-token> python3 scripts/seed_opencti_testdata.py
"""

from __future__ import annotations

import os
import sys
import time

OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://host.containers.internal:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# If running from the host, use localhost
if "--host" in sys.argv:
    OPENCTI_URL = "http://localhost:8080"

if not OPENCTI_TOKEN:
    print("ERROR: Set OPENCTI_TOKEN environment variable before running this script.")
    sys.exit(1)


def main():
    from pycti import OpenCTIApiClient

    print("=" * 60)
    print("  OpenCTI Test Data Seeder")
    print("=" * 60)

    print(f"\n[*] Connecting to {OPENCTI_URL}")
    api = OpenCTIApiClient(
        url=OPENCTI_URL,
        token=OPENCTI_TOKEN,
        ssl_verify=False,
        log_level="Warning",
    )

    if not api.health_check():
        print("[!] Health check failed — is OpenCTI running?")
        sys.exit(1)
    print("[+] Connected successfully\n")

    created = {}

    # ── 1. Author identity ──────────────────────────────────────
    _step("Creating author identity: ACME CSIRT")
    author = api.identity.create(type="Organization", name="ACME CSIRT")
    created["author"] = author["id"]
    _ok(author["id"])

    # ── 2. Labels ───────────────────────────────────────────────
    _step("Creating labels")
    for lbl, color in [("c2", "#d32f2f"), ("phishing", "#f57c00"),
                        ("apt", "#1565c0"), ("ransomware", "#6a1b9a")]:
        api.label.create(value=lbl, color=color)
        print(f"    {lbl}")
    print()

    # ── 3. Threat actors ────────────────────────────────────────
    _step("Creating threat actors")
    ta1 = api.threat_actor_group.create(
        name="Shadowed Serpent",
        description="A sophisticated state-sponsored threat actor group "
                    "targeting defence and aerospace sectors since 2019.",
        createdBy=created["author"],
    )
    created["ta_serpent"] = ta1["id"]
    _ok(f"Shadowed Serpent — {ta1['id']}")

    ta2 = api.threat_actor_group.create(
        name="Crimson Tempest",
        description="Financially motivated group specialising in "
                    "ransomware deployment via phishing campaigns.",
        createdBy=created["author"],
    )
    created["ta_tempest"] = ta2["id"]
    _ok(f"Crimson Tempest — {ta2['id']}")

    # ── 4. Intrusion set ────────────────────────────────────────
    _step("Creating intrusion set")
    iset = api.intrusion_set.create(
        name="Operation Nightfall",
        description="Long-running espionage campaign attributed to "
                    "Shadowed Serpent, active 2022–2026.",
        createdBy=created["author"],
    )
    created["intrusion_set"] = iset["id"]
    _ok(f"Operation Nightfall — {iset['id']}")

    # ── 5. Malware ──────────────────────────────────────────────
    _step("Creating malware")
    mal1 = api.malware.create(
        name="SerpentRAT",
        description="Custom remote-access trojan used by Shadowed Serpent. "
                    "Communicates over HTTPS using domain fronting.",
        is_family=True,
        createdBy=created["author"],
    )
    created["mal_serpentrat"] = mal1["id"]
    _ok(f"SerpentRAT — {mal1['id']}")

    mal2 = api.malware.create(
        name="TempestLocker",
        description="Ransomware payload deployed by Crimson Tempest. "
                    "Encrypts files with AES-256 and exfiltrates via Tor.",
        is_family=True,
        createdBy=created["author"],
    )
    created["mal_locker"] = mal2["id"]
    _ok(f"TempestLocker — {mal2['id']}")

    # ── 6. Campaign ─────────────────────────────────────────────
    _step("Creating campaign")
    camp = api.campaign.create(
        name="Nightfall Phase 3",
        description="Third wave of Operation Nightfall targeting European "
                    "critical infrastructure, Feb–Jun 2026.",
        createdBy=created["author"],
    )
    created["campaign"] = camp["id"]
    _ok(f"Nightfall Phase 3 — {camp['id']}")

    # ── 7. ATT&CK techniques ───────────────────────────────────
    _step("Creating ATT&CK techniques")
    techniques = [
        ("T1566.001", "Spearphishing Attachment",
         "Adversaries send spearphishing emails with a malicious attachment."),
        ("T1059.001", "PowerShell",
         "Adversaries abuse PowerShell for execution of commands and scripts."),
        ("T1071.001", "Web Protocols",
         "Adversaries communicate using application layer protocols (HTTP/S)."),
        ("T1486", "Data Encrypted for Impact",
         "Adversaries encrypt data on target systems to interrupt availability."),
    ]
    for mitre_id, name, desc in techniques:
        ap = api.attack_pattern.create(
            name=name,
            description=desc,
            x_mitre_id=mitre_id,
            createdBy=created["author"],
        )
        created[f"attack_{mitre_id}"] = ap["id"]
        _ok(f"{mitre_id} {name}")

    # ── 8. Observables (IOCs) ───────────────────────────────────
    _step("Creating observables")

    obs_domain1 = api.stix_cyber_observable.create(
        simple_observable_key="Domain-Name.value",
        simple_observable_value="c2-nightfall.example.com",
        createIndicator=True,
        x_opencti_score=85,
        createdBy=created["author"],
    )
    created["obs_domain1"] = obs_domain1["id"]
    _ok(f"Domain: c2-nightfall.example.com — {obs_domain1['id']}")

    obs_domain2 = api.stix_cyber_observable.create(
        simple_observable_key="Domain-Name.value",
        simple_observable_value="phish-tempest.example.net",
        createIndicator=True,
        x_opencti_score=72,
        createdBy=created["author"],
    )
    created["obs_domain2"] = obs_domain2["id"]
    _ok(f"Domain: phish-tempest.example.net — {obs_domain2['id']}")

    obs_ip = api.stix_cyber_observable.create(
        simple_observable_key="IPv4-Addr.value",
        simple_observable_value="198.51.100.23",
        createIndicator=True,
        x_opencti_score=90,
        createdBy=created["author"],
    )
    created["obs_ip"] = obs_ip["id"]
    _ok(f"IPv4: 198.51.100.23 — {obs_ip['id']}")

    obs_hash = api.stix_cyber_observable.create(
        observableData={
            "type": "file",
            "hashes": {
                "SHA-256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            },
            "name": "serpentrat_loader.exe",
        },
        createIndicator=True,
        x_opencti_score=95,
        createdBy=created["author"],
    )
    created["obs_hash"] = obs_hash["id"]
    _ok(f"File hash: serpentrat_loader.exe — {obs_hash['id']}")

    obs_email = api.stix_cyber_observable.create(
        simple_observable_key="Email-Addr.value",
        simple_observable_value="hr-payroll@phish-tempest.example.net",
        createIndicator=True,
        x_opencti_score=65,
        createdBy=created["author"],
    )
    created["obs_email"] = obs_email["id"]
    _ok(f"Email: hr-payroll@phish-tempest.example.net — {obs_email['id']}")

    # ── 9. Relationships ────────────────────────────────────────
    _step("Creating relationships")

    relationships = [
        # Threat actors → malware
        (created["ta_serpent"], "uses", created["mal_serpentrat"],
         "Shadowed Serpent uses SerpentRAT"),
        (created["ta_tempest"], "uses", created["mal_locker"],
         "Crimson Tempest uses TempestLocker"),
        # Threat actors → ATT&CK
        (created["ta_serpent"], "uses", created["attack_T1566.001"],
         "Shadowed Serpent uses spearphishing"),
        (created["ta_serpent"], "uses", created["attack_T1071.001"],
         "Shadowed Serpent uses web protocols for C2"),
        (created["ta_tempest"], "uses", created["attack_T1059.001"],
         "Crimson Tempest uses PowerShell"),
        (created["ta_tempest"], "uses", created["attack_T1486"],
         "Crimson Tempest encrypts data for impact"),
        # Intrusion set → threat actor
        (created["intrusion_set"], "attributed-to", created["ta_serpent"],
         "Operation Nightfall attributed to Shadowed Serpent"),
        # Campaign → intrusion set
        (created["campaign"], "attributed-to", created["intrusion_set"],
         "Nightfall Phase 3 is part of Operation Nightfall"),
        # Malware → observables (C2 infrastructure)
        (created["mal_serpentrat"], "communicates-with", created["obs_domain1"],
         "SerpentRAT communicates with c2-nightfall.example.com"),
        (created["mal_serpentrat"], "communicates-with", created["obs_ip"],
         "SerpentRAT communicates with 198.51.100.23"),
        # Indicators linked to observables happen automatically via createIndicator
        # Campaign → observable
        (created["campaign"], "uses", created["obs_domain1"],
         "Nightfall Phase 3 uses c2-nightfall.example.com"),
        (created["campaign"], "uses", created["obs_ip"],
         "Nightfall Phase 3 uses 198.51.100.23"),
        # Threat actor → observables
        (created["ta_tempest"], "uses", created["obs_domain2"],
         "Crimson Tempest uses phish-tempest.example.net"),
        (created["ta_tempest"], "uses", created["obs_email"],
         "Crimson Tempest uses phishing email"),
    ]

    for from_id, rel_type, to_id, desc in relationships:
        try:
            rel = api.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=rel_type,
                description=desc,
                createdBy=created["author"],
            )
            _ok(desc)
        except Exception as e:
            print(f"    [!] Failed: {desc} — {e}")

    # ── 10. Sightings ───────────────────────────────────────────
    _step("Creating sightings")

    # Create reporting organisations
    cert_eu = api.identity.create(type="Organization", name="CERT-EU")
    nato_cert = api.identity.create(type="Organization", name="NATO CIRC")
    internal_soc = api.identity.create(type="Organization", name="ACME SOC")

    sightings = [
        # (observable, sighted_by, first_seen, last_seen, count, desc)
        (created["obs_domain1"], cert_eu["id"],
         "2025-11-01T00:00:00Z", "2026-02-15T00:00:00Z", 28,
         "CERT-EU observed c2-nightfall.example.com in multiple EU incidents"),
        (created["obs_ip"], cert_eu["id"],
         "2025-12-10T00:00:00Z", "2026-01-20T00:00:00Z", 12,
         "CERT-EU observed 198.51.100.23 as C2 endpoint"),
        (created["obs_domain1"], nato_cert["id"],
         "2026-01-05T00:00:00Z", "2026-02-20T00:00:00Z", 7,
         "NATO CIRC confirmed sighting in allied network"),
        (created["obs_hash"], internal_soc["id"],
         "2026-02-25T00:00:00Z", "2026-02-25T00:00:00Z", 1,
         "ACME SOC detected serpentrat_loader.exe on endpoint WS-1042"),
        (created["obs_domain2"], internal_soc["id"],
         "2026-02-20T00:00:00Z", "2026-02-26T00:00:00Z", 3,
         "ACME SOC observed phishing domain in email logs"),
    ]

    for obs_id, org_id, first_seen, last_seen, count, desc in sightings:
        try:
            api.stix_sighting_relationship.create(
                fromId=obs_id,
                toId=org_id,
                first_seen=first_seen,
                last_seen=last_seen,
                count=count,
                description=desc,
                createdBy=created["author"],
            )
            _ok(desc)
        except Exception as e:
            print(f"    [!] Failed: {desc} — {e}")

    # ── 11. Labels on observables ───────────────────────────────
    _step("Applying labels to observables")
    label_assignments = [
        (created["obs_domain1"], ["c2", "apt"]),
        (created["obs_ip"], ["c2", "apt"]),
        (created["obs_hash"], ["apt"]),
        (created["obs_domain2"], ["phishing"]),
        (created["obs_email"], ["phishing"]),
    ]
    for obs_id, labels in label_assignments:
        for lbl in labels:
            try:
                api.stix_cyber_observable.add_label(id=obs_id, label_name=lbl)
            except Exception:
                pass  # label may already be assigned
        _ok(f"{obs_id[:12]}… ← {', '.join(labels)}")

    # ── 12. Case Incident ───────────────────────────────────────
    _step("Creating Case Incident")
    case = api.case_incident.create(
        name="IRIS-Test-Nightfall-2026",
        description="Test case for IRIS-OpenCTI module development. "
                    "Simulates an incident involving Shadowed Serpent / "
                    "Operation Nightfall targeting ACME infrastructure.",
        createdBy=created["author"],
    )
    created["case"] = case["id"]
    _ok(f"IRIS-Test-Nightfall-2026 — {case['id']}")

    # Link all observables to the case
    _step("Linking observables to case")
    for key in ["obs_domain1", "obs_domain2", "obs_ip", "obs_hash", "obs_email"]:
        try:
            api.case_incident.add_stix_object_or_stix_relationship(
                id=created["case"],
                stixObjectOrStixRelationshipId=created[key],
            )
            _ok(key)
        except Exception as e:
            print(f"    [!] Failed to link {key}: {e}")

    # ── 13. Report ──────────────────────────────────────────────
    _step("Creating threat report")
    report = api.report.create(
        name="Operation Nightfall — Phase 3 Analysis",
        description="Technical analysis of the third wave of Operation "
                    "Nightfall, including IOCs, TTPs, and attribution.",
        published="2026-02-15T00:00:00Z",
        report_types=["threat-report"],
        createdBy=created["author"],
    )
    created["report"] = report["id"]
    _ok(f"Report — {report['id']}")

    # Link key objects to the report
    for key in ["obs_domain1", "obs_ip", "obs_hash", "ta_serpent",
                "mal_serpentrat", "intrusion_set", "campaign"]:
        try:
            api.report.add_stix_object_or_stix_relationship(
                id=created["report"],
                stixObjectOrStixRelationshipId=created[key],
            )
        except Exception:
            pass

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  Test data seeded successfully!")
    print("=" * 60)
    print()
    print("IOC values to use in IRIS for testing:")
    print("  Domain:  c2-nightfall.example.com")
    print("  Domain:  phish-tempest.example.net")
    print("  IPv4:    198.51.100.23")
    print("  SHA-256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
          "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
    print("  Email:   hr-payroll@phish-tempest.example.net")
    print()
    print("These observables are linked to:")
    print("  - Threat actors:  Shadowed Serpent, Crimson Tempest")
    print("  - Intrusion set:  Operation Nightfall")
    print("  - Malware:        SerpentRAT, TempestLocker")
    print("  - Campaign:       Nightfall Phase 3")
    print("  - ATT&CK:         T1566.001, T1059.001, T1071.001, T1486")
    print("  - Sightings from: CERT-EU, NATO CIRC, ACME SOC")
    print("  - Case Incident:  IRIS-Test-Nightfall-2026")
    print("  - Report:         Operation Nightfall — Phase 3 Analysis")
    print()
    url = OPENCTI_URL.replace("host.containers.internal", "localhost")
    print(f"Check OpenCTI at: {url}/dashboard/cases/incidents")
    print("=" * 60)


def _step(msg: str):
    print(f"[*] {msg}")


def _ok(detail: str):
    print(f"  ✓ {detail}")


if __name__ == "__main__":
    main()
