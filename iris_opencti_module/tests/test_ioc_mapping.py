"""
Unit tests for the IOC type mapping module.
"""

import pytest

from iris_opencti_module.opencti_handler.ioc_type_mapping import (
    IOC_TYPE_MAP,
    build_observable_params,
    resolve_ioc_type,
    _detect_ip_version,
    _normalise_hash_name,
)


# ── resolve_ioc_type ────────────────────────────────────────────


class TestResolveIocType:
    """Tests for mapping IRIS IOC types to OpenCTI strategies."""

    @pytest.mark.parametrize(
        "type_name",
        [
            "ip-src", "ip-dst", "domain", "hostname", "url", "md5",
            "sha1", "sha256", "sha512", "email-src", "email-dst",
            "filename", "mac-address", "AS", "registry-key",
        ],
    )
    def test_known_types_resolve(self, type_name):
        result = resolve_ioc_type(type_name)
        assert result is not None, f"Expected mapping for '{type_name}'"

    def test_unknown_type_returns_none(self):
        assert resolve_ioc_type("completely_unknown_type_xyz") is None

    def test_case_insensitive(self):
        assert resolve_ioc_type("MD5") is not None
        assert resolve_ioc_type("SHA256") is not None
        assert resolve_ioc_type("Domain") is not None

    def test_ip_heuristic_fallback(self):
        # Should match via the ip heuristic
        result = resolve_ioc_type("ipv4")
        assert result is not None

    def test_domain_heuristic_fallback(self):
        result = resolve_ioc_type("domain-name")
        assert result is not None

    def test_url_heuristic_fallback(self):
        result = resolve_ioc_type("full-url")
        assert result is not None


# ── _detect_ip_version ──────────────────────────────────────────


class TestDetectIpVersion:
    def test_ipv4(self):
        assert _detect_ip_version("192.168.1.1") == "IPv4-Addr.value"

    def test_ipv6(self):
        assert _detect_ip_version("2001:db8::1") == "IPv6-Addr.value"

    def test_ipv6_full(self):
        assert _detect_ip_version("fe80:0:0:0:0:0:0:1") == "IPv6-Addr.value"


# ── _normalise_hash_name ────────────────────────────────────────


class TestNormaliseHashName:
    @pytest.mark.parametrize(
        "input_val,expected",
        [
            ("md5", "MD5"),
            ("sha1", "SHA-1"),
            ("sha256", "SHA-256"),
            ("sha512", "SHA-512"),
            ("ssdeep", "SSDEEP"),
            ("tlsh", "TLSH"),
            ("sha224", "SHA-224"),
            ("sha384", "SHA-384"),
            ("sha512/224", "SHA-512/224"),
            ("sha512/256", "SHA-512/256"),
            ("authentihash", "AUTHENTIHASH"),
        ],
    )
    def test_known_hashes(self, input_val, expected):
        assert _normalise_hash_name(input_val) == expected

    def test_unknown_hash_uppercased(self):
        # Use an algo that is NOT in the normalisation table — expect uppercase pass-through
        assert _normalise_hash_name("fuzzytest") == "FUZZYTEST"


# ── build_observable_params ─────────────────────────────────────


class TestBuildObservableParams:
    def test_simple_domain(self):
        mapping = resolve_ioc_type("domain")
        result = build_observable_params(mapping, "evil.example.com")
        assert len(result) == 1
        assert result[0]["simple_observable_key"] == "Domain-Name.value"
        assert result[0]["simple_observable_value"] == "evil.example.com"
        assert result[0]["createIndicator"] is True

    def test_simple_ipv4(self):
        mapping = resolve_ioc_type("ip-src")
        result = build_observable_params(mapping, "192.168.1.1")
        assert len(result) == 1
        assert result[0]["simple_observable_key"] == "IPv4-Addr.value"

    def test_simple_ipv6_auto_detect(self):
        mapping = resolve_ioc_type("ip-dst")
        result = build_observable_params(mapping, "2001:db8::1")
        assert len(result) == 1
        assert result[0]["simple_observable_key"] == "IPv6-Addr.value"

    def test_hash_md5(self):
        mapping = resolve_ioc_type("md5")
        result = build_observable_params(mapping, "d41d8cd98f00b204e9800998ecf8427e")
        assert len(result) == 1
        obs_data = result[0]["observableData"]
        assert obs_data["type"] == "file"
        assert obs_data["hashes"]["MD5"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_hash_sha256(self):
        mapping = resolve_ioc_type("sha256")
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = build_observable_params(mapping, hash_val)
        assert result[0]["observableData"]["hashes"]["SHA-256"] == hash_val

    def test_composite_ip_port(self):
        mapping = resolve_ioc_type("ip-src|port")
        result = build_observable_params(mapping, "10.0.0.1|443")
        assert len(result) == 1
        assert result[0]["simple_observable_key"] == "IPv4-Addr.value"
        assert result[0]["simple_observable_value"] == "10.0.0.1"

    def test_composite_domain_ip(self):
        mapping = resolve_ioc_type("domain|ip")
        result = build_observable_params(mapping, "evil.com|1.2.3.4")
        assert len(result) == 2
        keys = {r["simple_observable_key"] for r in result}
        assert "Domain-Name.value" in keys
        assert "IPv4-Addr.value" in keys

    def test_composite_filename_hash(self):
        mapping = resolve_ioc_type("filename|sha256")
        result = build_observable_params(
            mapping, "malware.exe|abc123def456"
        )
        assert len(result) == 1
        obs_data = result[0]["observableData"]
        assert obs_data["type"] == "file"
        assert obs_data["name"] == "malware.exe"
        assert "SHA-256" in obs_data["hashes"]

    def test_url(self):
        mapping = resolve_ioc_type("url")
        result = build_observable_params(mapping, "https://evil.example.com/payload")
        assert result[0]["simple_observable_key"] == "Url.value"

    def test_email(self):
        mapping = resolve_ioc_type("email-src")
        result = build_observable_params(mapping, "attacker@evil.com")
        assert result[0]["simple_observable_key"] == "Email-Addr.value"

    def test_marking_and_author_passed(self):
        mapping = resolve_ioc_type("domain")
        result = build_observable_params(
            mapping, "evil.com",
            marking_ids=["marking-1"],
            author_id="author-1",
            confidence=90,
        )
        assert result[0]["objectMarking"] == ["marking-1"]
        assert result[0]["createdBy"] == "author-1"
        assert result[0]["x_opencti_score"] == 90

    def test_no_indicator_flag(self):
        mapping = resolve_ioc_type("domain")
        result = build_observable_params(
            mapping, "evil.com", create_indicator=False
        )
        assert result[0]["createIndicator"] is False

    def test_registry_key(self):
        mapping = resolve_ioc_type("registry-key")
        result = build_observable_params(
            mapping, r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        assert result[0]["observableData"]["type"] == "windows-registry-key"

    def test_filename_simple(self):
        mapping = resolve_ioc_type("filename")
        result = build_observable_params(mapping, "evil.exe")
        assert result[0]["simple_observable_key"] == "File.name"
        assert result[0]["simple_observable_value"] == "evil.exe"

    def test_hostname_uses_hostname_type(self):
        mapping = resolve_ioc_type("hostname")
        result = build_observable_params(mapping, "webserver01")
        assert result[0]["simple_observable_key"] == "Hostname.value"
        assert result[0]["simple_observable_value"] == "webserver01"

    def test_user_agent_simple_observable(self):
        mapping = resolve_ioc_type("user-agent")
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        result = build_observable_params(mapping, ua)
        assert result[0]["simple_observable_key"] == "User-Agent.value"
        assert result[0]["simple_observable_value"] == ua

    def test_ja3_uses_text_type(self):
        mapping = resolve_ioc_type("ja3-fingerprint-md5")
        result = build_observable_params(mapping, "abc123def456")
        assert result[0]["simple_observable_key"] == "Text.value"
        assert result[0]["simple_observable_value"] == "abc123def456"

    def test_as_number_parsed_as_integer(self):
        mapping = resolve_ioc_type("AS")
        result = build_observable_params(mapping, "AS65535")
        obs_data = result[0]["observableData"]
        assert obs_data["type"] == "autonomous-system"
        assert obs_data["number"] == 65535
        assert isinstance(obs_data["number"], int)

    def test_as_number_plain_digits(self):
        mapping = resolve_ioc_type("as")
        result = build_observable_params(mapping, "1234")
        obs_data = result[0]["observableData"]
        assert obs_data["number"] == 1234

    def test_filename_hash_fallback_uses_file_name(self):
        """When filename|hash has no separator, fallback key should be File.name."""
        mapping = resolve_ioc_type("filename|md5")
        result = build_observable_params(mapping, "no_pipe_here")
        assert result[0]["simple_observable_key"] == "File.name"


class TestUnsupportedHashEnumFallbacks:
    """Algorithms not in OpenCTI's HashAlgorithm enum must NOT be submitted as
    StixFile hashes (causes FUNCTIONAL_ERROR). Standalone variants fall back
    to Text.value; filename|X variants fall back to File.name (hash discarded)."""

    @pytest.mark.parametrize("ioc_type", [
        "sha224", "sha384", "sha512/224", "sha512/256",
        "sha3-224", "sha3-384",
        "authentihash", "tlsh",
        "impfuzzy", "imphash", "pehash", "vhash", "telfhash", "cdhash",
    ])
    def test_standalone_unsupported_hash_uses_text_value(self, ioc_type):
        mapping = resolve_ioc_type(ioc_type)
        result = build_observable_params(mapping, "deadbeef" * 4)
        assert result[0]["simple_observable_key"] == "Text.value"

    @pytest.mark.parametrize("ioc_type", [
        "filename|sha224", "filename|sha3-224", "filename|sha3-384",
        "filename|sha512/224", "filename|sha512/256",
        "filename|tlsh", "filename|authentihash",
        "filename|impfuzzy", "filename|imphash", "filename|pehash",
        "filename|vhash",
    ])
    def test_filename_unsupported_hash_yields_filename_only(self, ioc_type):
        mapping = resolve_ioc_type(ioc_type)
        value = "malware.exe|" + "aa" * 32
        result = build_observable_params(mapping, value)
        assert len(result) == 1
        assert result[0]["simple_observable_key"] == "File.name"
        assert result[0]["simple_observable_value"] == "malware.exe"

    def test_sha3_256_and_sha3_512_still_use_file_hash(self):
        """Only SHA3-224 and SHA3-384 are excluded; SHA3-256/512 are in the enum."""
        for ioc_type in ("sha3-256", "sha3-512"):
            mapping = resolve_ioc_type(ioc_type)
            result = build_observable_params(mapping, "bb" * 32)
            assert "observableData" in result[0], f"{ioc_type} should still use observableData"

    def test_filename_sha3_256_still_carries_hash(self):
        mapping = resolve_ioc_type("filename|sha3-256")
        result = build_observable_params(mapping, f"test.exe|{'bb' * 32}")
        obs = result[0]["observableData"]
        assert obs["name"] == "test.exe"
        assert "SHA3-256" in obs["hashes"]


class TestUserAccountTypes:
    def test_account_generic_maps_to_login(self):
        mapping = resolve_ioc_type("account")
        result = build_observable_params(mapping, "jdoe")
        assert result[0]["simple_observable_key"] == "User-Account.account_login"
        assert result[0]["simple_observable_value"] == "jdoe"

    def test_target_user_maps_to_login(self):
        mapping = resolve_ioc_type("target-user")
        result = build_observable_params(mapping, "administrator")
        assert result[0]["simple_observable_key"] == "User-Account.account_login"
        assert result[0]["simple_observable_value"] == "administrator"

    def test_eppn_maps_to_user_id(self):
        mapping = resolve_ioc_type("eppn")
        result = build_observable_params(mapping, "alice@example.edu")
        assert result[0]["simple_observable_key"] == "User-Account.user_id"
        assert result[0]["simple_observable_value"] == "alice@example.edu"

    def test_github_username_has_account_type(self):
        mapping = resolve_ioc_type("github-username")
        result = build_observable_params(mapping, "octocat")
        obs = result[0]["observableData"]
        assert obs["type"] == "user-account"
        assert obs["account_type"] == "github"
        assert obs["account_login"] == "octocat"

    def test_twitter_id_has_account_type(self):
        mapping = resolve_ioc_type("twitter-id")
        result = build_observable_params(mapping, "@threat_actor")
        obs = result[0]["observableData"]
        assert obs["type"] == "user-account"
        assert obs["account_type"] == "twitter"
        assert obs["account_login"] == "@threat_actor"
