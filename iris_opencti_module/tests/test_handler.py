"""
Unit tests for OpenCTI handler business logic.

Uses mock objects to simulate IRIS IOC and case objects and a
mocked OpenCTIClient to verify the handler orchestration without
a live OpenCTI instance.

pycti and stix2 are mocked out so tests run without the actual
OpenCTI client library installed.
"""

import sys
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

import pytest

# ── Mock out pycti and stix2 before importing our modules ───────
# This allows the handler and client modules to import without
# having pycti/stix2 installed.
_pycti_mock = MagicMock()
_stix2_mock = MagicMock()
_stix2_mock.TLP_WHITE = {"id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"}
_stix2_mock.TLP_GREEN = {"id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"}
_stix2_mock.TLP_AMBER = {"id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"}
_stix2_mock.TLP_RED = {"id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}
sys.modules.setdefault("pycti", _pycti_mock)
sys.modules.setdefault("stix2", _stix2_mock)

from iris_opencti_module.opencti_handler.opencti_handler import (
    OpenCTIHandler,
    _TLP_TAG_RE,
    _PUSHED_TAG,
    _FAILED_TAG,
)
from iris_opencti_module.opencti_handler.opencti_client import (
    OpenCTIClientError,
)


# ── Fixtures ────────────────────────────────────────────────────


def _make_config(**overrides):
    """Return a minimal valid module config dict."""
    defaults = {
        "opencti_url": "https://opencti.test",
        "opencti_api_key": "test-token-123",
        "opencti_ssl_verify": True,
        "opencti_http_proxy": "",
        "opencti_https_proxy": "",
        "opencti_create_indicator": True,
        "opencti_create_case_incident": True,
        "opencti_default_tlp": "amber",
        "opencti_author_name": "TestOrg",
        "opencti_confidence": 75,
        "opencti_case_naming_mode": "case_name",
        "opencti_case_name_prefix": "IRIS-Case",
        "opencti_case_custom_attribute": "",
        "opencti_case_description_enabled": True,
    }
    defaults.update(overrides)
    return defaults


def _make_ioc(
    value="evil.com",
    type_name="domain",
    tags="",
    description="",
    tlp=None,
    enrichment=None,
):
    """Return a mock IRIS IOC object."""
    ioc = SimpleNamespace()
    ioc.ioc_value = value
    ioc.ioc_type = SimpleNamespace(type_name=type_name)
    ioc.ioc_tags = tags
    ioc.ioc_description = description
    ioc.tlp = tlp
    ioc.ioc_enrichment = enrichment
    return ioc


def _make_case(
    case_id=42,
    name="Ransomware at ACME",
    description="Detailed case info",
    custom_attributes=None,
):
    """Return a mock IRIS case object."""
    return SimpleNamespace(
        case_id=case_id,
        name=name,
        description=description,
        custom_attributes=custom_attributes,
    )


# ── TLP tag parsing ─────────────────────────────────────────────


class TestTlpTagParsing:
    def test_extracts_tlp_green(self):
        match = _TLP_TAG_RE.search("some:tag,tlp:green,other:stuff")
        assert match is not None
        assert match.group(1) == "green"

    def test_extracts_tlp_red(self):
        match = _TLP_TAG_RE.search("tlp:red")
        assert match is not None
        assert match.group(1) == "red"

    def test_extracts_amber_strict(self):
        match = _TLP_TAG_RE.search("tlp:amber+strict,foo:bar")
        assert match is not None
        assert match.group(1) == "amber+strict"

    def test_no_tlp_tag(self):
        match = _TLP_TAG_RE.search("tag1,tag2,tag3")
        assert match is None

    def test_empty_string(self):
        match = _TLP_TAG_RE.search("")
        assert match is None


# ── Handler tests with mocked client ───────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestOpenCTIHandler:

    def test_handle_ioc_domain_success(self, MockClient):
        """Happy path: domain IOC pushed, observable created, linked to case."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = "author-id"
        client.resolve_tlp.return_value = "tlp-marking-id"
        client.create_observable.return_value = {"id": "obs-123"}
        client.find_or_create_case_incident.return_value = {"id": "case-456"}
        client.link_to_case.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="evil.example.com", type_name="domain")
        case = _make_case()

        result = handler.handle_ioc(ioc, cases_info=[case])

        assert result is True
        client.create_observable.assert_called_once()
        client.find_or_create_case_incident.assert_called_once()
        client.link_to_case.assert_called_once_with("case-456", "obs-123")
        assert _PUSHED_TAG in ioc.ioc_tags

    def test_handle_ioc_unsupported_type(self, MockClient):
        """Unsupported IOC type should be skipped gracefully."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="something", type_name="completely_unknown_xyz")

        result = handler.handle_ioc(ioc)

        assert result is False
        client.create_observable.assert_not_called()

    def test_handle_ioc_creation_failure(self, MockClient):
        """Observable creation failure should return False, not crash."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="1.2.3.4", type_name="ip-src")

        result = handler.handle_ioc(ioc)

        assert result is False

    def test_handle_ioc_no_case_when_disabled(self, MockClient):
        """When case creation is disabled, no case should be created."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-789"}

        config = _make_config(opencti_create_case_incident=False)
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc(value="1.2.3.4", type_name="ip-src")

        result = handler.handle_ioc(ioc, cases_info=[_make_case()])

        assert result is True
        client.find_or_create_case_incident.assert_not_called()

    def test_tlp_from_tag_overrides_default(self, MockClient):
        """TLP from IOC tag should be used instead of default."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-red-id"
        client.create_observable.return_value = {"id": "obs-1"}

        config = _make_config(opencti_default_tlp="green")
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc(value="evil.com", type_name="domain", tags="tlp:red,intel:high")

        handler.handle_ioc(ioc)

        # resolve_tlp should be called with "red" (from tag), not "green" (default)
        client.resolve_tlp.assert_called_with("red")

    def test_tlp_default_when_no_tag(self, MockClient):
        """Default TLP should be used when no tlp: tag is present."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-amber-id"
        client.create_observable.return_value = {"id": "obs-2"}

        config = _make_config(opencti_default_tlp="amber")
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc(value="evil.com", type_name="domain", tags="intel:medium")

        handler.handle_ioc(ioc)

        client.resolve_tlp.assert_called_with("amber")

    def test_case_naming_mode_case_id(self, MockClient):
        """case_id mode should produce 'IRIS-Case-{id}'."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-3"}
        client.find_or_create_case_incident.return_value = {"id": "case-3"}
        client.link_to_case.return_value = True

        config = _make_config(opencti_case_naming_mode="case_id")
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc()
        case = _make_case(case_id=99)

        handler.handle_ioc(ioc, cases_info=[case])

        args, kwargs = client.find_or_create_case_incident.call_args
        name = kwargs.get("name") or args[0]
        assert name == "IRIS-Case-99"

    def test_case_naming_mode_custom_prefix(self, MockClient):
        """custom_prefix_id mode should use the configured prefix."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-4"}
        client.find_or_create_case_incident.return_value = {"id": "case-4"}
        client.link_to_case.return_value = True

        config = _make_config(
            opencti_case_naming_mode="custom_prefix_id",
            opencti_case_name_prefix="IR-2026",
        )
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc()
        case = _make_case(case_id=7)

        handler.handle_ioc(ioc, cases_info=[case])

        args, kwargs = client.find_or_create_case_incident.call_args
        name = kwargs.get("name") or args[0]
        assert name == "IR-2026-7"

    def test_case_description_suppressed(self, MockClient):
        """When description is disabled, empty string should be passed."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-5"}
        client.find_or_create_case_incident.return_value = {"id": "case-5"}
        client.link_to_case.return_value = True

        config = _make_config(opencti_case_description_enabled=False)
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc()
        case = _make_case(description="Super secret customer info")

        handler.handle_ioc(ioc, cases_info=[case])

        _, kwargs = client.find_or_create_case_incident.call_args
        assert kwargs.get("description") == "" or "description" not in kwargs

    def test_tag_not_duplicated(self, MockClient):
        """If opencti:pushed tag already exists, don't add it again."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-6"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(tags="opencti:pushed,other:tag")

        handler.handle_ioc(ioc)

        assert ioc.ioc_tags.count("opencti:pushed") == 1

    def test_composite_domain_ip_creates_two_observables(self, MockClient):
        """domain|ip should create two observables."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-multi"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com|1.2.3.4", type_name="domain|ip")

        result = handler.handle_ioc(ioc)

        assert result is True
        assert client.create_observable.call_count == 2


# ── Hash-based change detection ────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestChangeDetection:

    def test_unchanged_ioc_is_skipped(self, MockClient):
        """IOC with matching hash and pushed tag should skip re-push."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )

        # Pre-compute the hash for the IOC we will create
        ioc = _make_ioc(value="evil.com", type_name="domain", tags="opencti:pushed")
        expected_hash = handler._compute_ioc_hash(ioc)
        ioc.ioc_enrichment = {"opencti_push_hash": expected_hash}

        result = handler.handle_ioc(ioc)

        assert result is True
        client.create_observable.assert_not_called()

    def test_changed_ioc_is_repushed(self, MockClient):
        """IOC with a stale hash should be re-pushed."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-re"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )

        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            tags="opencti:pushed",
            enrichment={"opencti_push_hash": "stale-hash-000"},
        )

        result = handler.handle_ioc(ioc)

        assert result is True
        client.create_observable.assert_called_once()

    def test_first_push_stores_hash(self, MockClient):
        """First successful push should store the hash in enrichment."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-first"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )

        ioc = _make_ioc(value="brand-new.com", type_name="domain")

        result = handler.handle_ioc(ioc)

        assert result is True
        assert ioc.ioc_enrichment is not None
        assert "opencti_push_hash" in ioc.ioc_enrichment
        assert len(ioc.ioc_enrichment["opencti_push_hash"]) == 64  # SHA-256

    def test_manual_trigger_ignores_hash(self, MockClient):
        """Manual trigger should re-push even if hash matches."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-manual"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        handler._is_manual = True

        ioc = _make_ioc(value="evil.com", type_name="domain", tags="opencti:pushed")
        expected_hash = handler._compute_ioc_hash(ioc)
        ioc.ioc_enrichment = {"opencti_push_hash": expected_hash}

        result = handler.handle_ioc(ioc)

        assert result is True
        client.create_observable.assert_called_once()


# ── Failed tag behaviour ────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestFailedTag:

    def test_failed_tag_on_unsupported_type(self, MockClient):
        """Unsupported type should add opencti:failed tag."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="???", type_name="unknown_xyz_999")

        handler.handle_ioc(ioc)

        assert _FAILED_TAG in ioc.ioc_tags

    def test_failed_tag_on_creation_failure(self, MockClient):
        """Failed observable creation should add opencti:failed tag."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="1.2.3.4", type_name="ip-src")

        handler.handle_ioc(ioc)

        assert _FAILED_TAG in ioc.ioc_tags

    def test_failed_tag_removed_on_success(self, MockClient):
        """Successful push should remove any existing opencti:failed tag."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-ok"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            tags="opencti:failed,intel:high",
        )

        handler.handle_ioc(ioc)

        assert _FAILED_TAG not in ioc.ioc_tags
        assert _PUSHED_TAG in ioc.ioc_tags
        assert "intel:high" in ioc.ioc_tags


# ── TLP resolution priority ────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestTlpPriority:

    def test_tlp_field_takes_priority_over_tag(self, MockClient):
        """IOC's TLP field should override tlp: tag."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-green-id"
        client.create_observable.return_value = {"id": "obs-tlp"}

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_default_tlp="amber",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        tlp_obj = SimpleNamespace(tlp_name="TLP:GREEN")
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            tags="tlp:red",
            tlp=tlp_obj,
        )

        handler.handle_ioc(ioc)

        # Should use "green" from tlp field, not "red" from tag
        client.resolve_tlp.assert_called_with("green")

    def test_tlp_tag_overrides_default(self, MockClient):
        """TLP from tag should override the config default."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-red-id"
        client.create_observable.return_value = {"id": "obs-tlp2"}

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_default_tlp="green",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain", tags="tlp:red")

        handler.handle_ioc(ioc)

        client.resolve_tlp.assert_called_with("red")

    def test_default_tlp_when_no_field_or_tag(self, MockClient):
        """Config default TLP should be used when no field or tag."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-amber-id"
        client.create_observable.return_value = {"id": "obs-tlp3"}

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_default_tlp="amber",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        client.resolve_tlp.assert_called_with("amber")


# ── Custom attribute case naming ────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestCustomAttributeNaming:

    def test_custom_attribute_naming(self, MockClient):
        """custom_attribute mode should use the value from custom_attributes."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-ca"}
        client.find_or_create_case_incident.return_value = {"id": "case-ca"}
        client.link_to_case.return_value = True

        config = _make_config(
            opencti_case_naming_mode="custom_attribute",
            opencti_case_custom_attribute="CSIRT Case ID",
        )
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc()
        case = _make_case(
            custom_attributes={
                "Identification": {
                    "CSIRT Case ID": {"type": "input_string", "value": "CSIRT-2026-042"},
                }
            }
        )

        handler.handle_ioc(ioc, cases_info=[case])

        args, kwargs = client.find_or_create_case_incident.call_args
        name = kwargs.get("name") or args[0]
        assert name == "CSIRT-2026-042"

    def test_custom_attribute_fallback_when_empty(self, MockClient):
        """Empty custom attribute should fall back to IRIS-Case-{id}."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-fb"}
        client.find_or_create_case_incident.return_value = {"id": "case-fb"}
        client.link_to_case.return_value = True

        config = _make_config(
            opencti_case_naming_mode="custom_attribute",
            opencti_case_custom_attribute="CSIRT Case ID",
        )
        handler = OpenCTIHandler(mod_config=config, logger=MagicMock())
        ioc = _make_ioc()
        case = _make_case(case_id=99, custom_attributes={})

        handler.handle_ioc(ioc, cases_info=[case])

        args, kwargs = client.find_or_create_case_incident.call_args
        name = kwargs.get("name") or args[0]
        assert name == "IRIS-Case-99"


# ── Multi-case IOC support ─────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestMultiCaseIOC:

    def test_ioc_linked_to_multiple_cases(self, MockClient):
        """IOC in multiple IRIS cases should create a case for each."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-multi-1"}
        client.find_or_create_case_incident.side_effect = [
            {"id": "octi-case-1"},
            {"id": "octi-case-2"},
            {"id": "octi-case-3"},
        ]
        client.link_to_case.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="inmultiplecases.com", type_name="domain")
        cases = [
            _make_case(case_id=4, name="#4 - test99"),
            _make_case(case_id=3, name="#3 - buuu"),
            _make_case(case_id=5, name="#5 - ir2222"),
        ]

        result = handler.handle_ioc(ioc, cases_info=cases)

        assert result is True
        assert client.find_or_create_case_incident.call_count == 3
        assert client.link_to_case.call_count == 3

        # Verify each case was created with correct name
        call_names = [
            call[1].get("name") or call[0][0]
            for call in client.find_or_create_case_incident.call_args_list
        ]
        assert "#4 - test99" in call_names
        assert "#3 - buuu" in call_names
        assert "#5 - ir2222" in call_names

    def test_synced_case_ids_stored(self, MockClient):
        """After push, all synced case IDs should be stored in enrichment."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-sc-1"}
        client.find_or_create_case_incident.return_value = {"id": "octi-c1"}
        client.link_to_case.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="test.com", type_name="domain")
        cases = [
            _make_case(case_id=10, name="Case 10"),
            _make_case(case_id=20, name="Case 20"),
        ]

        handler.handle_ioc(ioc, cases_info=cases)

        synced = ioc.ioc_enrichment.get("opencti_synced_case_ids", [])
        assert "10" in synced
        assert "20" in synced

    def test_new_case_bypasses_hash_guard(self, MockClient):
        """IOC already pushed should still sync when linked to a new case."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-hg-1"}
        client.find_or_create_case_incident.return_value = {"id": "octi-new"}
        client.link_to_case.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())

        # Simulate an IOC that was already pushed to case 4
        ioc = _make_ioc(
            value="repeat.com",
            type_name="domain",
            tags="opencti:pushed",
            enrichment={
                "opencti_push_hash": handler._compute_ioc_hash(
                    _make_ioc(value="repeat.com", type_name="domain", tags="opencti:pushed")
                ),
                "opencti_observable_ids": ["obs-hg-1"],
                "opencti_synced_case_ids": ["4"],
            },
        )

        # Now the IOC is also in case 5 (new)
        cases = [
            _make_case(case_id=4, name="Old Case"),
            _make_case(case_id=5, name="New Case"),
        ]

        result = handler.handle_ioc(ioc, cases_info=cases)

        assert result is True
        # Should still process because case 5 is new
        client.create_observable.assert_called_once()
        assert client.find_or_create_case_incident.call_count == 2

    def test_no_new_cases_hash_match_skips(self, MockClient):
        """IOC with same hash and all cases already synced should be skipped."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())

        ioc = _make_ioc(
            value="stable.com",
            type_name="domain",
            tags="opencti:pushed",
            enrichment={
                "opencti_push_hash": handler._compute_ioc_hash(
                    _make_ioc(value="stable.com", type_name="domain", tags="opencti:pushed")
                ),
                "opencti_observable_ids": ["obs-old"],
                "opencti_synced_case_ids": ["4", "5"],
            },
        )

        cases = [
            _make_case(case_id=4, name="Case 4"),
            _make_case(case_id=5, name="Case 5"),
        ]

        result = handler.handle_ioc(ioc, cases_info=cases)

        assert result is True
        # Should skip — nothing changed
        client.create_observable.assert_not_called()

    def test_empty_cases_list_no_case_created(self, MockClient):
        """Empty cases list should not create any case incident."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-nc-1"}

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="nocase.com", type_name="domain")

        result = handler.handle_ioc(ioc, cases_info=[])

        assert result is True
        client.find_or_create_case_incident.assert_not_called()

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_shows_multiple_cases(self, mock_add_tab, MockClient):
        """Enrichment tab HTML should list all linked case names."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-et-1"}
        client.find_or_create_case_incident.side_effect = [
            {"id": "c1"},
            {"id": "c2"},
        ]
        client.link_to_case.return_value = True
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="multi.com", type_name="domain")
        cases = [
            _make_case(case_id=1, name="Alpha Case"),
            _make_case(case_id=2, name="Beta Case"),
        ]

        handler.handle_ioc(ioc, cases_info=cases)

        mock_add_tab.assert_called_once()
        html = mock_add_tab.call_args[1]["field_value"]
        assert "Alpha Case" in html
        assert "Beta Case" in html
        assert "Case Incidents (2)" in html


# ── OpenCTI ID storage ─────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestOpenCTIIdStorage:

    def test_ids_stored_on_success(self, MockClient):
        """Successful push should store observable IDs in enrichment."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-stored-1"}

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        assert ioc.ioc_enrichment is not None
        assert ioc.ioc_enrichment["opencti_observable_ids"] == ["obs-stored-1"]

    def test_ids_not_stored_on_failure(self, MockClient):
        """Failed push should not store any IDs."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = None

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        enrichment = ioc.ioc_enrichment or {}
        assert enrichment.get("opencti_observable_ids") is None

    def test_get_opencti_ids_round_trip(self, MockClient):
        """_store_opencti_ids / _get_opencti_ids round-trip."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc()

        handler._store_opencti_ids(ioc, ["id-a", "id-b"])
        result = handler._get_opencti_ids(ioc)

        assert result == ["id-a", "id-b"]

    def test_get_opencti_ids_empty_enrichment(self, MockClient):
        """No enrichment should return empty list."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc()

        result = handler._get_opencti_ids(ioc)

        assert result == []


# ── Deletion handler ───────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestDeletion:

    def test_delete_with_stored_ids(self, MockClient):
        """IOC with stored OpenCTI IDs should trigger deletion calls."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.delete_observable.return_value = True
        client.get_container_ids.return_value = ["case-uuid-ours"]  # only our case

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            enrichment={
                "opencti_observable_ids": ["obs-del-1", "obs-del-2"],
                "opencti_synced_case_opencti_ids": ["case-uuid-ours"],
            },
        )

        result = handler.handle_ioc_delete(ioc)

        assert result is True
        assert client.delete_observable.call_count == 2
        client.delete_observable.assert_any_call("obs-del-1")
        client.delete_observable.assert_any_call("obs-del-2")

    def test_delete_without_stored_ids(self, MockClient):
        """IOC with no stored IDs should succeed with nothing to delete."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="evil.com", type_name="domain")

        result = handler.handle_ioc_delete(ioc)

        assert result is True
        client.delete_observable.assert_not_called()

    def test_delete_partial_failure(self, MockClient):
        """If one deletion fails, result should be False."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.delete_observable.side_effect = [True, False]
        client.get_container_ids.return_value = ["case-uuid-ours"]

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            enrichment={
                "opencti_observable_ids": ["obs-ok", "obs-fail"],
                "opencti_synced_case_opencti_ids": ["case-uuid-ours"],
            },
        )

        result = handler.handle_ioc_delete(ioc)

        assert result is False

    def test_delete_fallback_skips_when_no_case_uuids_stored(self, MockClient):
        """Old IOCs without opencti_synced_case_opencti_ids are skipped safely."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(
            value="old.com",
            type_name="domain",
            # Only IRIS int case ID stored, no OpenCTI UUID
            enrichment={"opencti_observable_ids": ["obs-old"]},
        )

        result = handler.handle_ioc_delete(ioc)

        assert result is True
        client.delete_observable.assert_not_called()
        client.get_container_ids.assert_not_called()

    def test_delete_shared_observable_unlinks_not_deletes(self, MockClient):
        """Observable shared with non-IRIS containers is unlinked, not deleted."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        our_case_uuid = "case-uuid-ours"
        external_uuid = "report-uuid-external"
        client.get_container_ids.return_value = [our_case_uuid, external_uuid]
        client.unlink_from_case.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            enrichment={
                "opencti_observable_ids": ["obs-shared"],
                # OpenCTI UUIDs of our cases (not IRIS int IDs)
                "opencti_synced_case_opencti_ids": [our_case_uuid],
            },
        )

        result = handler.handle_ioc_delete(ioc)

        assert result is True
        client.delete_observable.assert_not_called()
        client.unlink_from_case.assert_called_once_with(our_case_uuid, "obs-shared")

    def test_delete_sole_owner_hard_deletes(self, MockClient):
        """Observable only in our IRIS cases is hard-deleted."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        our_case_uuid = "case-uuid-ours"
        client.get_container_ids.return_value = [our_case_uuid]  # only our case
        client.delete_observable.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            enrichment={
                "opencti_observable_ids": ["obs-1"],
                "opencti_synced_case_opencti_ids": [our_case_uuid],
            },
        )

        result = handler.handle_ioc_delete(ioc)

        assert result is True
        client.delete_observable.assert_called_once_with("obs-1")
        client.unlink_from_case.assert_not_called()

    def test_delete_multiple_observables_all_deleted(self, MockClient):
        """All stored observable IDs are deleted when no external containers."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.get_container_ids.return_value = ["case-uuid-ours"]
        client.delete_observable.return_value = True

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(
            value="evil.com",
            type_name="domain",
            enrichment={
                "opencti_observable_ids": ["obs-1", "obs-2"],
                "opencti_synced_case_opencti_ids": ["case-uuid-ours"],
            },
        )

        result = handler.handle_ioc_delete(ioc)

        assert result is True
        assert client.delete_observable.call_count == 2


# ── Tag helper edge cases ──────────────────────────────────────


class TestTagHelpers:

    def test_add_tag_to_empty(self):
        ioc = _make_ioc(tags="")
        OpenCTIHandler._add_tag(ioc, "test:tag")
        assert ioc.ioc_tags == "test:tag"

    def test_add_tag_to_existing(self):
        ioc = _make_ioc(tags="existing:tag")
        OpenCTIHandler._add_tag(ioc, "test:tag")
        assert ioc.ioc_tags == "existing:tag,test:tag"

    def test_add_tag_no_duplicate(self):
        ioc = _make_ioc(tags="test:tag,other:tag")
        OpenCTIHandler._add_tag(ioc, "test:tag")
        assert ioc.ioc_tags.count("test:tag") == 1

    def test_remove_tag(self):
        ioc = _make_ioc(tags="keep:this,remove:me,also:keep")
        OpenCTIHandler._remove_tag(ioc, "remove:me")
        assert ioc.ioc_tags == "keep:this,also:keep"

    def test_remove_tag_not_present(self):
        ioc = _make_ioc(tags="keep:this")
        OpenCTIHandler._remove_tag(ioc, "not:here")
        assert ioc.ioc_tags == "keep:this"

    def test_remove_tag_from_none(self):
        ioc = _make_ioc(tags="")
        OpenCTIHandler._remove_tag(ioc, "any:tag")
        assert ioc.ioc_tags == ""


# ── Hash computation ───────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestHashComputation:

    def test_same_ioc_produces_same_hash(self, MockClient):
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())

        ioc1 = _make_ioc(value="evil.com", type_name="domain", description="bad")
        ioc2 = _make_ioc(value="evil.com", type_name="domain", description="bad")

        assert handler._compute_ioc_hash(ioc1) == handler._compute_ioc_hash(ioc2)

    def test_different_value_different_hash(self, MockClient):
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())

        ioc1 = _make_ioc(value="evil.com", type_name="domain")
        ioc2 = _make_ioc(value="other.com", type_name="domain")

        assert handler._compute_ioc_hash(ioc1) != handler._compute_ioc_hash(ioc2)

    def test_different_description_different_hash(self, MockClient):
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())

        ioc1 = _make_ioc(value="evil.com", type_name="domain", description="v1")
        ioc2 = _make_ioc(value="evil.com", type_name="domain", description="v2")

        assert handler._compute_ioc_hash(ioc1) != handler._compute_ioc_hash(ioc2)

    def test_tag_change_does_not_affect_hash(self, MockClient):
        """Tags are deliberately excluded to avoid infinite loops."""
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())

        ioc1 = _make_ioc(value="evil.com", type_name="domain", tags="")
        ioc2 = _make_ioc(value="evil.com", type_name="domain", tags="opencti:pushed")

        assert handler._compute_ioc_hash(ioc1) == handler._compute_ioc_hash(ioc2)


# ── Enrichment tab ─────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestEnrichmentTab:

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_written_on_success(self, mock_add_tab, MockClient):
        """Successful push should write an OpenCTI enrichment tab."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-enrich-1"}
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        mock_add_tab.assert_called_once()
        call_kwargs = mock_add_tab.call_args
        assert call_kwargs[1]["tab_name"] == "OpenCTI"
        assert call_kwargs[1]["field_type"] == "html"
        assert "obs-enrich-1" in call_kwargs[1]["field_value"]

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_includes_case_name(self, mock_add_tab, MockClient):
        """Enrichment tab should include linked case name."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-enrich-2"}
        client.find_or_create_case_incident.return_value = {"id": "case-enrich"}
        client.link_to_case.return_value = True
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(
            mod_config=_make_config(),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")
        case = _make_case(name="Phishing at ACME")

        handler.handle_ioc(ioc, cases_info=[case])

        mock_add_tab.assert_called_once()
        html = mock_add_tab.call_args[1]["field_value"]
        assert "Phishing at ACME" in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_not_written_on_failure(self, mock_add_tab, MockClient):
        """Failed push should NOT write an enrichment tab."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = None  # failure
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        mock_add_tab.assert_not_called()

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_contains_clickable_link(self, mock_add_tab, MockClient):
        """Enrichment should contain a link to the OpenCTI observable."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-link-test"}
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "https://opencti.example.com/dashboard/observations/observables/obs-link-test" in html
        assert 'target="_blank"' in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_shows_containers(self, mock_add_tab, MockClient):
        """Containers (reports, cases) fetched via enrichment should appear in the HTML."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-ctr-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-ctr-1",
            "value": "evil.com",
            "score": 80,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [
                {"id": "report-1", "type": "Report", "name": "Weekly Threat Intel", "date": "2025-06-01"},
                {"id": "case-1", "type": "Case-Incident", "name": "#42 - Phishing", "date": "2025-05-20"},
            ],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Containers (2)" in html
        assert "Weekly Threat Intel" in html
        assert "#42 - Phishing" in html
        assert "analyses/reports/report-1" in html
        assert "cases/incidents/case-1" in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_shows_score_and_labels(self, mock_add_tab, MockClient):
        """Enrichment v2 should render score badge and label pills."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-v2-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-v2-1",
            "value": "evil.com",
            "score": 90,
            "description": "Known malware C2",
            "created_by": "ThreatTeam",
            "labels": [
                {"value": "malware", "color": "#ff0000"},
                {"value": "apt", "color": "#0000ff"},
            ],
            "indicators": [
                {"pattern": "[domain-name:value = 'evil.com']", "pattern_type": "stix"},
            ],
            "external_references": [
                {"source": "VirusTotal", "url": "https://vt.example.com/evil.com"},
            ],
            "containers": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        # Score
        assert "90" in html
        # Labels
        assert "malware" in html
        assert "apt" in html
        # Indicator pattern
        assert "[domain-name:value = &#x27;evil.com&#x27;]" in html or "domain-name:value" in html
        # External reference
        assert "VirusTotal" in html
        assert "https://vt.example.com/evil.com" in html
        # Description
        assert "Known malware C2" in html
        # Author
        assert "ThreatTeam" in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_enrichment_tab_no_containers_no_section(self, mock_add_tab, MockClient):
        """When no containers exist, the Containers section should not appear."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-noctr"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-noctr",
            "value": "clean.com",
            "score": 10,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="clean.com", type_name="domain")

        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Containers" not in html


# ── Threat context & sightings in enrichment tab ───────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestThreatContextEnrichment:
    """Tests for threat context (actors, malware, campaigns, ATT&CK) rendering."""

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_threat_actors_displayed(self, mock_add_tab, MockClient):
        """Linked threat actors should appear in the enrichment tab."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-ta-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-ta-1",
            "value": "evil.com",
            "score": 85,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [
                    {"id": "ta-001", "name": "APT28", "description": "Russian state-sponsored"},
                    {"id": "ta-002", "name": "Lazarus Group"},
                ],
                "intrusion_sets": [],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [],
            },
            "sightings": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Threat Actors (2)" in html
        assert "APT28" in html
        assert "Lazarus Group" in html
        assert "threats/threat_actors/ta-001" in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_malware_and_campaigns_displayed(self, mock_add_tab, MockClient):
        """Linked malware and campaigns should appear in separate sections."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-mc-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-mc-1",
            "value": "1.2.3.4",
            "score": 70,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [],
                "malware": [
                    {"id": "mal-001", "name": "Emotet"},
                ],
                "campaigns": [
                    {"id": "camp-001", "name": "Operation Aurora"},
                ],
                "attack_patterns": [],
            },
            "sightings": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="1.2.3.4", type_name="ip-src")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Malware (1)" in html
        assert "Emotet" in html
        assert "arsenal/malware/mal-001" in html
        assert "Campaigns (1)" in html
        assert "Operation Aurora" in html
        assert "threats/campaigns/camp-001" in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_attack_patterns_with_mitre_id(self, mock_add_tab, MockClient):
        """ATT&CK techniques should show MITRE ID prefixes."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-att-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-att-1",
            "value": "evil.com",
            "score": 60,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [
                    {"id": "ap-001", "name": "Spearphishing Attachment", "mitre_id": "T1566.001"},
                    {"id": "ap-002", "name": "Command and Scripting Interpreter", "mitre_id": "T1059"},
                ],
            },
            "sightings": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "ATT&amp;CK Techniques (2)" in html or "ATT&CK Techniques (2)" in html
        assert "T1566.001" in html
        assert "T1059" in html
        assert "Spearphishing Attachment" in html
        assert "techniques/attack_patterns/ap-001" in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_no_threat_context_no_sections(self, mock_add_tab, MockClient):
        """When no threat context exists, those sections should not appear."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-notc"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-notc",
            "value": "clean.com",
            "score": 5,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [],
            },
            "sightings": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="clean.com", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Threat Actors" not in html
        assert "Malware" not in html
        assert "Campaigns" not in html
        assert "ATT&CK" not in html and "ATT&amp;CK" not in html
        assert "Sightings" not in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_threat_context_missing_key_graceful(self, mock_add_tab, MockClient):
        """Missing threat_context key should not crash."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-nokey"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-nokey",
            "value": "test.com",
            "score": 20,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            # No "threat_context" key at all
            # No "sightings" key at all
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="test.com", type_name="domain")

        # Should not raise
        result = handler.handle_ioc(ioc)
        assert result is True

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_intrusion_sets_displayed(self, mock_add_tab, MockClient):
        """Intrusion sets should appear with correct URL path."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-is-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-is-1",
            "value": "evil.com",
            "score": 75,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [
                    {"id": "is-001", "name": "Cozy Bear"},
                ],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [],
            },
            "sightings": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Intrusion Sets (1)" in html
        assert "Cozy Bear" in html
        assert "threats/intrusion_sets/is-001" in html


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestSightingsEnrichment:
    """Tests for sighting history rendering."""

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_sightings_displayed(self, mock_add_tab, MockClient):
        """Sightings should appear with source, count and date range."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-sig-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-sig-1",
            "value": "evil.com",
            "score": 80,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [],
            },
            "sightings": [
                {
                    "source": "CERT-EU",
                    "first_seen": "2025-01-15T00:00:00Z",
                    "last_seen": "2025-06-20T00:00:00Z",
                    "count": "14",
                    "description": "",
                },
                {
                    "source": "Internal SOC",
                    "first_seen": "2025-03-01T00:00:00Z",
                    "last_seen": "2025-03-01T00:00:00Z",
                    "count": "1",
                    "description": "",
                },
            ],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Sightings (2)" in html
        assert "CERT-EU" in html
        assert "Internal SOC" in html
        assert "14x" in html  # count badge
        assert "2025-01-15" in html  # first seen date
        assert "2025-06-20" in html  # last seen date

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_sightings_single_count_no_badge(self, mock_add_tab, MockClient):
        """Single-count sightings should not show a count badge."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-sig-2"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-sig-2",
            "value": "clean.org",
            "score": 10,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [],
            },
            "sightings": [
                {
                    "source": "Partner Feed",
                    "first_seen": "2025-05-01T00:00:00Z",
                    "last_seen": "",
                    "count": "1",
                    "description": "",
                },
            ],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="clean.org", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Sightings (1)" in html
        assert "Partner Feed" in html
        assert "1x" not in html  # no badge for count=1
        assert "from 2025-05-01" in html  # only first_seen, no arrow

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_no_sightings_no_section(self, mock_add_tab, MockClient):
        """Empty sightings list should not render a section."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-nosig"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-nosig",
            "value": "clean.com",
            "score": 5,
            "labels": [],
            "indicators": [],
            "external_references": [],
            "containers": [],
            "threat_context": {
                "threat_actors": [],
                "intrusion_sets": [],
                "malware": [],
                "campaigns": [],
                "attack_patterns": [],
            },
            "sightings": [],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="clean.com", type_name="domain")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]
        assert "Sightings" not in html

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_full_enrichment_all_sections(self, mock_add_tab, MockClient):
        """Integration: all enrichment sections present together."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-full-1"}
        client.get_observable_enrichment.return_value = {
            "id": "obs-full-1",
            "entity_type": "IPv4-Addr",
            "value": "10.0.0.1",
            "score": 95,
            "description": "Known C2 server",
            "created_by": "ThreatTeam",
            "labels": [{"value": "c2", "color": "#ff0000"}],
            "markings": ["TLP:RED"],
            "indicators": [
                {"pattern": "[ipv4-addr:value = '10.0.0.1']", "pattern_type": "stix"},
            ],
            "external_references": [
                {"source": "AbuseIPDB", "url": "https://abuseipdb.com/10.0.0.1"},
            ],
            "containers": [
                {"id": "report-99", "type": "Report", "name": "APT28 Infrastructure", "date": "2025-07-01"},
            ],
            "threat_context": {
                "threat_actors": [
                    {"id": "ta-28", "name": "APT28"},
                ],
                "intrusion_sets": [
                    {"id": "is-fb", "name": "Fancy Bear"},
                ],
                "malware": [
                    {"id": "mal-xagent", "name": "X-Agent"},
                ],
                "campaigns": [
                    {"id": "camp-gru", "name": "GRU Campaign 2025"},
                ],
                "attack_patterns": [
                    {"id": "ap-t1071", "name": "Application Layer Protocol", "mitre_id": "T1071"},
                ],
            },
            "sightings": [
                {
                    "source": "NATO CERT",
                    "first_seen": "2025-02-01T00:00:00Z",
                    "last_seen": "2025-06-15T00:00:00Z",
                    "count": "42",
                    "description": "",
                },
            ],
        }

        handler = OpenCTIHandler(
            mod_config=_make_config(
                opencti_url="https://opencti.example.com",
                opencti_create_case_incident=False,
            ),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="10.0.0.1", type_name="ip-src")
        handler.handle_ioc(ioc)

        html = mock_add_tab.call_args[1]["field_value"]

        # All sections present
        assert "95" in html  # score
        assert "c2" in html  # label
        assert "Known C2 server" in html  # description
        assert "APT28 Infrastructure" in html  # container
        assert "Threat Actors (1)" in html
        assert "APT28" in html
        assert "Intrusion Sets (1)" in html
        assert "Fancy Bear" in html
        assert "Malware (1)" in html
        assert "X-Agent" in html
        assert "Campaigns (1)" in html
        assert "GRU Campaign 2025" in html
        assert "T1071" in html  # MITRE ID
        assert "Application Layer Protocol" in html
        assert "Sightings (1)" in html
        assert "NATO CERT" in html
        assert "42x" in html  # sighting count


# ── Bug fix: failed cases not stored as synced ──────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestFailedCaseSyncTracking:
    """
    Verify that only *successfully* synced IRIS case IDs are stored in
    ``opencti_synced_case_ids``.  Previously, all case IDs from
    ``cases_info`` were stored even when ``find_or_create_case_incident``
    returned ``None`` for some.
    """

    def test_failed_case_not_stored_as_synced(self, MockClient, _mock_tab):
        """Case that fails to create in OpenCTI must NOT be marked synced."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-id"
        client.create_observable.return_value = {"id": "obs-1"}
        # Case 1 succeeds, case 2 fails
        client.find_or_create_case_incident.side_effect = [
            {"id": "octi-case-1", "name": "Case1"},
            None,
        ]
        client.link_to_case.return_value = True
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="evil.com", type_name="domain")
        case1 = _make_case(case_id=10, name="Case1")
        case2 = _make_case(case_id=20, name="Case2")

        handler.handle_ioc(ioc, cases_info=[case1, case2])

        synced = set(ioc.ioc_enrichment.get("opencti_synced_case_ids", []))
        assert "10" in synced, "Successful case should be stored"
        assert "20" not in synced, "Failed case should NOT be stored"

    def test_all_cases_succeed_all_stored(self, MockClient, _mock_tab):
        """When all cases succeed, all IDs are stored."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = "tlp-id"
        client.create_observable.return_value = {"id": "obs-1"}
        client.find_or_create_case_incident.side_effect = [
            {"id": "octi-case-1", "name": "Case1"},
            {"id": "octi-case-2", "name": "Case2"},
        ]
        client.link_to_case.return_value = True
        client.get_observable_enrichment.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = _make_ioc(value="evil.com", type_name="domain")

        handler.handle_ioc(
            ioc,
            cases_info=[
                _make_case(case_id=10, name="Case1"),
                _make_case(case_id=20, name="Case2"),
            ],
        )

        synced = set(ioc.ioc_enrichment.get("opencti_synced_case_ids", []))
        assert synced == {"10", "20"}


# ── XSS prevention in enrichment HTML ───────────────────────────


class TestEnrichmentHtmlEscaping:
    """Verify user-controlled values are HTML-escaped in the enrichment tab."""

    def test_ioc_value_escaped(self):
        from iris_opencti_module.opencti_handler.enrichment_renderer import render_enrichment_html

        html = render_enrichment_html(
            enrichments=[{
                "id": "obs-1",
                "entity_type": "Domain-Name",
                "value": '<img src=x onerror=alert(1)>',
                "score": None,
            }],
            opencti_url="",
            case_names=[],
            tlp_name="amber",
            synced_at="2025-01-01",
        )
        assert "<img src=x onerror=alert(1)>" not in html
        assert "&lt;img" in html

    def test_case_name_escaped(self):
        from iris_opencti_module.opencti_handler.enrichment_renderer import render_enrichment_html

        html = render_enrichment_html(
            enrichments=[{"id": "obs-1"}],
            opencti_url="",
            case_names=['<script>alert("xss")</script>'],
            tlp_name="amber",
            synced_at="2025-01-01",
        )
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_description_escaped(self):
        from iris_opencti_module.opencti_handler.enrichment_renderer import render_enrichment_html

        html = render_enrichment_html(
            enrichments=[{
                "id": "obs-1",
                "value": "test.com",
                "description": '<b onmouseover="alert(1)">hover</b>',
            }],
            opencti_url="",
            case_names=[],
            tlp_name="amber",
            synced_at="2025-01-01",
        )
        assert 'onmouseover="alert(1)"' not in html
        assert "&lt;b" in html

    def test_javascript_url_blocked(self):
        from iris_opencti_module.opencti_handler.enrichment_renderer import render_enrichment_html

        html = render_enrichment_html(
            enrichments=[{
                "id": "obs-1",
                "value": "test.com",
                "external_references": [{
                    "source": "evil",
                    "url": "javascript:alert(document.cookie)",
                    "description": "",
                    "external_id": "",
                }],
            }],
            opencti_url="",
            case_names=[],
            tlp_name="amber",
            synced_at="2025-01-01",
        )
        assert "javascript:" not in html

    def test_label_value_escaped(self):
        from iris_opencti_module.opencti_handler.enrichment_renderer import render_enrichment_html

        html = render_enrichment_html(
            enrichments=[{
                "id": "obs-1",
                "value": "test.com",
                "labels": [{"value": "<script>xss</script>", "color": "#f00"}],
            }],
            opencti_url="",
            case_names=[],
            tlp_name="amber",
            synced_at="2025-01-01",
        )
        assert "<script>xss</script>" not in html
        assert "&lt;script&gt;" in html

    def test_sighting_source_escaped(self):
        from iris_opencti_module.opencti_handler.enrichment_renderer import render_enrichment_html

        html = render_enrichment_html(
            enrichments=[{
                "id": "obs-1",
                "value": "test.com",
                "sightings": [{
                    "source": '<img src=x onerror=alert(3)>',
                    "first_seen": "",
                    "last_seen": "",
                    "count": "1",
                }],
            }],
            opencti_url="",
            case_names=[],
            tlp_name="amber",
            synced_at="2025-01-01",
        )
        assert "<img src=x onerror=alert(3)>" not in html
        assert "&lt;img" in html


# ── Case search ────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestCaseSearchByName:
    """Tests for _search_case_by_name (OpenCTI 6.x eq filter)."""

    def _make_client(self, MockApiClient):
        from iris_opencti_module.opencti_handler.opencti_client import OpenCTIClient
        return OpenCTIClient(
            url="https://opencti.test",
            api_key="test-key",
            ssl_verify=False,
            logger=MagicMock(),
        )

    def test_filter_finds_exact_match(self, MockApiClient):
        """Filter-based search returns exact match."""
        client = self._make_client(MockApiClient)
        api = MockApiClient.return_value
        api.case_incident.list.return_value = [
            {"id": "c1", "name": "IR4601"},
        ]

        result = client._search_case_by_name("IR4601")

        assert result is not None
        assert result["name"] == "IR4601"
        assert api.case_incident.list.call_count == 1

    def test_filter_fails_returns_none(self, MockApiClient):
        """When the filter call raises, returns None."""
        client = self._make_client(MockApiClient)
        api = MockApiClient.return_value
        api.case_incident.list.side_effect = Exception("network error")

        result = client._search_case_by_name("IR4601")

        assert result is None
        assert api.case_incident.list.call_count == 1

    def test_no_match_returns_none(self, MockApiClient):
        """Filter returns results but none match exactly — returns None."""
        client = self._make_client(MockApiClient)
        api = MockApiClient.return_value
        api.case_incident.list.return_value = [
            {"id": "c10", "name": "IR46010"},
            {"id": "c11", "name": "IR46011"},
        ]

        result = client._search_case_by_name("IR4601")

        assert result is None


# ── Handler initialisation edge cases ──────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestHandlerInit:

    def test_missing_url_raises(self, MockClient):
        """Empty URL should raise OpenCTIClientError."""
        config = _make_config(opencti_url="", opencti_api_key="some-key")
        with pytest.raises(OpenCTIClientError, match="URL and API key must be configured"):
            OpenCTIHandler(mod_config=config, logger=MagicMock())

    def test_missing_api_key_raises(self, MockClient):
        """Empty API key should raise OpenCTIClientError."""
        config = _make_config(opencti_url="https://opencti.test", opencti_api_key="")
        with pytest.raises(OpenCTIClientError, match="URL and API key must be configured"):
            OpenCTIHandler(mod_config=config, logger=MagicMock())

    def test_confidence_clamped_high(self, MockClient):
        """Confidence > 100 should be clamped to 100."""
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_confidence=200), logger=MagicMock()
        )
        assert handler._confidence == 100

    def test_confidence_clamped_low(self, MockClient):
        """Confidence < 0 should be clamped to 0."""
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_confidence=-50), logger=MagicMock()
        )
        assert handler._confidence == 0

    def test_confidence_invalid_string_defaults(self, MockClient):
        """Non-numeric confidence should default to 50."""
        MockClient.return_value.resolve_or_create_author.return_value = None
        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_confidence="not-a-number"), logger=MagicMock()
        )
        assert handler._confidence == 50


# ── Synced case ID merging ─────────────────────────────────────


class TestSyncedCaseIdMerging:

    def test_merge_preserves_existing_ids(self):
        """New case IDs merge with previously stored ones."""
        ioc = _make_ioc(enrichment={
            "opencti_synced_case_ids": ["1", "2"],
        })

        OpenCTIHandler._store_synced_case_ids(ioc, {"3", "4"})

        synced = set(ioc.ioc_enrichment["opencti_synced_case_ids"])
        assert synced == {"1", "2", "3", "4"}

    def test_merge_deduplicates(self):
        """Storing already-known IDs should not create duplicates."""
        ioc = _make_ioc(enrichment={
            "opencti_synced_case_ids": ["1", "2"],
        })

        OpenCTIHandler._store_synced_case_ids(ioc, {"2", "3"})

        synced = ioc.ioc_enrichment["opencti_synced_case_ids"]
        assert sorted(synced) == ["1", "2", "3"]

    def test_merge_with_no_existing(self):
        """Storing IDs when no enrichment exists should work."""
        ioc = _make_ioc()

        OpenCTIHandler._store_synced_case_ids(ioc, {"5"})

        synced = ioc.ioc_enrichment["opencti_synced_case_ids"]
        assert synced == ["5"]


# ── Null ioc_type handling ─────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestNullIocType:

    def test_none_ioc_type_returns_false(self, MockClient):
        """IOC with ioc_type=None should fail gracefully."""
        MockClient.return_value.resolve_or_create_author.return_value = None

        handler = OpenCTIHandler(mod_config=_make_config(), logger=MagicMock())
        ioc = SimpleNamespace(
            ioc_value="something",
            ioc_type=None,
            ioc_tags="",
            ioc_description="",
            tlp=None,
            ioc_enrichment=None,
        )

        result = handler.handle_ioc(ioc)

        assert result is False
        assert _FAILED_TAG in ioc.ioc_tags


# ── Enrichment tab error resilience ────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_handler.OpenCTIClient")
class TestEnrichmentTabErrorResilience:

    @patch("iris_opencti_module.opencti_handler.opencti_handler.add_tab_attribute_field")
    def test_tab_write_exception_does_not_crash(self, mock_add_tab, MockClient):
        """If add_tab_attribute_field raises, handle_ioc should still succeed."""
        client = MockClient.return_value
        client.resolve_or_create_author.return_value = None
        client.resolve_tlp.return_value = None
        client.create_observable.return_value = {"id": "obs-err"}
        client.get_observable_enrichment.return_value = None
        mock_add_tab.side_effect = RuntimeError("DB write failed")

        handler = OpenCTIHandler(
            mod_config=_make_config(opencti_create_case_incident=False),
            logger=MagicMock(),
        )
        ioc = _make_ioc(value="evil.com", type_name="domain")

        result = handler.handle_ioc(ioc)

        # Should still succeed — enrichment tab is non-critical
        assert result is True
        assert _PUSHED_TAG in ioc.ioc_tags


# ── Custom attribute extraction edge cases ─────────────────────


class TestExtractCustomAttribute:

    def test_nested_section_search(self):
        """Attribute found in second section should still be returned."""
        case = _make_case(custom_attributes={
            "Section A": {
                "Other Field": {"type": "input_string", "value": "irrelevant"},
            },
            "Section B": {
                "Target": {"type": "input_string", "value": "found-it"},
            },
        })
        result = OpenCTIHandler._extract_custom_attribute(case, "Target")
        assert result == "found-it"

    def test_non_dict_section_skipped(self):
        """Non-dict section value should be safely skipped."""
        case = _make_case(custom_attributes={
            "BadSection": "just a string",
            "GoodSection": {
                "MyAttr": {"type": "input_string", "value": "ok"},
            },
        })
        result = OpenCTIHandler._extract_custom_attribute(case, "MyAttr")
        assert result == "ok"

    def test_none_custom_attributes(self):
        """None custom_attributes should return None."""
        case = _make_case(custom_attributes=None)
        result = OpenCTIHandler._extract_custom_attribute(case, "Anything")
        assert result is None

    def test_empty_value_returns_none(self):
        """Whitespace-only value should return None."""
        case = _make_case(custom_attributes={
            "Section": {
                "Field": {"type": "input_string", "value": "   "},
            },
        })
        result = OpenCTIHandler._extract_custom_attribute(case, "Field")
        assert result is None

    def test_empty_attr_name_returns_none(self):
        """Empty attribute name should return None."""
        case = _make_case(custom_attributes={"Section": {"X": {"value": "y"}}})
        result = OpenCTIHandler._extract_custom_attribute(case, "")
        assert result is None
