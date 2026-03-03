"""
pytest configuration and shared test utilities.

Mocks pycti and stix2 only when they are NOT installed, so that
test files can import the module code in environments without a
real OpenCTI installation.

When pycti IS installed (e.g. host dev environment with the same
version as the containers), the real library is used, which allows
the live integration tests to also run against a real OpenCTI.

Helper factories (_make_config, _make_ioc, _make_case) are defined
here so that new test files can import them directly:

    from iris_opencti_module.tests.conftest import _make_config, _make_ioc, _make_case
"""

import importlib.util
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

# ── Conditionally mock pycti / stix2 ─────────────────────────────────────────
# Only inject mocks for packages that cannot be genuinely imported.
# This lets host environments with pycti installed run integration tests
# while CI/containers without pycti still work for unit tests.

def _needs_mock(package: str) -> bool:
    return importlib.util.find_spec(package) is None

if _needs_mock("pycti"):
    _pycti_mock = MagicMock()
    sys.modules.setdefault("pycti", _pycti_mock)
else:
    import pycti  # eagerly load so test_handler.py's setdefault is a no-op

if _needs_mock("stix2"):
    _stix2_mock = MagicMock()
    _stix2_mock.TLP_WHITE = {"id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"}
    _stix2_mock.TLP_GREEN = {"id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"}
    _stix2_mock.TLP_AMBER = {"id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"}
    _stix2_mock.TLP_RED = {"id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}
    sys.modules.setdefault("stix2", _stix2_mock)
else:
    import stix2  # noqa: F401


# ── Shared helper factories ───────────────────────────────────────────────────


def _make_config(**overrides) -> dict:
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
    ioc.ioc_id = 1
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
