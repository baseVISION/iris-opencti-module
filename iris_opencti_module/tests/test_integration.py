"""
Integration tests against a live OpenCTI instance.

These tests are **skipped automatically** unless the environment
variables ``OPENCTI_URL`` and ``OPENCTI_TOKEN`` are set:

    export OPENCTI_URL=http://localhost:8080
    export OPENCTI_TOKEN=<your-api-key>
    python -m pytest iris_opencti_module/tests/test_integration.py -v

They can also be run as a standalone script for manual smoke testing:

    python -m iris_opencti_module.tests.test_integration

Requires pycti to be installed: pip install pycti>=6.0,<7.0
"""

from __future__ import annotations

import os
import sys
import types

import pytest

# ── Skip guard ────────────────────────────────────────────────────────────────

_OPENCTI_URL = os.environ.get("OPENCTI_URL", "")
_OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# conftest.py eagerly imports pycti when installed, so sys.modules["pycti"]
# is the real module here.  A MagicMock means pycti is not installed.
_PYCTI_REAL = isinstance(sys.modules.get("pycti"), types.ModuleType)

_LIVE_MARK = pytest.mark.skipif(
    not (_OPENCTI_URL and _OPENCTI_TOKEN) or not _PYCTI_REAL,
    reason="Live OpenCTI required: install pycti and set OPENCTI_URL / OPENCTI_TOKEN",
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def live_api():
    """Return a connected OpenCTIApiClient for the test session."""
    from pycti import OpenCTIApiClient

    return OpenCTIApiClient(
        url=_OPENCTI_URL,
        token=_OPENCTI_TOKEN,
        ssl_verify=False,
    )


@pytest.fixture(scope="module")
def live_client(live_api):
    """Return an OpenCTIClient (module wrapper) for the test session."""
    import logging
    from iris_opencti_module.opencti_handler.opencti_client import OpenCTIClient

    return OpenCTIClient(
        url=_OPENCTI_URL,
        api_key=_OPENCTI_TOKEN,
        ssl_verify=False,
        logger=logging.getLogger("integration"),
    )


# ── Live connectivity ─────────────────────────────────────────────────────────


@_LIVE_MARK
class TestLiveConnectivity:

    def test_health_check_basic(self, live_api):
        health = live_api.health_check()
        assert health, "health_check() returned falsy"

    def test_health_check_detailed(self, live_client):
        result = live_client.health_check_detailed()
        assert result["ok"] is True, f"Health check failed: {result}"
        assert result["reachable"] is True
        assert result["authenticated"] is True
        assert "version" in result  # may be "unknown" if platform_version not in settings API

    def test_resolve_tlp_amber(self, live_client):
        marking_id = live_client.resolve_tlp("amber")
        assert marking_id is not None, "TLP:AMBER marking not found in OpenCTI"

    def test_resolve_or_create_author(self, live_client):
        org_id = live_client.resolve_or_create_author("iris-opencti-integration-test")
        assert org_id is not None


# ── Live observable CRUD ──────────────────────────────────────────────────────


@_LIVE_MARK
class TestLiveObservable:
    """
    Creates a real observable in OpenCTI, verifies it can be read back
    via get_observable_enrichment, then cleans it up.
    """

    _OBS_DOMAIN = "iris-opencti-integration-test.example.invalid"

    def test_create_domain_observable(self, live_client):
        result = live_client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value=self._OBS_DOMAIN,
            createIndicator=False,
        )
        assert result is not None
        assert result.get("id"), f"No ID in result: {result}"
        # Cleanup
        live_client.delete_observable(result["id"])

    def test_get_observable_enrichment_after_create(self, live_client):
        obs = live_client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value=self._OBS_DOMAIN,
            createIndicator=False,
        )
        assert obs and obs.get("id")

        try:
            enrichment = live_client.get_observable_enrichment(obs["id"])
            assert enrichment is not None
            assert enrichment["entity_type"] == "Domain-Name"
            assert "containers" in enrichment
            assert "threat_context" in enrichment
            assert "sightings" in enrichment
        finally:
            live_client.delete_observable(obs["id"])

    def test_delete_domain_observable(self, live_client):
        obs = live_client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value=self._OBS_DOMAIN,
            createIndicator=False,
        )
        assert obs and obs.get("id")
        ok = live_client.delete_observable(obs["id"])
        assert ok is True


# ── Live file hash observable ─────────────────────────────────────────────────


@_LIVE_MARK
class TestLiveFileHashObservable:

    # Use a test-specific hash unlikely to exist in real threat intel
    _SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def test_create_file_hash_observable(self, live_client):
        result = live_client.create_observable(
            observableData={
                "type": "file",
                "hashes": {"SHA-256": self._SHA256},
            },
            createIndicator=False,
        )
        assert result is not None
        assert result.get("id")
        # Cleanup
        live_client.delete_observable(result["id"])

    def test_delete_file_hash_observable(self, live_client):
        obs = live_client.create_observable(
            observableData={
                "type": "file",
                "hashes": {"SHA-256": self._SHA256},
            },
            createIndicator=False,
        )
        assert obs and obs.get("id")
        ok = live_client.delete_observable(obs["id"])
        assert ok is True


# ── Live Case Incident management ─────────────────────────────────────────────


@_LIVE_MARK
class TestLiveCaseIncident:

    _CASE_NAME = "IRIS-Test-Case-Integration-001"

    def test_find_or_create_case_incident(self, live_client):
        case = live_client.find_or_create_case_incident(
            name=self._CASE_NAME,
            description="Created by iris-opencti-module integration tests",
        )
        assert case is not None
        assert case.get("id")

    def test_find_or_create_is_idempotent(self, live_client):
        """A second client instance must find the same case via the API, not cache."""
        import logging
        from iris_opencti_module.opencti_handler.opencti_client import OpenCTIClient

        client2 = OpenCTIClient(
            url=_OPENCTI_URL,
            api_key=_OPENCTI_TOKEN,
            ssl_verify=False,
            logger=logging.getLogger("integration2"),
        )
        case1 = live_client.find_or_create_case_incident(name=self._CASE_NAME)
        case2 = client2.find_or_create_case_incident(name=self._CASE_NAME)
        assert case1["id"] == case2["id"], "Two client instances produced different cases"

    def test_link_observable_to_case(self, live_client):
        obs = live_client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="link-test.iris-opencti.example.invalid",
            createIndicator=False,
        )
        assert obs and obs.get("id")

        case = live_client.find_or_create_case_incident(name=self._CASE_NAME)
        assert case and case.get("id")

        ok = live_client.link_to_case(case["id"], obs["id"])
        assert ok is True

        # Cleanup observable (case is cleaned up by teardown_class)
        live_client.delete_observable(obs["id"])

    @classmethod
    def teardown_class(cls):
        """Delete the test Case Incident from OpenCTI after all tests in this class."""
        import logging
        from iris_opencti_module.opencti_handler.opencti_client import OpenCTIClient

        if not (_OPENCTI_URL and _OPENCTI_TOKEN):
            return
        try:
            client = OpenCTIClient(
                url=_OPENCTI_URL,
                api_key=_OPENCTI_TOKEN,
                ssl_verify=False,
                logger=logging.getLogger("integration-teardown"),
            )
            case = client.find_or_create_case_incident(name=cls._CASE_NAME)
            if case and case.get("id"):
                client.api.case_incident.delete(id=case["id"])
        except Exception:
            pass  # best effort — don't fail the test run on cleanup errors


# ── Standalone script entry point ─────────────────────────────────────────────

def main():
    """Run a quick manual smoke test. Honours OPENCTI_URL / OPENCTI_TOKEN env vars."""
    from pycti import OpenCTIApiClient

    url = _OPENCTI_URL or "http://localhost:8080"
    token = _OPENCTI_TOKEN
    if not token:
        print("Set OPENCTI_URL and OPENCTI_TOKEN env vars before running.")
        return

    print("=" * 60)
    print("IRIS-OpenCTI Module — Integration Smoke Test")
    print(f"Connecting to: {url}")
    print("=" * 60)

    try:
        client = OpenCTIApiClient(url=url, token=token, ssl_verify=False)
        print("\n[1/4] Connected successfully")
    except Exception as e:
        print(f"\n[1/4] Connection failed: {e}")
        return

    try:
        health = client.health_check()
        print(f"[2/4] Health check: {health}")
    except Exception as e:
        print(f"[2/4] Health check failed: {e}")
        return

    try:
        obs = client.stix_cyber_observable.create(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="iris-smoke-test.example.invalid",
            createIndicator=False,
            update=True,
        )
        print(f"[3/4] Observable: id={obs.get('id') if obs else 'None'}")
    except Exception as e:
        print(f"[3/4] Observable creation failed: {e}")

    try:
        case = client.case_incident.create(
            name="IRIS-Smoke-Test-Case",
            description="Smoke test — safe to delete",
            update=True,
        )
        print(f"[4/4] Case Incident: id={case.get('id') if case else 'None'}")
    except Exception as e:
        print(f"[4/4] Case Incident creation failed: {e}")

    print("\n" + "=" * 60)
    print(f"Done. Check {url}/dashboard/cases/incidents")
    print("=" * 60)


if __name__ == "__main__":
    main()
