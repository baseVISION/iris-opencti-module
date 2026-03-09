"""
Unit tests for OpenCTIClient — the pycti wrapper.

These tests mock ``OpenCTIApiClient`` at the class level so they run
without a live OpenCTI instance.  They cover the response-normalisation
logic, caching behaviour, error handling, and GraphQL edge-parsing
that the handler-level tests skip by mocking OpenCTIClient entirely.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, call, patch

import pytest

# conftest.py has already ensured pycti/stix2 are in sys.modules before
# this file is collected.  Import the module under test after that.
from iris_opencti_module.opencti_handler.opencti_client import (
    OpenCTIClient,
    OpenCTIClientError,
    _TLP_NAME_MAP,
)


# ── Helper: construct a client from a mocked OpenCTIApiClient ────────────────


def _make_client(MockApiClient: MagicMock) -> OpenCTIClient:
    """
    Instantiate OpenCTIClient using the already-patched constructor.
    ``MockApiClient.return_value`` becomes ``client.api``.
    """
    return OpenCTIClient(
        url="https://opencti.test",
        api_key="test-token",
        ssl_verify=False,
        logger=logging.getLogger("test"),
    )


# ── Construction & factory ────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestClientConstruction:

    def test_constructs_successfully(self, MockApi):
        client = _make_client(MockApi)
        assert client.api is MockApi.return_value

    def test_proxies_forwarded(self, MockApi):
        OpenCTIClient(
            url="https://x.test",
            api_key="k",
            ssl_verify=True,
            http_proxy="http://proxy:3128",
            https_proxy="https://proxy:3128",
            logger=logging.getLogger("t"),
        )
        _, kwargs = MockApi.call_args
        assert kwargs["proxies"] == {
            "http": "http://proxy:3128",
            "https": "https://proxy:3128",
        }

    def test_no_proxies_passes_none(self, MockApi):
        OpenCTIClient(url="https://x.test", api_key="k", logger=logging.getLogger("t"))
        _, kwargs = MockApi.call_args
        assert kwargs.get("proxies") is None

    def test_api_init_failure_raises_client_error(self, MockApi):
        MockApi.side_effect = RuntimeError("connection refused")
        with pytest.raises(OpenCTIClientError, match="Failed to initialise"):
            OpenCTIClient(url="https://x.test", api_key="k", logger=logging.getLogger("t"))


# ── health_check_detailed ────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestHealthCheckDetailed:

    def test_all_good(self, MockApi):
        api = MockApi.return_value
        api.health_check.return_value = True
        api.settings.read.return_value = {"platform_version": "6.3.0"}

        client = _make_client(MockApi)
        result = client.health_check_detailed()

        assert result["ok"] is True
        assert result["reachable"] is True
        assert result["authenticated"] is True
        assert result["version"] == "6.3.0"
        assert result["error"] is None

    def test_unreachable(self, MockApi):
        api = MockApi.return_value
        api.health_check.side_effect = ConnectionError("refused")

        client = _make_client(MockApi)
        result = client.health_check_detailed()

        assert result["ok"] is False
        assert result["reachable"] is False
        assert result["authenticated"] is False
        assert "Cannot reach" in result["error"]

    def test_reachable_but_health_check_falsy(self, MockApi):
        api = MockApi.return_value
        api.health_check.return_value = None  # falsy

        client = _make_client(MockApi)
        result = client.health_check_detailed()

        assert result["reachable"] is False  # treated as not reachable
        assert result["ok"] is False

    def test_reachable_but_marking_list_raises_fails_auth(self, MockApi):
        # Auth is now validated by listing marking definitions (connector-level
        # permission only), NOT settings.read() which requires admin rights.
        api = MockApi.return_value
        api.health_check.return_value = True
        api.marking_definition.list.side_effect = Exception("FORBIDDEN_ACCESS")

        client = _make_client(MockApi)
        result = client.health_check_detailed()

        assert result["reachable"] is True
        assert result["authenticated"] is False
        assert result["ok"] is False
        assert "Authentication" in result["error"]

    def test_settings_read_failure_does_not_break_auth(self, MockApi):
        # settings.read() is now best-effort only (admin accounts get the
        # version; connector accounts silently skip it).  A failure here
        # must NOT cause authenticated=False or ok=False.
        api = MockApi.return_value
        api.health_check.return_value = True
        api.settings.read.side_effect = Exception("ACCESS_DENIED")
        # marking_definition.list returns a MagicMock by default (truthy, no raise)

        client = _make_client(MockApi)
        result = client.health_check_detailed()

        assert result["reachable"] is True
        assert result["authenticated"] is True
        assert result["ok"] is True
        assert result["version"] is None  # unavailable but not fatal

    def test_version_missing_in_settings(self, MockApi):
        api = MockApi.return_value
        api.health_check.return_value = True
        # Non-empty dict (truthy) but without platform_version key
        api.settings.read.return_value = {"other_key": "value"}

        client = _make_client(MockApi)
        result = client.health_check_detailed()

        assert result["ok"] is True
        assert result["version"] == "unknown"


# ── resolve_tlp ──────────────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestResolveTlp:

    def test_resolves_amber(self, MockApi):
        api = MockApi.return_value
        api.marking_definition.read.return_value = {"id": "internal-amber-id"}

        client = _make_client(MockApi)
        result = client.resolve_tlp("amber")

        assert result == "internal-amber-id"
        api.marking_definition.read.assert_called_once_with(
            id=_TLP_NAME_MAP["amber"]
        )

    def test_clear_is_alias_for_white(self, MockApi):
        api = MockApi.return_value
        api.marking_definition.read.return_value = {"id": "internal-white-id"}

        client = _make_client(MockApi)
        result = client.resolve_tlp("clear")

        assert result == "internal-white-id"
        # Both "clear" and "white" map to the same STIX ID
        api.marking_definition.read.assert_called_once_with(
            id=_TLP_NAME_MAP["white"]
        )

    def test_unknown_tlp_returns_none(self, MockApi):
        client = _make_client(MockApi)
        result = client.resolve_tlp("ultraviolet")

        assert result is None
        MockApi.return_value.marking_definition.read.assert_not_called()

    def test_pycti_exception_returns_none(self, MockApi):
        api = MockApi.return_value
        api.marking_definition.read.side_effect = Exception("not found")

        client = _make_client(MockApi)
        result = client.resolve_tlp("green")

        assert result is None

    def test_result_cached_second_call_no_api(self, MockApi):
        api = MockApi.return_value
        api.marking_definition.read.return_value = {"id": "cached-id"}

        client = _make_client(MockApi)
        r1 = client.resolve_tlp("red")
        r2 = client.resolve_tlp("red")

        assert r1 == r2 == "cached-id"
        assert api.marking_definition.read.call_count == 1

    def test_marking_read_returns_none_returns_none(self, MockApi):
        api = MockApi.return_value
        api.marking_definition.read.return_value = None

        client = _make_client(MockApi)
        result = client.resolve_tlp("amber")

        assert result is None

    def test_case_insensitive_input(self, MockApi):
        api = MockApi.return_value
        api.marking_definition.read.return_value = {"id": "id-amber"}

        client = _make_client(MockApi)
        result = client.resolve_tlp("AMBER")

        assert result == "id-amber"


# ── resolve_or_create_author ─────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestResolveOrCreateAuthor:

    def test_empty_name_returns_none_without_api_call(self, MockApi):
        client = _make_client(MockApi)
        result = client.resolve_or_create_author("")

        assert result is None
        MockApi.return_value.identity.create.assert_not_called()

    def test_creates_organization(self, MockApi):
        api = MockApi.return_value
        api.identity.create.return_value = {"id": "org-123"}

        client = _make_client(MockApi)
        result = client.resolve_or_create_author("CERT-EU")

        assert result == "org-123"
        api.identity.create.assert_called_once_with(
            type="Organization", name="CERT-EU"
        )

    def test_result_cached_second_call_no_api(self, MockApi):
        api = MockApi.return_value
        api.identity.create.return_value = {"id": "org-cached"}

        client = _make_client(MockApi)
        r1 = client.resolve_or_create_author("MyOrg")
        r2 = client.resolve_or_create_author("MyOrg")

        assert r1 == r2 == "org-cached"
        assert api.identity.create.call_count == 1

    def test_pycti_exception_returns_none(self, MockApi):
        api = MockApi.return_value
        api.identity.create.side_effect = Exception("not authorised")

        client = _make_client(MockApi)
        result = client.resolve_or_create_author("OrgThatFails")

        assert result is None

    def test_pycti_returns_none_returns_none(self, MockApi):
        api = MockApi.return_value
        api.identity.create.return_value = None

        client = _make_client(MockApi)
        result = client.resolve_or_create_author("OrgReturnNone")

        assert result is None


# ── create_observable ────────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestCreateObservable:

    def test_passes_update_true_by_default(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.create.return_value = {"id": "obs-1"}

        client = _make_client(MockApi)
        client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="evil.com",
        )

        _, call_kwargs = api.stix_cyber_observable.create.call_args
        assert call_kwargs.get("update") is True

    def test_caller_can_override_update(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.create.return_value = {"id": "obs-2"}

        client = _make_client(MockApi)
        client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="evil.com",
            update=False,
        )

        _, call_kwargs = api.stix_cyber_observable.create.call_args
        assert call_kwargs.get("update") is False

    def test_returns_result_dict(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.create.return_value = {"id": "obs-3", "entity_type": "Domain-Name"}

        client = _make_client(MockApi)
        result = client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="evil.com",
        )

        assert result == {"id": "obs-3", "entity_type": "Domain-Name"}

    def test_exception_returns_none(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.create.side_effect = Exception("rate limited")

        client = _make_client(MockApi)
        result = client.create_observable(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="evil.com",
        )

        assert result is None


# ── link_to_case ─────────────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestLinkToCase:

    def test_success_returns_true(self, MockApi):
        api = MockApi.return_value
        api.case_incident.add_stix_object_or_stix_relationship.return_value = True

        client = _make_client(MockApi)
        result = client.link_to_case("case-1", "obs-1")

        assert result is True
        api.case_incident.add_stix_object_or_stix_relationship.assert_called_once_with(
            id="case-1",
            stixObjectOrStixRelationshipId="obs-1",
        )

    def test_exception_returns_false(self, MockApi):
        api = MockApi.return_value
        api.case_incident.add_stix_object_or_stix_relationship.side_effect = Exception("permission denied")

        client = _make_client(MockApi)
        result = client.link_to_case("case-1", "obs-1")

        assert result is False

    def test_falsy_result_returns_false(self, MockApi):
        api = MockApi.return_value
        api.case_incident.add_stix_object_or_stix_relationship.return_value = None

        client = _make_client(MockApi)
        result = client.link_to_case("case-1", "obs-1")

        assert result is False


# ── delete_observable ────────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestDeleteObservable:

    def test_success_returns_true(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.delete.return_value = None  # pycti returns None on success

        client = _make_client(MockApi)
        result = client.delete_observable("obs-del-1")

        assert result is True
        api.stix_cyber_observable.delete.assert_called_once_with(id="obs-del-1")

    def test_exception_returns_false(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.delete.side_effect = Exception("not found")

        client = _make_client(MockApi)
        result = client.delete_observable("obs-del-2")

        assert result is False


# ── get_observable_enrichment ────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestGetObservableEnrichment:
    """Tests for the normalisation logic inside get_observable_enrichment."""

    def _raw(self, **overrides) -> dict:
        """A minimal realistic pycti response dict."""
        base = {
            "id": "obs-norm-1",
            "standard_id": "domain-name--abc",
            "entity_type": "Domain-Name",
            "observable_value": "evil.com",
            "x_opencti_score": 80,
            "x_opencti_description": "Known C2",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-06-01T00:00:00Z",
            "createdBy": {"name": "ThreatTeam"},
            "objectMarking": [{"definition": "TLP:AMBER"}],
            "objectLabel": [{"value": "malware", "color": "#f00"}],
            "indicators": [
                {"id": "ind-1", "pattern": "[domain-name:value = 'evil.com']", "pattern_type": "stix"},
            ],
            "externalReferences": [
                {"source_name": "VT", "url": "https://vt.io/evil.com", "external_id": "VT-1234", "description": ""},
            ],
        }
        base.update(overrides)
        return base

    def _prepare_client(self, MockApi, raw, containers=None, threat_ctx=None, sightings=None):
        api = MockApi.return_value
        api.stix_cyber_observable.read.return_value = raw
        # _fetch_containers, _fetch_threat_context, _fetch_sightings all call api.query()
        # We stub them to return empty so get_observable_enrichment can complete.
        # To test those helpers separately we use TestFetchContainers etc.
        api.query.return_value = {
            "data": {
                "stixCoreObject": {
                    "containers": {"edges": []},
                    "stixCoreRelationships": {"edges": []},
                    "stixSightingRelationships": {"edges": []},
                }
            }
        }
        client = _make_client(MockApi)
        return client

    def test_happy_path_normalises_all_fields(self, MockApi):
        raw = self._raw()
        client = self._prepare_client(MockApi, raw)

        result = client.get_observable_enrichment("obs-norm-1")

        assert result is not None
        assert result["id"] == "obs-norm-1"
        assert result["entity_type"] == "Domain-Name"
        assert result["value"] == "evil.com"
        assert result["score"] == 80
        assert result["description"] == "Known C2"
        assert result["created_by"] == "ThreatTeam"
        assert result["markings"] == ["TLP:AMBER"]
        assert result["labels"] == [{"value": "malware", "color": "#f00"}]
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["pattern"] == "[domain-name:value = 'evil.com']"
        assert len(result["external_references"]) == 1
        assert result["external_references"][0]["source"] == "VT"
        assert result["external_references"][0]["url"] == "https://vt.io/evil.com"
        assert result["external_references"][0]["external_id"] == "VT-1234"

    def test_pycti_returns_none_gives_none(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.read.return_value = None

        client = _make_client(MockApi)
        result = client.get_observable_enrichment("obs-missing")

        assert result is None

    def test_pycti_raises_gives_none(self, MockApi):
        api = MockApi.return_value
        api.stix_cyber_observable.read.side_effect = Exception("timeout")

        client = _make_client(MockApi)
        result = client.get_observable_enrichment("obs-exception")

        assert result is None

    def test_missing_created_by_becomes_empty_string(self, MockApi):
        raw = self._raw(createdBy=None)
        client = self._prepare_client(MockApi, raw)
        result = client.get_observable_enrichment("obs-norm-1")

        assert result["created_by"] == ""

    def test_empty_markings_is_empty_list(self, MockApi):
        raw = self._raw(objectMarking=None)
        client = self._prepare_client(MockApi, raw)
        result = client.get_observable_enrichment("obs-norm-1")

        assert result["markings"] == []

    def test_empty_labels_is_empty_list(self, MockApi):
        raw = self._raw(objectLabel=[])
        client = self._prepare_client(MockApi, raw)
        result = client.get_observable_enrichment("obs-norm-1")

        assert result["labels"] == []

    def test_result_includes_containers_and_threat_context_keys(self, MockApi):
        """Verify that containers, threat_context and sightings are always present."""
        raw = self._raw()
        client = self._prepare_client(MockApi, raw)
        result = client.get_observable_enrichment("obs-norm-1")

        assert "containers" in result
        assert "threat_context" in result
        assert "sightings" in result


# ── _fetch_containers ────────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestFetchContainers:

    def _client_with_edges(self, MockApi, edges: list) -> OpenCTIClient:
        api = MockApi.return_value
        api.query.return_value = {
            "data": {
                "stixCoreObject": {
                    "containers": {"edges": edges}
                }
            }
        }
        return _make_client(MockApi)

    def test_report_parsed_correctly(self, MockApi):
        edges = [{
            "node": {
                "id": "rpt-1",
                "entity_type": "Report",
                "name": "Weekly Intel",
                "published": "2025-05-01T00:00:00Z",
            }
        }]
        client = self._client_with_edges(MockApi, edges)
        result = client._fetch_containers("obs-1")

        assert len(result) == 1
        assert result[0] == {
            "id": "rpt-1",
            "type": "Report",
            "name": "Weekly Intel",
            "date": "2025-05-01T00:00:00Z",
        }

    def test_case_incident_parsed_with_created_date(self, MockApi):
        edges = [{
            "node": {
                "id": "case-42",
                "entity_type": "Case-Incident",
                "name": "IR-42 Phishing",
                "created": "2025-03-10T00:00:00Z",
            }
        }]
        client = self._client_with_edges(MockApi, edges)
        result = client._fetch_containers("obs-1")

        assert result[0]["type"] == "Case-Incident"
        assert result[0]["date"] == "2025-03-10T00:00:00Z"

    def test_name_fallback_to_attribute_abstract(self, MockApi):
        edges = [{
            "node": {
                "id": "note-1",
                "entity_type": "Note",
                "attribute_abstract": "Analyst note",
                "created": "2025-01-01T00:00:00Z",
            }
        }]
        client = self._client_with_edges(MockApi, edges)
        result = client._fetch_containers("obs-1")

        assert result[0]["name"] == "Analyst note"

    def test_name_fallback_to_opinion(self, MockApi):
        edges = [{
            "node": {
                "id": "op-1",
                "entity_type": "Opinion",
                "opinion": "strongly-disagree",
                "created": "2025-01-01T00:00:00Z",
            }
        }]
        client = self._client_with_edges(MockApi, edges)
        result = client._fetch_containers("obs-1")

        assert result[0]["name"] == "strongly-disagree"

    def test_date_fallback_to_first_observed(self, MockApi):
        edges = [{
            "node": {
                "id": "od-1",
                "entity_type": "Observed-Data",
                "first_observed": "2025-02-10T00:00:00Z",
            }
        }]
        client = self._client_with_edges(MockApi, edges)
        result = client._fetch_containers("obs-1")

        assert result[0]["date"] == "2025-02-10T00:00:00Z"

    def test_empty_edges_returns_empty_list(self, MockApi):
        client = self._client_with_edges(MockApi, [])
        result = client._fetch_containers("obs-1")

        assert result == []

    def test_query_exception_returns_empty_list(self, MockApi):
        MockApi.return_value.query.side_effect = Exception("GraphQL error")
        client = _make_client(MockApi)
        result = client._fetch_containers("obs-1")

        assert result == []


# ── _fetch_threat_context ────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestFetchThreatContext:

    def _client_with_edges(self, MockApi, edges: list) -> OpenCTIClient:
        api = MockApi.return_value
        api.query.return_value = {
            "data": {
                "stixCoreObject": {
                    "stixCoreRelationships": {"edges": edges}
                }
            }
        }
        return _make_client(MockApi)

    def _edge(self, from_obj=None, to_obj=None) -> dict:
        return {"node": {"id": f"rel-{id(from_obj)}", "from": from_obj, "to": to_obj}}

    def test_threat_actor_on_from_side(self, MockApi):
        from_obj = {"id": "ta-001", "entity_type": "Threat-Actor", "name": "APT28"}
        client = self._client_with_edges(MockApi, [self._edge(from_obj=from_obj)])
        result = client._fetch_threat_context("obs-x")

        assert len(result["threat_actors"]) == 1
        assert result["threat_actors"][0]["name"] == "APT28"

    def test_threat_actor_on_to_side(self, MockApi):
        to_obj = {"id": "ta-002", "entity_type": "Threat-Actor-Group", "name": "Lazarus"}
        client = self._client_with_edges(MockApi, [self._edge(to_obj=to_obj)])
        result = client._fetch_threat_context("obs-x")

        assert len(result["threat_actors"]) == 1
        assert result["threat_actors"][0]["name"] == "Lazarus"

    def test_deduplication(self, MockApi):
        """Same entity appearing in two relationships should be counted once."""
        ta = {"id": "ta-001", "entity_type": "Threat-Actor", "name": "APT28"}
        client = self._client_with_edges(MockApi, [
            self._edge(from_obj=ta),
            self._edge(from_obj=ta),  # duplicate
        ])
        result = client._fetch_threat_context("obs-x")

        assert len(result["threat_actors"]) == 1

    def test_self_entity_skipped(self, MockApi):
        """An entity with id == the observable id should be skipped."""
        self_ref = {"id": "obs-x", "entity_type": "Threat-Actor", "name": "Self"}
        client = self._client_with_edges(MockApi, [self._edge(from_obj=self_ref)])
        result = client._fetch_threat_context("obs-x")

        assert result["threat_actors"] == []

    def test_unknown_entity_type_skipped(self, MockApi):
        unknown = {"id": "unk-1", "entity_type": "Tool", "name": "Cobalt Strike"}
        client = self._client_with_edges(MockApi, [self._edge(from_obj=unknown)])
        result = client._fetch_threat_context("obs-x")

        # "Tool" is not in _THREAT_TYPE_KEY_MAP — should not appear in any bucket
        for bucket in result.values():
            assert bucket == []

    def test_malware_bucket(self, MockApi):
        malware = {"id": "mal-1", "entity_type": "Malware", "name": "Emotet"}
        client = self._client_with_edges(MockApi, [self._edge(from_obj=malware)])
        result = client._fetch_threat_context("obs-x")

        assert result["malware"][0]["name"] == "Emotet"

    def test_attack_pattern_with_mitre_id(self, MockApi):
        ap = {
            "id": "ap-1",
            "entity_type": "Attack-Pattern",
            "name": "Spearphishing",
            "x_mitre_id": "T1566.001",
        }
        client = self._client_with_edges(MockApi, [self._edge(from_obj=ap)])
        result = client._fetch_threat_context("obs-x")

        entry = result["attack_patterns"][0]
        assert entry["mitre_id"] == "T1566.001"
        assert entry["name"] == "Spearphishing"

    def test_empty_result_structure(self, MockApi):
        client = self._client_with_edges(MockApi, [])
        result = client._fetch_threat_context("obs-x")

        for key in ("threat_actors", "intrusion_sets", "malware", "campaigns", "attack_patterns"):
            assert result[key] == []

    def test_query_exception_returns_empty_buckets(self, MockApi):
        MockApi.return_value.query.side_effect = Exception("whoops")
        client = _make_client(MockApi)
        result = client._fetch_threat_context("obs-x")

        for bucket in result.values():
            assert bucket == []

    def test_intrusion_set_bucket(self, MockApi):
        iset = {"id": "is-1", "entity_type": "Intrusion-Set", "name": "Fancy Bear"}
        client = self._client_with_edges(MockApi, [self._edge(from_obj=iset)])
        result = client._fetch_threat_context("obs-x")

        assert result["intrusion_sets"][0]["name"] == "Fancy Bear"

    def test_campaign_bucket(self, MockApi):
        camp = {"id": "c-1", "entity_type": "Campaign", "name": "Operation Aurora"}
        client = self._client_with_edges(MockApi, [self._edge(from_obj=camp)])
        result = client._fetch_threat_context("obs-x")

        assert result["campaigns"][0]["name"] == "Operation Aurora"

    def test_description_truncated_at_200_chars(self, MockApi):
        long_desc = "A" * 300
        ta = {
            "id": "ta-1",
            "entity_type": "Threat-Actor",
            "name": "APT-long",
            "description": long_desc,
        }
        client = self._client_with_edges(MockApi, [self._edge(from_obj=ta)])
        result = client._fetch_threat_context("obs-x")

        assert len(result["threat_actors"][0]["description"]) == 200


# ── _fetch_sightings ─────────────────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestFetchSightings:

    def _client_with_edges(self, MockApi, edges: list) -> OpenCTIClient:
        api = MockApi.return_value
        api.query.return_value = {
            "data": {
                "stixCoreObject": {
                    "stixSightingRelationships": {"edges": edges}
                }
            }
        }
        return _make_client(MockApi)

    def test_source_from_created_by(self, MockApi):
        edge = {"node": {
            "id": "s-1",
            "first_seen": "2025-01-01T00:00:00Z",
            "last_seen": "2025-06-01T00:00:00Z",
            "attribute_count": 5,
            "description": "",
            "createdBy": {"name": "CERT-EU"},
            "from": None,
            "to": None,
        }}
        client = self._client_with_edges(MockApi, [edge])
        result = client._fetch_sightings("obs-1")

        assert len(result) == 1
        assert result[0]["source"] == "CERT-EU"
        assert result[0]["count"] == "5"
        assert result[0]["first_seen"] == "2025-01-01T00:00:00Z"

    def test_source_fallback_to_from_identity(self, MockApi):
        edge = {"node": {
            "id": "s-2",
            "first_seen": "2025-03-01T00:00:00Z",
            "last_seen": "",
            "attribute_count": 1,
            "description": "",
            "createdBy": None,
            "from": {"id": "ident-1", "entity_type": "Identity", "name": "SOC Team"},
            "to": {"id": "obs-1", "entity_type": "Domain-Name"},
        }}
        client = self._client_with_edges(MockApi, [edge])
        result = client._fetch_sightings("obs-1")

        assert result[0]["source"] == "SOC Team"

    def test_source_fallback_to_to_identity_when_from_is_self(self, MockApi):
        """When 'from' is the observable itself, use 'to' for source name."""
        edge = {"node": {
            "id": "s-3",
            "first_seen": "",
            "last_seen": "",
            "attribute_count": 1,
            "description": "",
            "createdBy": None,
            "from": {"id": "obs-1", "entity_type": "Domain-Name"},
            "to": {"id": "ident-2", "entity_type": "Identity", "name": "Partner Feed"},
        }}
        client = self._client_with_edges(MockApi, [edge])
        result = client._fetch_sightings("obs-1")

        assert result[0]["source"] == "Partner Feed"

    def test_empty_edges_returns_empty_list(self, MockApi):
        client = self._client_with_edges(MockApi, [])
        assert client._fetch_sightings("obs-1") == []

    def test_query_exception_returns_empty_list(self, MockApi):
        MockApi.return_value.query.side_effect = Exception("error")
        client = _make_client(MockApi)
        assert client._fetch_sightings("obs-1") == []

    def test_description_included_and_truncated(self, MockApi):
        edge = {"node": {
            "id": "s-4",
            "first_seen": "",
            "last_seen": "",
            "attribute_count": 1,
            "description": "B" * 300,
            "createdBy": {"name": "ISAC"},
            "from": None, "to": None,
        }}
        client = self._client_with_edges(MockApi, [edge])
        result = client._fetch_sightings("obs-1")

        assert len(result[0]["description"]) == 200


# ── find_or_create_case_incident ─────────────────────────────────────────────


@patch("iris_opencti_module.opencti_handler.opencti_client.OpenCTIApiClient")
class TestFindOrCreateCaseIncident:

    def test_cache_hit_skips_api(self, MockApi):
        api = MockApi.return_value
        existing = {"id": "c-cached"}

        client = _make_client(MockApi)
        client._case_cache["IR-99"] = existing

        result = client.find_or_create_case_incident("IR-99")

        assert result == existing
        api.case_incident.list.assert_not_called()
        api.case_incident.create.assert_not_called()

    def test_finds_existing_case_without_creating(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.return_value = [{"id": "c-existing", "name": "IR-42"}]

        client = _make_client(MockApi)
        result = client.find_or_create_case_incident("IR-42")

        assert result == {"id": "c-existing", "name": "IR-42"}
        api.case_incident.create.assert_not_called()

    def test_creates_new_case_when_not_found(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.return_value = []  # filter returns nothing
        # second call (text search) also returns nothing
        api.case_incident.list.side_effect = [[], []]
        api.case_incident.create.return_value = {"id": "c-new", "name": "IR-new"}

        client = _make_client(MockApi)
        result = client.find_or_create_case_incident("IR-new")

        assert result == {"id": "c-new", "name": "IR-new"}
        api.case_incident.create.assert_called_once()

    def test_creates_with_description_and_markings(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.side_effect = [[], []]
        api.case_incident.create.return_value = {"id": "c-desc", "name": "IR-desc"}

        client = _make_client(MockApi)
        client.find_or_create_case_incident(
            name="IR-desc",
            description="Very important case",
            author_id="org-1",
            marking_ids=["tlp-amber"],
            confidence=90,
        )

        _, kwargs = api.case_incident.create.call_args
        assert kwargs["description"] == "Very important case"
        assert kwargs["createdBy"] == "org-1"
        assert kwargs["objectMarking"] == ["tlp-amber"]
        assert kwargs["confidence"] == 90

    def test_create_returns_none_logs_error_returns_none(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.side_effect = [[], []]
        api.case_incident.create.return_value = None

        client = _make_client(MockApi)
        result = client.find_or_create_case_incident("IR-none")

        assert result is None

    def test_create_raises_returns_none(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.side_effect = [[], []]
        api.case_incident.create.side_effect = Exception("quota exceeded")

        client = _make_client(MockApi)
        result = client.find_or_create_case_incident("IR-exc")

        assert result is None

    def test_result_cached_after_successful_create(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.side_effect = [[], []]
        api.case_incident.create.return_value = {"id": "c-cache-me", "name": "IR-cache"}

        client = _make_client(MockApi)
        r1 = client.find_or_create_case_incident("IR-cache")
        r2 = client.find_or_create_case_incident("IR-cache")  # should hit cache

        assert r1 is r2
        assert api.case_incident.create.call_count == 1

    def test_empty_description_not_included_in_create(self, MockApi):
        api = MockApi.return_value
        api.case_incident.list.side_effect = [[], []]
        api.case_incident.create.return_value = {"id": "c-no-desc"}

        client = _make_client(MockApi)
        client.find_or_create_case_incident("IR-no-desc", description="")

        _, kwargs = api.case_incident.create.call_args
        assert "description" not in kwargs
