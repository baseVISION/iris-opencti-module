"""
Thin wrapper around ``pycti.OpenCTIApiClient``.

Handles connection management, error handling, and caching of
resolved TLP markings and author identities so they are only
looked up once per handler invocation.
"""

from __future__ import annotations

import logging
from typing import Any

from pycti import OpenCTIApiClient
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED

# TLP:AMBER+STRICT is not in the stix2 library; its STIX ID is fixed.
_TLP_AMBER_STRICT_ID = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"

# Map user-friendly names → stix2 constant objects (or raw ID for amber+strict)
_TLP_NAME_MAP: dict[str, str] = {
    "white": TLP_WHITE["id"],
    "clear": TLP_WHITE["id"],  # TLP v2 alias
    "green": TLP_GREEN["id"],
    "amber": TLP_AMBER["id"],
    "amber+strict": _TLP_AMBER_STRICT_ID,
    "red": TLP_RED["id"],
}


class OpenCTIClientError(Exception):
    """Raised when the OpenCTI client encounters an unrecoverable error."""


# ── GraphQL query constants ─────────────────────────────────────

_CONTAINERS_QUERY = """
    query ObservableContainers($id: String!) {
        stixCoreObject(id: $id) {
            containers(first: 50) {
                edges {
                    node {
                        id
                        entity_type
                        ... on Report { name published }
                        ... on CaseIncident { name created }
                        ... on CaseRfi { name created }
                        ... on CaseRft { name created }
                        ... on Grouping { name created }
                        ... on Note { attribute_abstract created }
                        ... on Opinion { opinion created }
                        ... on ObservedData {
                            first_observed last_observed
                        }
                    }
                }
            }
        }
    }
"""

_THREAT_CONTEXT_QUERY = """
    query ThreatContext($id: String!) {
        stixCoreObject(id: $id) {
            stixCoreRelationships(first: 100) {
                edges {
                    node {
                        id
                        relationship_type
                        from {
                            ... on StixDomainObject {
                                id
                                entity_type
                                ... on ThreatActor { name description }
                                ... on IntrusionSet { name description }
                                ... on Malware { name description }
                                ... on Campaign { name description }
                                ... on AttackPattern {
                                    name
                                    description
                                    x_mitre_id
                                }
                            }
                        }
                        to {
                            ... on StixDomainObject {
                                id
                                entity_type
                                ... on ThreatActor { name description }
                                ... on IntrusionSet { name description }
                                ... on Malware { name description }
                                ... on Campaign { name description }
                                ... on AttackPattern {
                                    name
                                    description
                                    x_mitre_id
                                }
                            }
                        }
                    }
                }
            }
        }
    }
"""

_SIGHTINGS_QUERY = """
    query Sightings($id: String!) {
        stixCoreObject(id: $id) {
            stixSightingRelationships(first: 50) {
                edges {
                    node {
                        id
                        first_seen
                        last_seen
                        attribute_count
                        description
                        createdBy {
                            ... on Identity { name }
                        }
                        from {
                            ... on StixDomainObject {
                                id
                                entity_type
                                ... on Identity { name }
                                ... on ThreatActor { name }
                                ... on IntrusionSet { name }
                            }
                        }
                        to {
                            ... on StixDomainObject {
                                id
                                entity_type
                                ... on Identity { name }
                                ... on ThreatActor { name }
                                ... on IntrusionSet { name }
                            }
                        }
                    }
                }
            }
        }
    }
"""

# Maps OpenCTI entity_type → result bucket key for threat context.
_THREAT_TYPE_KEY_MAP = {
    "Threat-Actor-Individual": "threat_actors",
    "Threat-Actor-Group": "threat_actors",
    "Threat-Actor": "threat_actors",
    "Intrusion-Set": "intrusion_sets",
    "Malware": "malware",
    "Campaign": "campaigns",
    "Attack-Pattern": "attack_patterns",
}


class OpenCTIClient:
    """
    Manages a single ``OpenCTIApiClient`` connection and provides
    high-level helpers for creating observables, case incidents,
    and linking objects.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        ssl_verify: bool = True,
        http_proxy: str = "",
        https_proxy: str = "",
        logger: logging.Logger | None = None,
    ) -> None:
        self.log = logger or logging.getLogger(__name__)

        proxies: dict[str, str] = {}
        if http_proxy:
            proxies["http"] = http_proxy
        if https_proxy:
            proxies["https"] = https_proxy

        try:
            self.api = OpenCTIApiClient(
                url=url,
                token=api_key,
                ssl_verify=ssl_verify,
                proxies=proxies if proxies else None,
                log_level="Warning",
            )
        except Exception as exc:
            raise OpenCTIClientError(
                f"Failed to initialise OpenCTI client at {url}: {exc}"
            ) from exc

        # Caches (populated lazily, valid for one handler invocation)
        self._tlp_cache: dict[str, str] = {}
        self._author_id: str | None = None
        self._case_cache: dict[str, dict] = {}

    # ── Health check ────────────────────────────────────────────

    def health_check(self) -> bool:
        """Return True if the OpenCTI instance is reachable."""
        try:
            about = self.api.health_check()
            return bool(about)
        except Exception as exc:
            self.log.error("OpenCTI health check failed: %s", exc)
            return False

    def health_check_detailed(self) -> dict[str, Any]:
        """
        Perform a detailed health check verifying connectivity *and*
        API-key validity.

        Returns a dict with keys:
            - ``ok`` (bool): True if everything passed.
            - ``reachable`` (bool): True if the server responded.
            - ``authenticated`` (bool): True if the API key is valid.
            - ``version`` (str | None): OpenCTI platform version.
            - ``error`` (str | None): Human-readable error message.
        """
        result: dict[str, Any] = {
            "ok": False,
            "reachable": False,
            "authenticated": False,
            "version": None,
            "error": None,
        }

        # Step 1: basic connectivity
        try:
            alive = self.api.health_check()
            if not alive:
                result["error"] = (
                    "OpenCTI server responded but health-check returned falsy"
                )
                return result
            result["reachable"] = True
        except Exception as exc:
            result["error"] = f"Cannot reach OpenCTI server: {exc}"
            return result

        # Step 2: authenticated call – list marking definitions.
        # We deliberately avoid settings.read() because that requires
        # "Access to admin functionalities", which Connector accounts
        # do not have.  Listing marking definitions only needs
        # "Access knowledge" (the base Connector capability).
        try:
            markings = self.api.marking_definition.list(first=1)
            # A valid key returns a list (possibly empty); an invalid key
            # raises an exception with FORBIDDEN_ACCESS.
            result["authenticated"] = True
            # Best-effort version: try settings if we happen to have admin
            # rights, otherwise leave version as None.
            try:
                settings = self.api.settings.read()
                if settings:
                    result["version"] = settings.get(
                        "platform_version", "unknown"
                    )
            except Exception:
                pass
        except Exception as exc:
            result["error"] = f"Authentication failed: {exc}"
            return result

        result["ok"] = True
        return result

    # ── TLP resolution ──────────────────────────────────────────

    def resolve_tlp(self, tlp_name: str) -> str | None:
        """
        Resolve a TLP name (e.g. ``"amber"``) to an OpenCTI marking
        definition internal ID.  Results are cached.
        """
        tlp_name = tlp_name.lower().strip()
        if tlp_name in self._tlp_cache:
            return self._tlp_cache[tlp_name]

        stix_id = _TLP_NAME_MAP.get(tlp_name)
        if stix_id is None:
            self.log.warning("Unknown TLP name '%s', skipping marking", tlp_name)
            return None

        try:
            marking = self.api.marking_definition.read(id=stix_id)
            if marking:
                internal_id = marking["id"]
                self._tlp_cache[tlp_name] = internal_id
                return internal_id
            self.log.warning("TLP marking '%s' not found in OpenCTI", tlp_name)
            return None
        except Exception as exc:
            self.log.warning("Failed to resolve TLP '%s': %s", tlp_name, exc)
            return None

    # ── Author / Identity ──────────────────────────────────────

    def resolve_or_create_author(self, org_name: str) -> str | None:
        """
        Get or create an Organization identity in OpenCTI.  Cached
        after first call.
        """
        if not org_name:
            return None
        if self._author_id is not None:
            return self._author_id

        try:
            identity = self.api.identity.create(
                type="Organization",
                name=org_name,
            )
            if identity:
                self._author_id = identity["id"]
                return self._author_id
        except Exception as exc:
            self.log.warning("Failed to create/resolve author '%s': %s", org_name, exc)
        return None

    # ── Observable reading ────────────────────────────────────

    def get_observable_enrichment(self, observable_id: str) -> dict[str, Any] | None:
        """
        Fetch full observable details from OpenCTI for enrichment.

        Returns a normalised dict with keys::

            value, entity_type, score, description, created_at,
            updated_at, created_by, markings, labels, indicators,
            external_references, containers

        Returns ``None`` on failure.
        """
        try:
            raw = self.api.stix_cyber_observable.read(id=observable_id)
            if not raw:
                return None
        except Exception as exc:
            self.log.warning(
                "Failed to read observable %s for enrichment: %s",
                observable_id, exc,
            )
            return None

        # ── Normalise into a flat dict ──────────────────────────
        result: dict[str, Any] = {
            "id": raw.get("id", observable_id),
            "standard_id": raw.get("standard_id", ""),
            "entity_type": raw.get("entity_type", "unknown"),
            "value": raw.get("observable_value", ""),
            "score": raw.get("x_opencti_score"),
            "description": raw.get("x_opencti_description", ""),
            "created_at": raw.get("created_at", ""),
            "updated_at": raw.get("updated_at", ""),
        }

        # Author
        created_by = raw.get("createdBy")
        if isinstance(created_by, dict):
            result["created_by"] = created_by.get("name", "")
        else:
            result["created_by"] = ""

        # Markings (TLP)
        markings = raw.get("objectMarking") or []
        result["markings"] = [
            m.get("definition", "") for m in markings if isinstance(m, dict)
        ]

        # Labels
        labels = raw.get("objectLabel") or []
        result["labels"] = [
            {"value": lb.get("value", ""), "color": lb.get("color", "#000000")}
            for lb in labels if isinstance(lb, dict)
        ]

        # Indicators (STIX patterns, YARA rules, etc.)
        # pycti 6.x flattens GraphQL edges/node into plain lists of dicts.
        indicators_raw = raw.get("indicators") or []
        result["indicators"] = [
            {
                "id": ind.get("id", ""),
                "pattern": ind.get("pattern", ""),
                "pattern_type": ind.get("pattern_type", ""),
            }
            for ind in indicators_raw
            if isinstance(ind, dict)
        ]

        # External references
        # pycti 6.x flattens GraphQL edges/node into plain lists of dicts.
        refs_raw = raw.get("externalReferences") or []
        result["external_references"] = [
            {
                "source": ref.get("source_name", ""),
                "url": ref.get("url", ""),
                "description": ref.get("description", ""),
                "external_id": ref.get("external_id", ""),
            }
            for ref in refs_raw
            if isinstance(ref, dict)
        ]

        # Containers (reports, cases, groupings, notes, etc.)
        result["containers"] = self._fetch_containers(observable_id)

        # Threat context (threat actors, malware, campaigns, ATT&CK)
        result["threat_context"] = self._fetch_threat_context(observable_id)

        # Sightings
        result["sightings"] = self._fetch_sightings(observable_id)

        return result

    # ── Shared GraphQL helper ──────────────────────────────────

    def _query_edges(
        self,
        query: str,
        entity_id: str,
        relationship_key: str,
        label: str,
    ) -> list[dict]:
        """
        Run a GraphQL query and extract the edges list from
        ``data.stixCoreObject.<relationship_key>.edges``.

        Returns an empty list on failure.
        """
        try:
            data = self.api.query(query, {"id": entity_id})
            return (
                data.get("data", {})
                .get("stixCoreObject", {})
                .get(relationship_key, {})
                .get("edges", [])
            )
        except Exception as exc:
            self.log.warning(
                "Failed to fetch %s for %s: %s", label, entity_id, exc,
            )
            return []

    def _fetch_containers(self, entity_id: str) -> list[dict[str, str]]:
        """
        Fetch all containers (reports, cases, groupings, etc.) that
        reference a given STIX core object.
        """
        edges = self._query_edges(
            _CONTAINERS_QUERY, entity_id, "containers", "containers",
        )

        containers: list[dict[str, str]] = []
        for edge in edges:
            node = edge.get("node", {})
            entity_type = node.get("entity_type", "")
            name = (
                node.get("name")
                or node.get("attribute_abstract")
                or node.get("opinion")
                or ""
            )
            date = (
                node.get("published")
                or node.get("created")
                or node.get("first_observed")
                or ""
            )
            containers.append({
                "id": node.get("id", ""),
                "type": entity_type,
                "name": name,
                "date": date,
            })

        return containers

    def _fetch_threat_context(self, entity_id: str) -> dict[str, list[dict[str, str]]]:
        """
        Fetch threat context linked to an observable: threat actors,
        intrusion sets, malware, campaigns, ATT&CK techniques.
        """
        result: dict[str, list[dict[str, str]]] = {
            "threat_actors": [],
            "intrusion_sets": [],
            "malware": [],
            "campaigns": [],
            "attack_patterns": [],
        }

        edges = self._query_edges(
            _THREAT_CONTEXT_QUERY, entity_id,
            "stixCoreRelationships", "threat context",
        )

        seen_ids: set[str] = set()
        for edge in edges:
            node = edge.get("node", {})
            for side in ("from", "to"):
                obj = node.get(side)
                if not isinstance(obj, dict):
                    continue
                etype = obj.get("entity_type", "")
                key = _THREAT_TYPE_KEY_MAP.get(etype)
                if key is None:
                    continue
                oid = obj.get("id", "")
                if oid in seen_ids or oid == entity_id:
                    continue
                seen_ids.add(oid)
                entry: dict[str, str] = {
                    "id": oid,
                    "name": obj.get("name", ""),
                }
                desc = obj.get("description", "")
                if desc:
                    entry["description"] = desc[:200]
                mitre = obj.get("x_mitre_id", "")
                if mitre:
                    entry["mitre_id"] = mitre
                result[key].append(entry)

        return result

    def _fetch_sightings(self, entity_id: str) -> list[dict[str, str]]:
        """
        Fetch sighting relationships for an observable.
        """
        edges = self._query_edges(
            _SIGHTINGS_QUERY, entity_id,
            "stixSightingRelationships", "sightings",
        )

        sightings: list[dict[str, str]] = []
        for edge in edges:
            node = edge.get("node", {})
            source_name = ""
            created_by = node.get("createdBy")
            if isinstance(created_by, dict):
                source_name = created_by.get("name", "")
            if not source_name:
                for side in ("from", "to"):
                    obj = node.get(side)
                    if isinstance(obj, dict) and obj.get("id") != entity_id:
                        source_name = obj.get("name", "")
                        break

            sightings.append({
                "source": source_name,
                "first_seen": node.get("first_seen", ""),
                "last_seen": node.get("last_seen", ""),
                "count": str(node.get("attribute_count", 1)),
                "description": (node.get("description") or "")[:200],
            })

        return sightings

    # ── Observable creation ────────────────────────────────────

    def create_observable(self, **kwargs: Any) -> dict | None:
        """
        Create or update a STIX Cyber Observable in OpenCTI.

        Accepts the same kwargs as
        ``pycti.StixCyberObservable.create()``.
        Passes ``update=True`` so that re-pushing an IOC with
        changed attributes (description, markings, etc.) updates
        the existing observable rather than creating a duplicate.
        Returns the created/updated object dict or ``None`` on failure.
        """
        try:
            kwargs.setdefault("update", True)
            result = self.api.stix_cyber_observable.create(**kwargs)
            return result
        except Exception as exc:
            value = kwargs.get("simple_observable_value") or str(
                kwargs.get("observableData", {})
            )
            self.log.error("Failed to create observable for '%s': %s", value, exc)
            return None

    def replace_tlp_marking(self, observable_id: str, desired_marking_id: str | None) -> None:
        """
        Ensure the observable carries exactly one TLP marking matching
        *desired_marking_id*.

        OpenCTI's observable upsert (``update=True``) does not replace
        existing marking-definition edges — it only adds new ones.  This
        method reads the current markings, removes any TLP entries that
        differ from the desired one, and adds the desired one if absent.

        Parameters
        ----------
        observable_id:
            Internal OpenCTI ID of the observable.
        desired_marking_id:
            Internal OpenCTI ID of the desired TLP marking definition,
            as returned by :meth:`resolve_tlp`.  Pass ``None`` to only
            remove existing TLP markings without adding a new one.
        """
        try:
            obs = self.api.stix_cyber_observable.read(id=observable_id)
            if not obs:
                return
            current_markings = obs.get("objectMarking") or []

            existing_tlp_ids = [
                m["id"] for m in current_markings
                if isinstance(m, dict) and m.get("definition_type") == "TLP"
            ]

            # Remove stale TLP markings
            for mid in existing_tlp_ids:
                if mid != desired_marking_id:
                    self.api.stix_cyber_observable.remove_marking_definition(
                        id=observable_id, marking_definition_id=mid
                    )
                    self.log.info(
                        "Removed stale TLP marking %s from observable %s",
                        mid, observable_id,
                    )

            # Add the desired marking if not already present
            if desired_marking_id and desired_marking_id not in existing_tlp_ids:
                self.api.stix_cyber_observable.add_marking_definition(
                    id=observable_id, marking_definition_id=desired_marking_id
                )
                self.log.info(
                    "Added TLP marking %s to observable %s",
                    desired_marking_id, observable_id,
                )
        except Exception as exc:
            self.log.warning(
                "Failed to replace TLP marking on observable %s: %s",
                observable_id, exc,
            )

    # ── Case Incident management ───────────────────────────────

    def _search_case_by_name(self, name: str) -> dict | None:
        """
        Search OpenCTI for an existing Case Incident whose name
        matches *exactly*.  Returns the first exact match or None.

        Uses the server-side ``eq`` filter (OpenCTI 6.x+) which is
        reliable and avoids fetching large result sets.
        """
        try:
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "name", "values": [name], "operator": "eq"},
                ],
                "filterGroups": [],
            }
            results = self.api.case_incident.list(
                filters=filters,
                first=10,
                customAttributes="id standard_id entity_type name",
            )
            for case in results or []:
                if case.get("name") == name:
                    self.log.info(
                        "Found existing Case Incident '%s' (id=%s)",
                        name,
                        case.get("id"),
                    )
                    return case
        except Exception as exc:
            self.log.warning(
                "Failed to search for Case Incident '%s': %s", name, exc
            )
        return None

    def find_or_create_case_incident(
        self,
        name: str,
        description: str = "",
        author_id: str | None = None,
        marking_ids: list[str] | None = None,
        confidence: int = 50,
    ) -> dict | None:
        """
        Find an existing Case Incident by name or create a new one.

        First checks the local cache, then queries OpenCTI for an
        existing case with the same name.  Only creates a new case
        if none is found.  Caches results by name.
        """
        if name in self._case_cache:
            return self._case_cache[name]

        # ── Try to find an existing case first ──────────────────
        existing = self._search_case_by_name(name)
        if existing:
            self._case_cache[name] = existing
            return existing

        # ── Create a new case ───────────────────────────────────
        kwargs: dict[str, Any] = {
            "name": name,
            "update": True,
            "confidence": confidence,
        }
        if description:
            kwargs["description"] = description
        if author_id:
            kwargs["createdBy"] = author_id
        if marking_ids:
            kwargs["objectMarking"] = marking_ids

        try:
            case = self.api.case_incident.create(**kwargs)
            if case:
                self._case_cache[name] = case
                self.log.info(
                    "Created new Case Incident '%s' (id=%s)", name, case.get("id")
                )
                return case
            self.log.error("Case Incident creation returned None for '%s'", name)
            return None
        except Exception as exc:
            self.log.error("Failed to create Case Incident '%s': %s", name, exc)
            return None

    def link_to_case(self, case_id: str, object_id: str) -> bool:
        """
        Link an observable (or indicator, or relationship) to a
        Case Incident.
        """
        try:
            result = self.api.case_incident.add_stix_object_or_stix_relationship(
                id=case_id,
                stixObjectOrStixRelationshipId=object_id,
            )
            return bool(result)
        except Exception as exc:
            self.log.warning(
                "Failed to link object %s to case %s: %s", object_id, case_id, exc
            )
            return False

    def add_case_external_reference(
        self,
        case_id: str,
        source_name: str,
        url: str,
        description: str = "",
        external_id: str = "",
    ) -> bool:
        """
        Create an external reference and attach it to a Case Incident.

        Uses ``update=True`` so re-pushing with the same URL upserts
        rather than duplicating.

        Returns True on success, False on failure.
        """
        try:
            ref = self.api.external_reference.create(
                source_name=source_name,
                url=url,
                description=description,
                external_id=external_id,
                update=True,
            )
            if not ref or not ref.get("id"):
                self.log.warning(
                    "External reference creation returned no ID for case %s",
                    case_id,
                )
                return False

            self.api.stix_domain_object.add_external_reference(
                id=case_id,
                external_reference_id=ref["id"],
            )
            self.log.info(
                "Attached external reference '%s' to case %s", url, case_id,
            )
            return True
        except Exception as exc:
            self.log.warning(
                "Failed to add external reference to case %s: %s", case_id, exc,
            )
            return False

    def unlink_from_case(self, case_id: str, object_id: str) -> bool:
        """
        Remove an observable from a Case Incident without deleting it.
        """
        try:
            self.api.case_incident.remove_stix_object_or_stix_relationship(
                id=case_id,
                stixObjectOrStixRelationshipId=object_id,
            )
            self.log.info("Unlinked %s from case %s", object_id, case_id)
            return True
        except Exception as exc:
            self.log.warning(
                "Failed to unlink object %s from case %s: %s", object_id, case_id, exc
            )
            return False

    def get_container_ids(self, observable_id: str) -> list:
        """
        Return the IDs of all containers (cases, reports, groupings, …)
        that reference this observable in OpenCTI.
        Returns an empty list on failure.
        """
        query = """
        query GetContainers($id: String!) {
          stixCoreObject(id: $id) {
            containers(first: 100) {
              edges { node { id } }
            }
          }
        }
        """
        try:
            result = self.api.query(query, {"id": observable_id})
            obj = (result or {}).get("data", {}).get("stixCoreObject") or {}
            edges = obj.get("containers", {}).get("edges", [])
            return [e["node"]["id"] for e in edges if e.get("node", {}).get("id")]
        except Exception as exc:
            self.log.warning(
                "Failed to fetch containers for %s: %s", observable_id, exc
            )
            return []

    # ── Observable deletion ────────────────────────────────────

    def delete_observable(self, observable_id: str) -> bool:
        """
        Delete a STIX Cyber Observable from OpenCTI by its internal ID.

        Returns True on success, False on failure.
        """
        try:
            self.api.stix_cyber_observable.delete(id=observable_id)
            self.log.info("Deleted observable %s from OpenCTI", observable_id)
            return True
        except Exception as exc:
            self.log.warning(
                "Failed to delete observable %s: %s", observable_id, exc
            )
            return False
