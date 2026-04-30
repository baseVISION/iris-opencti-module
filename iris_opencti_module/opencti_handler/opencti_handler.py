"""
Business logic for pushing IRIS IOCs to OpenCTI.

Instantiated per hook invocation.  Orchestrates observable creation,
Case Incident management and IOC tagging.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any

from iris_opencti_module.opencti_handler.opencti_client import (
    OpenCTIClient,
    OpenCTIClientError,
)
from iris_opencti_module.opencti_handler.ioc_type_mapping import (
    build_observable_params,
    resolve_ioc_type,
)
from iris_opencti_module.opencti_handler.enrichment_renderer import (
    render_enrichment_html,
)

# Late-import helper: only available inside the IRIS worker context.
# A no-op stub is used during unit tests or standalone execution.
try:
    from app.datamgmt.manage.manage_attribute_db import (
        add_tab_attribute_field,
    )
except ImportError:
    add_tab_attribute_field = None  # type: ignore[assignment]


# Regex to extract TLP level from IOC tag strings like "tlp:amber,other:tag"
_TLP_TAG_RE = re.compile(r"\btlp:(clear|white|green|amber\+strict|amber|red)\b", re.IGNORECASE)

_PUSHED_TAG = "opencti:pushed"
_FAILED_TAG = "opencti:failed"


class OpenCTIHandler:
    """
    High-level handler that translates IRIS IOC objects into OpenCTI
    observables linked to a Case Incident.
    """

    def __init__(self, mod_config: dict[str, Any], logger: logging.Logger) -> None:
        self.config = mod_config
        self.log = logger
        self.message_queue: list[str] = []

        url = self.config.get("opencti_url", "").strip()
        api_key = self.config.get("opencti_api_key", "").strip()
        ssl_verify = self.config.get("opencti_ssl_verify", True)
        http_proxy = self.config.get("opencti_http_proxy", "") or ""
        https_proxy = self.config.get("opencti_https_proxy", "") or ""

        if not url or not api_key:
            raise OpenCTIClientError(
                "OpenCTI URL and API key must be configured. "
                "Go to Manage → Modules → IrisOpenCTI to set them."
            )

        self.client = OpenCTIClient(
            url=url,
            api_key=api_key,
            ssl_verify=ssl_verify,
            http_proxy=http_proxy,
            https_proxy=https_proxy,
            logger=self.log,
        )

        # Pre-resolve shared attributes once
        self._author_id = self.client.resolve_or_create_author(
            self.config.get("opencti_author_name", "")
        )
        self._parse_config(mod_config)
        self._is_manual = False  # set to True for manual triggers

    def _parse_config(self, config: dict[str, Any]) -> None:
        """Extract and validate module configuration parameters."""
        self._default_tlp = config.get("opencti_default_tlp", "amber")
        try:
            self._confidence = max(0, min(100, int(config.get("opencti_confidence", 50))))
        except (ValueError, TypeError):
            self.log.warning("Invalid confidence value in config, defaulting to 50")
            self._confidence = 50
        self._create_indicator = bool(config.get("opencti_create_indicator", True))
        self._create_case = bool(config.get("opencti_create_case_incident", True))
        self._case_naming_mode = config.get("opencti_case_naming_mode", "case_name")
        self._case_name_prefix = config.get("opencti_case_name_prefix", "IRIS-Case")
        self._case_custom_attr = config.get("opencti_case_custom_attribute", "").strip().strip("'\"")
        self._iris_url = (config.get("opencti_iris_url", "") or "").strip().rstrip("/")

    # ── Public entry point ──────────────────────────────────────

    def handle_ioc(self, ioc: Any, cases_info: list | None = None) -> bool:
        """
        Process a single IRIS IOC object:
        1. Map the IOC type to OpenCTI observable parameters.
        2. Create the observable(s) in OpenCTI.
        3. Optionally create / link to Case Incident(s).
        4. Tag the IRIS IOC with ``opencti:pushed``.

        Parameters
        ----------
        ioc
            An IRIS IOC SQLAlchemy object (has ``.ioc_value``,
            ``.ioc_type.type_name``, ``.ioc_tags``, etc.).
        cases_info
            List of IRIS case objects for Case Incident creation.
            May be empty or None.

        Returns ``True`` if at least one observable was created
        successfully.
        """
        if cases_info is None:
            cases_info = []

        ioc_value = ioc.ioc_value
        type_name = ioc.ioc_type.type_name if ioc.ioc_type else "unknown"

        self.log.info("Processing IOC '%s' (type=%s)", ioc_value, type_name)

        # ── Ensure editable custom fields exist on the IOC ──────
        # Done unconditionally so the OpenCTI tab is visible to analysts
        # even before the first successful push.
        OpenCTIHandler.ensure_ioc_custom_fields(ioc, self._confidence)

        # ── Check for new case associations ─────────────────────
        current_case_ids = set()
        for c in cases_info:
            cid = getattr(c, "case_id", None) or getattr(c, "id", None)
            if cid is not None:
                current_case_ids.add(str(cid))
        synced_case_ids = set(self._get_synced_case_ids(ioc))
        new_case_ids = current_case_ids - synced_case_ids

        # ── Guard: skip if nothing meaningful changed ───────────
        current_tags = getattr(ioc, "ioc_tags", "") or ""
        current_hash = self._compute_ioc_hash(ioc)
        stored_hash = self._get_push_hash(ioc)

        if _PUSHED_TAG in current_tags and not self._is_manual:
            if stored_hash and stored_hash == current_hash and not new_case_ids:
                self.log.info(
                    "IOC '%s' unchanged (hash match, no new cases) — skipping",
                    ioc_value,
                )
                return True
            elif new_case_ids:
                self.log.info(
                    "IOC '%s' has %d new case association(s) — syncing",
                    ioc_value, len(new_case_ids),
                )
            elif stored_hash:
                self.log.info(
                    "IOC '%s' changed since last push — re-syncing to OpenCTI",
                    ioc_value,
                )
            # else: first push with hash tracking — proceed

        # ── Step 1: resolve IOC type mapping ────────────────────
        mapping = resolve_ioc_type(type_name)
        if mapping is None:
            msg = f"Unsupported IOC type '{type_name}' for value '{ioc_value}' — skipped"
            self.log.warning(msg)
            self.message_queue.append(msg)
            self._add_tag(ioc, _FAILED_TAG)
            return False

        # ── Step 2: resolve TLP marking ─────────────────────────
        tlp_name = self._resolve_tlp_name(ioc)
        marking_ids = []
        tlp_id = self.client.resolve_tlp(tlp_name)
        if tlp_id:
            marking_ids.append(tlp_id)

        # ── Step 3: build observable parameters ─────────────────
        # Use the analyst-provided OpenCTI Description custom field rather than
        # the internal ioc_description, which may contain sensitive details.
        opencti_description = self._extract_ioc_custom_attribute(
            ioc, "OpenCTI", "OpenCTI Description"
        ) or None

        # Allow per-IOC confidence override via custom field.
        confidence = self._confidence
        confidence_override_str = self._extract_ioc_custom_attribute(
            ioc, "OpenCTI", "OpenCTI Confidence Score"
        )
        if confidence_override_str is not None:
            try:
                confidence = max(0, min(100, int(confidence_override_str)))
            except (ValueError, TypeError):
                self.log.warning(
                    "Invalid OpenCTI Confidence Score '%s' for IOC '%s' "
                    "— using module default %d",
                    confidence_override_str, ioc_value, self._confidence,
                )

        obs_param_list = build_observable_params(
            mapping=mapping,
            ioc_value=ioc_value,
            create_indicator=self._create_indicator,
            marking_ids=marking_ids,
            author_id=self._author_id,
            confidence=confidence,
            description=opencti_description,
        )

        # ── Step 4: create observables in OpenCTI ───────────────
        desired_tlp_id = marking_ids[0] if marking_ids else None
        stored_tlp = self._get_push_tlp(ioc)
        tlp_changed = tlp_name != stored_tlp
        created_ids = self._create_observables(obs_param_list, desired_tlp_id, tlp_changed)

        if not created_ids:
            msg = f"Failed to create any observable for IOC '{ioc_value}'"
            self.log.error(msg)
            self.message_queue.append(msg)
            self._add_tag(ioc, _FAILED_TAG)
            return False

        # ── Step 5: link to Case Incident(s) ─────────────────────
        linked_case_names, successfully_synced_case_ids = self._link_cases_to_observables(
            ioc, created_ids, cases_info, marking_ids
        )

        # ── Step 6: tag the IOC and store push metadata ─────────
        self._add_tag(ioc, _PUSHED_TAG)
        self._remove_tag(ioc, _FAILED_TAG)
        self._store_push_hash(ioc, current_hash)
        self._store_push_tlp(ioc, tlp_name)
        self._store_opencti_ids(ioc, created_ids)
        self._store_synced_case_ids(ioc, successfully_synced_case_ids)

        # ── Step 7: update enrichment tab in IRIS UI ────────────
        self._update_enrichment_tab(
            ioc,
            observable_ids=created_ids,
            case_names=linked_case_names,
            tlp_name=tlp_name,
        )

        return True

    # ── Internal helpers ────────────────────────────────────────

    def _create_observables(
        self,
        obs_param_list: list[dict[str, Any]],
        desired_tlp_id: str | None,
        tlp_changed: bool,
    ) -> list[str]:
        """Create observables in OpenCTI and return a list of created IDs."""
        created_ids: list[str] = []
        for obs_kwargs in obs_param_list:
            result = self.client.create_observable(**obs_kwargs)
            if result and result.get("id"):
                obs_id = result["id"]
                created_ids.append(obs_id)
                obs_value = obs_kwargs.get("simple_observable_value", str(obs_kwargs.get("observableData", "")))
                msg = f"Created observable in OpenCTI: {obs_value} (id={obs_id})"
                self.log.info(msg)
                self.message_queue.append(msg)
                if tlp_changed:
                    self.client.replace_tlp_marking(obs_id, desired_tlp_id)
        return created_ids

    def _link_cases_to_observables(
        self,
        ioc: Any,
        created_ids: list[str],
        cases_info: list[Any],
        marking_ids: list[str],
    ) -> tuple[list[str], set[str]]:
        """
        Create / find Case Incidents and link observables to them.

        Returns a tuple of (linked_case_names, successfully_synced_iris_case_ids).
        """
        linked_case_names: list[str] = []
        successfully_synced_case_ids: set[str] = set()
        if not self._create_case or not cases_info:
            return linked_case_names, successfully_synced_case_ids

        for case_obj in cases_info:
            case_name = self._resolve_case_name(case_obj)
            case_desc = getattr(case_obj, "description", "") or ""

            case = self.client.find_or_create_case_incident(
                name=case_name,
                description=case_desc,
                author_id=self._author_id,
                marking_ids=marking_ids,
                confidence=self._confidence,
            )
            if case and case.get("id"):
                case_id = case["id"]
                for obj_id in created_ids:
                    self.client.link_to_case(case_id, obj_id)
                msg = f"Linked {len(created_ids)} observable(s) to Case Incident '{case_name}'"
                self.log.info(msg)
                self.message_queue.append(msg)
                linked_case_names.append(case_name)
                iris_cid = getattr(case_obj, "case_id", None) or getattr(case_obj, "id", None)
                if iris_cid is not None:
                    successfully_synced_case_ids.add(str(iris_cid))
                self._store_synced_case_opencti_id(ioc, case_id)
                if self._iris_url and iris_cid is not None:
                    self.client.add_case_external_reference(
                        case_id=case_id,
                        source_name="IRIS DFIR",
                        url=f"{self._iris_url}/case/ioc?cid={iris_cid}",
                        description=case_name,
                        external_id=str(iris_cid),
                    )
        return linked_case_names, successfully_synced_case_ids

    def _resolve_tlp_name(self, ioc: Any) -> str:
        """
        Determine the TLP level for an IOC using this priority:
        1. The IOC's dedicated ``tlp`` relationship (ioc.tlp.tlp_name)
        2. A ``tlp:<level>`` tag in the IOC tags string
        3. The module's configured default TLP
        """
        # Priority 1: IRIS TLP field
        tlp_obj = getattr(ioc, "tlp", None)
        if tlp_obj is not None:
            tlp_name = getattr(tlp_obj, "tlp_name", None)
            if tlp_name:
                # IRIS stores e.g. "TLP:AMBER" or "TLP:RED"
                cleaned = tlp_name.lower().replace("tlp:", "").strip()
                if cleaned:
                    self.log.info("TLP from IOC field: %s", cleaned)
                    return cleaned

        # Priority 2: tag-based
        tags = getattr(ioc, "ioc_tags", None)
        if tags:
            match = _TLP_TAG_RE.search(tags)
            if match:
                return match.group(1).lower()
            # Warn if there is a tlp: tag that didn't match accepted values
            # (e.g. a typo like tlp:ambr) so analysts aren't silently surprised.
            if re.search(r"\btlp:", tags, re.IGNORECASE):
                self.log.warning(
                    "IOC '%s' has a tlp: tag that does not match a known TLP "
                    "level — falling back to default TLP '%s'. "
                    "Check the tag value in IRIS.",
                    getattr(ioc, "ioc_value", "unknown"),
                    self._default_tlp,
                )

        # Priority 3: config default
        return self._default_tlp

    def _resolve_case_name(self, case_info: Any) -> str:
        """
        Build the OpenCTI Case Incident name based on the configured
        naming mode.
        """
        mode = self._case_naming_mode
        case_id = getattr(case_info, "case_id", None) or getattr(case_info, "id", "0")

        if mode == "case_id":
            return f"IRIS-Case-{case_id}"
        elif mode == "custom_prefix_id":
            prefix = self._case_name_prefix or "IRIS-Case"
            return f"{prefix}-{case_id}"
        elif mode == "custom_attribute":
            value = self._extract_custom_attribute(case_info, self._case_custom_attr)
            if value:
                return value
            self.log.warning(
                "Custom attribute '%s' is empty for case %s — falling back to IRIS-Case-%s",
                self._case_custom_attr, case_id, case_id,
            )
            return f"IRIS-Case-{case_id}"
        else:
            # Default: "case_name"
            return getattr(case_info, "name", None) or f"IRIS-Case-{case_id}"

    @staticmethod
    def _extract_custom_attribute(case_info: Any, attr_name: str) -> str | None:
        """
        Extract a custom attribute value from case.custom_attributes.

        IRIS stores custom attributes as::

            {"Section": {"Attr Name": {"type": ..., "value": ...}, ...}}

        This searches all sections for the given attribute name.
        Returns the value string if found and non-empty, else None.
        """
        if not attr_name:
            return None

        custom_attrs = getattr(case_info, "custom_attributes", None)
        if not custom_attrs or not isinstance(custom_attrs, dict):
            return None

        for section_data in custom_attrs.values():
            if not isinstance(section_data, dict):
                continue
            attr = section_data.get(attr_name)
            if isinstance(attr, dict):
                val = attr.get("value", "")
                if isinstance(val, str) and val.strip():
                    return val.strip()

        return None

    # ── Enrichment tab (IRIS UI) ────────────────────────────────

    def _update_enrichment_tab(
        self,
        ioc: Any,
        observable_ids: list[str],
        case_names: list[str] | None = None,
        tlp_name: str = "",
    ) -> None:
        """
        Write an *OpenCTI* enrichment tab to the IOC's
        ``custom_attributes`` so analysts see sync status directly
        in the IRIS web UI.

        Fetches full observable details from OpenCTI (score, labels,
        indicators, external references) and renders a rich HTML
        report.  Falls back to a basic summary when the details
        API call fails.

        Uses ``add_tab_attribute_field`` from the IRIS helper library
        (same approach as the IrisVT module).
        """
        if add_tab_attribute_field is None:
            self.log.debug(
                "add_tab_attribute_field not available — skipping enrichment tab"
            )
            return

        opencti_url = self.config.get("opencti_url", "").rstrip("/")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # ── Fetch enrichment details from OpenCTI ───────────────
        enrichments: list[dict] = []
        for oid in observable_ids:
            detail = self.client.get_observable_enrichment(oid)
            if detail:
                enrichments.append(detail)
            else:
                enrichments.append({"id": oid})

        html_report = self._render_enrichment_html(
            enrichments=enrichments,
            opencti_url=opencti_url,
            case_names=case_names or [],
            tlp_name=tlp_name,
            synced_at=now,
        )

        # Cache the value before the commit so the except handler never
        # needs to touch the (possibly broken) SQLAlchemy session.
        ioc_val_str = getattr(ioc, "ioc_value", "?") or "?"

        try:
            add_tab_attribute_field(
                ioc,
                tab_name="OpenCTI",
                field_name="Sync Report",
                field_type="html",
                field_value=html_report,
            )
        except Exception as exc:
            # Non-critical: don't fail the push because of a UI update
            self.log.warning(
                "Failed to update enrichment tab for IOC '%s': %s",
                ioc_val_str,
                exc,
            )

    @staticmethod
    def ensure_ioc_custom_fields(ioc: Any, confidence: int = 50) -> None:
        """
        Add editable custom fields to the IOC if they are not already present.

        This is a ``@staticmethod`` so it can be called from the IRIS interface
        layer (e.g. on IOC create) without needing a full handler instance or
        an active OpenCTI connection.

        Fields added:

        **OpenCTI tab**
        - ``OpenCTI Description`` — public-facing description pushed to
          OpenCTI instead of the internal ``ioc_description``.
        - ``OpenCTI Confidence Score`` — pre-filled with the module default;
          analyst can override per-IOC.

        ``add_tab_attribute_field`` always overwrites, so existence is
        checked first to preserve any analyst-entered content.
        """
        if add_tab_attribute_field is None:
            return

        custom_attrs = getattr(ioc, "custom_attributes", None) or {}
        opencti_section = custom_attrs.get("OpenCTI", {})
        ioc_val_str = getattr(ioc, "ioc_value", "?") or "?"

        if "OpenCTI Description" not in opencti_section:
            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="OpenCTI",
                    field_name="OpenCTI Description",
                    field_type="input_textfield",
                    field_value="",
                )
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "Failed to add OpenCTI Description field for IOC '%s': %s",
                    ioc_val_str, exc,
                )

        if "OpenCTI Confidence Score" not in opencti_section:
            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="OpenCTI",
                    field_name="OpenCTI Confidence Score",
                    field_type="input_string",
                    field_value=str(confidence),
                )
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "Failed to add OpenCTI Confidence Score field for IOC '%s': %s",
                    ioc_val_str, exc,
                )

    @staticmethod
    def _render_enrichment_html(
        enrichments: list[dict],
        opencti_url: str,
        case_names: list[str],
        tlp_name: str,
        synced_at: str,
    ) -> str:
        """
        Build the HTML report for the enrichment tab.

        Delegates to the extracted ``enrichment_renderer`` module.
        """
        return render_enrichment_html(
            enrichments=enrichments,
            opencti_url=opencti_url,
            case_names=case_names,
            tlp_name=tlp_name,
            synced_at=synced_at,
        )

    @staticmethod
    def _extract_ioc_custom_attribute(ioc: Any, tab_name: str, field_name: str) -> str | None:
        """
        Read a custom attribute value from ``ioc.custom_attributes``.

        IRIS stores custom attributes as::

            {"Tab Name": {"Field Name": {"type": ..., "value": ...}, ...}}

        Returns the stripped string value if found and non-empty, else ``None``.
        """
        custom_attrs = getattr(ioc, "custom_attributes", None)
        if not custom_attrs or not isinstance(custom_attrs, dict):
            return None
        section = custom_attrs.get(tab_name, {})
        if not isinstance(section, dict):
            return None
        attr = section.get(field_name)
        if isinstance(attr, dict):
            val = attr.get("value", "")
            if isinstance(val, str) and val.strip():
                return val.strip()
        return None

    @staticmethod
    def _add_tag(ioc: Any, tag: str) -> None:
        """
        Append a tag to the IOC's ``ioc_tags`` string if not already
        present.  Uses exact token matching to avoid false positives
        from substrings (e.g. ``opencti:pushed-extra`` ≠ ``opencti:pushed``).
        Modifies the IOC object in-place; IRIS will commit the change
        since postload hooks receive managed objects.
        """
        current = ioc.ioc_tags or ""
        tokens = {t.strip() for t in current.split(",") if t.strip()}
        if tag not in tokens:
            tokens.add(tag)
            ioc.ioc_tags = ",".join(sorted(tokens))

    @staticmethod
    def _remove_tag(ioc: Any, tag: str) -> None:
        """
        Remove a tag from the IOC's ``ioc_tags`` string if present.
        Uses exact token matching; preserves all other tags and their order.
        """
        current = ioc.ioc_tags or ""
        parts = [t.strip() for t in current.split(",") if t.strip() and t.strip() != tag]
        ioc.ioc_tags = ",".join(parts)

    # ── Push-hash helpers (change detection) ────────────────────

    @staticmethod
    def _get_enrichment(ioc: Any) -> dict:
        """Return the IOC's enrichment dict (never None)."""
        enrichment = getattr(ioc, "ioc_enrichment", None)
        if not enrichment or not isinstance(enrichment, dict):
            return {}
        return enrichment

    @staticmethod
    def _set_enrichment_field(ioc: Any, key: str, value: Any) -> None:
        """Write a single key into ``ioc.ioc_enrichment``."""
        enrichment = getattr(ioc, "ioc_enrichment", None)
        if not enrichment or not isinstance(enrichment, dict):
            enrichment = {}
        enrichment[key] = value
        ioc.ioc_enrichment = enrichment

    @staticmethod
    def _compute_ioc_hash(ioc: Any) -> str:
        """
        Compute a SHA-256 digest of the IOC's key fields.

        Only fields that should trigger a re-push are included:
        value, type, OpenCTI description, confidence override, and TLP.
        The internal ``ioc_description`` and ``ioc_tags`` fields are
        excluded — the former to prevent internal notes from leaking
        changes, the latter to avoid infinite loops (since we write
        tags on push).
        """
        value = getattr(ioc, "ioc_value", "") or ""
        type_name = ""
        ioc_type = getattr(ioc, "ioc_type", None)
        if ioc_type:
            type_name = getattr(ioc_type, "type_name", "") or ""
        # Read description and confidence from OpenCTI-specific custom fields.
        description = (
            OpenCTIHandler._extract_ioc_custom_attribute(ioc, "OpenCTI", "OpenCTI Description") or ""
        )
        confidence_override = (
            OpenCTIHandler._extract_ioc_custom_attribute(ioc, "OpenCTI", "OpenCTI Confidence Score") or ""
        )
        tlp_name = ""
        tlp_obj = getattr(ioc, "tlp", None)
        if tlp_obj:
            tlp_name = getattr(tlp_obj, "tlp_name", "") or ""

        payload = f"{value}|{type_name}|{description}|{confidence_override}|{tlp_name}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _get_push_hash(ioc: Any) -> str | None:
        """Read the last push hash from ``ioc.ioc_enrichment``."""
        return OpenCTIHandler._get_enrichment(ioc).get("opencti_push_hash")

    @staticmethod
    def _store_push_hash(ioc: Any, hex_digest: str) -> None:
        """Store the push hash in ``ioc.ioc_enrichment``."""
        OpenCTIHandler._set_enrichment_field(ioc, "opencti_push_hash", hex_digest)

    @staticmethod
    def _get_push_tlp(ioc: Any) -> str | None:
        """Read the last synced TLP name from ``ioc.ioc_enrichment``."""
        return OpenCTIHandler._get_enrichment(ioc).get("opencti_push_tlp")

    @staticmethod
    def _store_push_tlp(ioc: Any, tlp_name: str) -> None:
        """Store the synced TLP name in ``ioc.ioc_enrichment``."""
        OpenCTIHandler._set_enrichment_field(ioc, "opencti_push_tlp", tlp_name)

    @staticmethod
    def _store_opencti_ids(ioc: Any, observable_ids: list[str]) -> None:
        """Store the OpenCTI observable IDs for later use (e.g. deletion)."""
        OpenCTIHandler._set_enrichment_field(ioc, "opencti_observable_ids", observable_ids)

    @staticmethod
    def _get_opencti_ids(ioc: Any) -> list[str]:
        """Read stored OpenCTI observable IDs. Returns ``[]`` if unset."""
        ids = OpenCTIHandler._get_enrichment(ioc).get("opencti_observable_ids", [])
        return ids if isinstance(ids, list) else []

    @staticmethod
    def _get_synced_case_ids(ioc: Any) -> list[str]:
        """Read IRIS case IDs that have been synced. Returns ``[]`` if unset."""
        ids = OpenCTIHandler._get_enrichment(ioc).get("opencti_synced_case_ids", [])
        return ids if isinstance(ids, list) else []

    @staticmethod
    def _store_synced_case_ids(ioc: Any, case_ids: set[str]) -> None:
        """
        Store synced IRIS case IDs, merging with previously stored IDs
        so earlier syncs are never forgotten.
        """
        existing = set(OpenCTIHandler._get_enrichment(ioc).get("opencti_synced_case_ids", []))
        merged = sorted(existing | case_ids)
        OpenCTIHandler._set_enrichment_field(ioc, "opencti_synced_case_ids", merged)

    @staticmethod
    def _get_synced_case_opencti_ids(ioc: Any) -> list[str]:
        """Read OpenCTI UUIDs of cases we have linked. Returns ``[]`` if unset."""
        ids = OpenCTIHandler._get_enrichment(ioc).get("opencti_synced_case_opencti_ids", [])
        return ids if isinstance(ids, list) else []

    @staticmethod
    def _store_synced_case_opencti_id(ioc: Any, opencti_case_id: str) -> None:
        """
        Accumulate an OpenCTI case UUID so we know which containers
        we own and can make the right delete-vs-unlink decision later.
        """
        existing = set(OpenCTIHandler._get_enrichment(ioc).get("opencti_synced_case_opencti_ids", []))
        existing.add(opencti_case_id)
        OpenCTIHandler._set_enrichment_field(
            ioc, "opencti_synced_case_opencti_ids", sorted(existing)
        )

    # ── Deletion ────────────────────────────────────────────────

    def handle_ioc_delete(self, ioc: Any) -> bool:
        """
        Delete or unlink an IOC's corresponding OpenCTI observable(s).

        Checks whether the observable belongs to containers outside IRIS
        (reports, groupings, manually-created cases, etc.).  If so, only
        the link to our IRIS-created case(s) is removed so the observable
        is preserved for those other investigations.  If IRIS is the sole
        owner, the observable is hard-deleted.
        """
        ioc_value = getattr(ioc, "ioc_value", "unknown")
        opencti_ids = self._get_opencti_ids(ioc)
        # OpenCTI UUIDs of the cases we created — comparable to container IDs
        our_case_opencti_ids = set(self._get_synced_case_opencti_ids(ioc))

        if not opencti_ids:
            self.log.info(
                "IOC '%s' has no stored OpenCTI IDs — nothing to delete",
                ioc_value,
            )
            return True

        all_ok = True
        for obs_id in opencti_ids:
            # If we never stored our case UUIDs (IOCs synced before this feature),
            # skip — we cannot safely determine ownership so we do nothing.
            if not our_case_opencti_ids:
                self.log.warning(
                    "IOC '%s': no OpenCTI case UUIDs stored — skipping delete "
                    "of %s (re-sync the IOC to enable safe deletion)",
                    ioc_value, obs_id,
                )
                continue

            all_container_ids = set(self.client.get_container_ids(obs_id))
            external_container_ids = all_container_ids - our_case_opencti_ids

            if external_container_ids:
                # Observable is shared with non-IRIS containers — unlink only
                self.log.info(
                    "Observable %s for IOC '%s' is referenced by %d external "
                    "container(s) — unlinking from IRIS cases only",
                    obs_id, ioc_value, len(external_container_ids),
                )
                for case_id in our_case_opencti_ids:
                    ok = self.client.unlink_from_case(case_id, obs_id)
                    if not ok:
                        all_ok = False
            else:
                # We are the sole owner — hard delete
                ok = self.client.delete_observable(obs_id)
                if ok:
                    msg = f"Deleted OpenCTI observable {obs_id} (was IOC '{ioc_value}')"
                    self.log.info(msg)
                    self.message_queue.append(msg)
                else:
                    msg = f"Failed to delete OpenCTI observable {obs_id} for IOC '{ioc_value}'"
                    self.log.warning(msg)
                    self.message_queue.append(msg)
                    all_ok = False

        return all_ok
