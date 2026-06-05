"""
HTML renderer for the OpenCTI enrichment tab in IRIS.

Builds the rich HTML report that analysts see in the IOC detail
view under the "OpenCTI" tab.  Purely presentational — no side
effects, no dependencies on pycti or IRIS models.
"""

from __future__ import annotations

from html import escape as _esc


# ── Lookup tables ───────────────────────────────────────────────

_CONTAINER_URL_PATHS: dict[str, str] = {
    "Report": "analyses/reports",
    "Case-Incident": "cases/incidents",
    "Case-Rfi": "cases/rfis",
    "Case-Rft": "cases/rfts",
    "Grouping": "analyses/groupings",
    "Note": "analyses/notes",
    "Opinion": "analyses/opinions",
    "Observed-Data": "events/observed_data",
}

_CONTAINER_DISPLAY_TYPES: dict[str, str] = {
    "Report": "Report",
    "Case-Incident": "Case",
    "Case-Rfi": "RFI",
    "Case-Rft": "RFT",
    "Grouping": "Grouping",
    "Note": "Note",
    "Opinion": "Opinion",
    "Observed-Data": "Observed Data",
}

_THREAT_SECTIONS = [
    ("threat_actors", "Threat Actors", "#c62828", "threats/threat_actors"),
    ("intrusion_sets", "Intrusion Sets", "#6a1b9a", "threats/intrusion_sets"),
    ("malware", "Malware", "#d84315", "arsenal/malware"),
    ("campaigns", "Campaigns", "#00695c", "threats/campaigns"),
    ("attack_patterns", "ATT&CK Techniques", "#283593", "techniques/attack_patterns"),
]

# No custom <style> block — IRIS 2.5.x strips <style> tags via bleach but
# leaves the text content as visible raw CSS.  All styling uses Bootstrap 4
# utility classes (allowed by the sanitizer's 'class' whitelist) and the
# built-in semantic HTML elements that carry browser-default styling.


# ── Small helpers ───────────────────────────────────────────────

def _score_text_class(score: int | None) -> str:
    """Return a Bootstrap 4 text-colour utility class for an OpenCTI score."""
    if score is None:
        return "text-muted"
    if score >= 70:
        return "text-danger"   # red — high
    if score >= 40:
        return "text-warning"  # orange — medium
    return "text-success"      # green — low


def _is_safe_url(url: str) -> bool:
    """Return True only for http(s) URLs — blocks javascript:, data:, etc."""
    stripped = url.strip().lower()
    return stripped.startswith("http://") or stripped.startswith("https://")


def _container_url_path(entity_type: str) -> str:
    """Return the OpenCTI dashboard URL path segment for a container type."""
    return _CONTAINER_URL_PATHS.get(entity_type, "")


def _container_display_type(entity_type: str) -> str:
    """Return a human-friendly label for a container entity_type."""
    return _CONTAINER_DISPLAY_TYPES.get(entity_type, entity_type)


# ── Main renderer ───────────────────────────────────────────────

def render_enrichment_html(
    enrichments: list[dict],
    opencti_url: str,
    case_names: list[str],
    tlp_name: str,
    synced_at: str,
) -> str:
    """
    Build the HTML report for the enrichment tab.

    Renders a summary header (status, case, TLP, sync time) plus
    a details section per observable with score, labels, linked
    indicators (STIX patterns / YARA), and external references.
    """
    parts = [
        '<h6 class="border-bottom pb-1 mb-2 font-weight-bold">&#x1F50D; OpenCTI Sync Summary</h6>',
        _render_summary_table(enrichments, case_names, tlp_name, synced_at),
    ]

    # Sanitise the configured URL before embedding it in any href.
    # An admin-supplied javascript: or data: URL would otherwise be
    # stored as a clickable link in every IOC enrichment tab (stored XSS).
    safe_url = opencti_url if _is_safe_url(opencti_url) else ""

    for i, obs in enumerate(enrichments, 1):
        parts.append(_render_observable_card(obs, i, safe_url))

    return "\n".join(parts)

def _rows_html(rows: list[tuple[str, str]]) -> str:
    """Render key/value pairs as compact Bootstrap grid rows."""
    parts = []
    for lbl, val in rows:
        parts.append(
            f'<div class="row no-gutters border-bottom py-1 small">'
            f'<div class="col-3 font-weight-bold text-muted">{lbl}</div>'
            f'<div class="col-9">{val}</div>'
            f'</div>'
        )
    return "\n".join(parts)

def _render_summary_table(
    enrichments: list[dict],
    case_names: list[str],
    tlp_name: str,
    synced_at: str,
) -> str:
    """Build the summary header table."""
    rows: list[tuple[str, str]] = [
        ("Status", "&#x2705; Pushed to OpenCTI"),
    ]
    if case_names:
        if len(case_names) == 1:
            rows.append(("Case Incident", f"<code>{_esc(case_names[0])}</code>"))
        else:
            cases_html = ", ".join(f"<code>{_esc(n)}</code>" for n in case_names)
            rows.append((f"Case Incidents ({len(case_names)})", cases_html))
    rows.append((
        "TLP",
        f"<code>{_esc(tlp_name.upper())}</code>" if tlp_name else "<em>default</em>",
    ))
    rows.append(("Last synced", f"<code>{_esc(synced_at)}</code>"))
    rows.append((
        "Observables",
        f"<strong>{len(enrichments)}</strong> created / updated",
    ))

    rows_html = _rows_html(rows)
    return f'<div class="mb-2">{rows_html}</div>'


# ── Per-observable card ─────────────────────────────────────────

def _render_observable_card(obs: dict, index: int, opencti_url: str) -> str:
    """Render a single observable detail card."""
    obs_id = obs.get("id", "unknown")
    entity_type = obs.get("entity_type", "")
    obs_value = obs.get("value", "")
    score = obs.get("score")
    description = obs.get("description", "")
    created_by = obs.get("created_by", "")
    labels = obs.get("labels") or []
    indicators = obs.get("indicators") or []
    ext_refs = obs.get("external_references") or []
    markings = obs.get("markings") or []

    link = (
        f'{opencti_url}/dashboard/observations/observables/{_esc(obs_id)}'
        if opencti_url else ""
    )
    title = f"Observable {index}: {_esc(entity_type)}" if entity_type else f"Observable {index}"
    title_html = (
        f'<a href="{_esc(link)}" target="_blank" '
        f'rel="noopener noreferrer" style="color:#fff;'
        f'text-decoration:underline">{title}</a>'
        if link else title
    )

    detail_rows: list[tuple[str, str]] = []

    # Value
    if obs_value:
        detail_rows.append(("Value", f"<code>{_esc(obs_value)}</code>"))

    # Score badge
    if score is not None:
        score_cls = _score_text_class(score)
        detail_rows.append((
            "Score",
            f'<span class="font-weight-bold h5 {score_cls}">{score}/100</span>',
        ))

    # Description
    if description:
        detail_rows.append(("Description", _esc(description)))

    # Author
    if created_by:
        detail_rows.append(("Created by", f"<code>{_esc(created_by)}</code>"))

    # Markings
    if markings:
        marking_html = ", ".join(f"<code>{_esc(m)}</code>" for m in markings)
        detail_rows.append(("Markings", marking_html))

    # Labels
    if labels:
        label_html = " ".join(
            f'<span class="badge badge-secondary">{_esc(lb.get("value", ""))}</span>'
            for lb in labels
            if lb.get("value")
        )
        if label_html:
            detail_rows.append(("Labels", label_html))

    # Indicators
    if indicators:
        detail_rows.append(("Indicators", _render_indicators(indicators)))

    # External references
    if ext_refs:
        detail_rows.append(("External References", _render_ext_refs(ext_refs)))

    # Containers
    containers = obs.get("containers") or []
    if containers:
        detail_rows.append((
            f"Containers ({len(containers)})",
            _render_containers(containers, opencti_url),
        ))

    # Threat context
    threat_ctx = obs.get("threat_context") or {}
    for ctx_key, ctx_label, ctx_color, ctx_path in _THREAT_SECTIONS:
        items = threat_ctx.get(ctx_key) or []
        if items:
            detail_rows.append((
                f"{ctx_label} ({len(items)})",
                _render_threat_items(items, ctx_color, ctx_path, opencti_url),
            ))

    # Sightings
    sightings = obs.get("sightings") or []
    if sightings:
        detail_rows.append((
            f"Sightings ({len(sightings)})",
            _render_sightings(sightings),
        ))

    if not detail_rows:
        detail_rows.append((
            "ID",
            f"<code>{_esc(obs_id)}</code> <em>(details unavailable)</em>",
        ))

    rows_html = _rows_html(detail_rows)
    return (
        f'<h6 class="border-bottom pb-1 mb-1 mt-2 font-weight-bold">{title_html}</h6>\n'
        f'<div class="mb-2">{rows_html}</div>'
    )


# ── Section renderers ───────────────────────────────────────────

def _render_indicators(indicators: list[dict]) -> str:
    """Render STIX pattern / YARA / Sigma indicators."""
    parts = []
    for ind in indicators:
        ptype = _esc(ind.get("pattern_type", "stix"))
        pattern = _esc(ind.get("pattern", ""))
        if pattern:
            parts.append(
                f'<code class="d-block">[{ptype}] {pattern}</code>'
            )
    return "\n".join(parts)


def _render_ext_refs(refs: list[dict]) -> str:
    """Render external references."""
    parts = []
    for ref in refs:
        source = ref.get("source", "")
        url = ref.get("url", "")
        ext_id = ref.get("external_id", "")
        label_text = _esc(source or ext_id or url)
        if url and _is_safe_url(url):
            parts.append(
                f'<div class="mb-1">'
                f'<a href="{_esc(url)}" target="_blank" '
                f'rel="noopener noreferrer">{label_text}</a>'
                f'{": (" + _esc(ext_id) + ")" if ext_id and source else ""}'
                f'</div>'
            )
        elif label_text:
            parts.append(f'<div class="mb-1">{label_text}</div>')
    return "\n".join(parts)


def _render_containers(containers: list[dict], opencti_url: str) -> str:
    """Render container links (reports, cases, groupings, etc.)."""
    parts = []
    for ctr in containers:
        ctr_type = ctr.get("type", "")
        ctr_name = ctr.get("name", "")
        ctr_id = ctr.get("id", "")
        ctr_date = ctr.get("date", "")

        type_path = _container_url_path(ctr_type)
        display_type = _container_display_type(ctr_type)

        label_text = _esc(ctr_name or ctr_id)
        date_suffix = (
            f' <span style="color:#888">({_esc(ctr_date[:10])})</span>'
            if ctr_date else ""
        )
        type_badge = (
            f'<span class="badge badge-secondary">{_esc(display_type)}</span> '
            if display_type else ""
        )

        if opencti_url and type_path and ctr_id:
            ctr_url = f"{opencti_url}/dashboard/{type_path}/{_esc(ctr_id)}"
            parts.append(
                f'<div class="mb-1">{type_badge}'
                f'<a href="{_esc(ctr_url)}" target="_blank" '
                f'rel="noopener noreferrer">{label_text}</a>'
                f'{date_suffix}</div>'
            )
        else:
            parts.append(
                f'<div class="mb-1">{type_badge}'
                f'{label_text}{date_suffix}</div>'
            )
    return "\n".join(parts)


def _render_threat_items(
    items: list[dict],
    color: str,
    path: str,
    opencti_url: str,
) -> str:
    """Render threat context items (actors, malware, TTPs, etc.)."""
    parts = []
    for item in items:
        item_name = _esc(item.get("name", ""))
        item_id = item.get("id", "")
        mitre_id = item.get("mitre_id", "")
        mitre_prefix = (
            f'<code>{_esc(mitre_id)}</code> '
            if mitre_id else ""
        )
        if opencti_url and item_id:
            item_url = f"{opencti_url}/dashboard/{path}/{_esc(item_id)}"
            parts.append(
                f'<div class="mb-1">{mitre_prefix}'
                f'<a href="{_esc(item_url)}" target="_blank" '
                f'rel="noopener noreferrer">'
                f'{item_name}</a></div>'
            )
        else:
            parts.append(
                f'<div class="mb-1">{mitre_prefix}{item_name}</div>'
            )
    return "\n".join(parts)


def _render_sightings(sightings: list[dict]) -> str:
    """Render sighting entries."""
    parts = []
    for sig in sightings:
        source = _esc(sig.get("source", "Unknown"))
        first_seen = sig.get("first_seen", "")
        last_seen = sig.get("last_seen", "")
        count = _esc(sig.get("count", "1"))
        # Build compact one-liner per sighting
        date_range = ""
        if first_seen and last_seen:
            date_range = (
                f' <span style="color:#888">'
                f'{_esc(first_seen[:10])} \u2192 {_esc(last_seen[:10])}</span>'
            )
        elif first_seen:
            date_range = (
                f' <span style="color:#888">'
                f'from {_esc(first_seen[:10])}</span>'
            )
        count_badge = (
            f' <span class="badge badge-secondary">{count}x</span>'
            if count and count != "1" else ""
        )
        parts.append(
            f'<div class="border-bottom py-1 small">'
            f'<strong>{source or "Unknown"}</strong>'
            f'{count_badge}{date_range}</div>'
        )
    return "\n".join(parts)
