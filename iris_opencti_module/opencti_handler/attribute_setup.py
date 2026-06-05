"""
Ensures the 'OpenCTI' custom-attribute tab exists in the global IOC
attribute template (CustomAttribute table, attribute_for='ioc').

IRIS uses get_default_custom_attributes('ioc') when rendering the
"Add IOC" modal, so any tab registered here appears immediately in
the create dialog — before the IOC is saved and before any hook fires.

Also backfills existing IOCs that are missing the tab or its fields.
"""

from __future__ import annotations

ATTRIBUTE_FOR = "ioc"
ATTRIBUTE_TAB = "OpenCTI"
FIELD_DESCRIPTION = "OpenCTI Description"
FIELD_CONFIDENCE = "OpenCTI Confidence Score"

_OUR_TAB_TEMPLATE = {
    FIELD_DESCRIPTION: {
        "type": "input_textfield",
        "value": "",
        "mandatory": False,
    },
    FIELD_CONFIDENCE: {
        "type": "input_string",
        "value": "50",
        "mandatory": False,
    },
}

# Guards repeated full-table backfill within the same worker/app process lifetime.
_backfill_done: bool = False


def ensure_ioc_attribute_exists(logger, confidence_default: int = 50) -> None:
    """
    Create or update the OpenCTI tab in the global IOC CustomAttribute template.

    Called from register_hooks (which runs in the *app* container context
    where the IRIS DB models are available).  Safe to call repeatedly.
    """
    try:
        from app import db
        from app.models.models import CustomAttribute
        from sqlalchemy.orm.attributes import flag_modified

        ca = CustomAttribute.query.filter(
            CustomAttribute.attribute_for == ATTRIBUTE_FOR
        ).first()

        template = dict(_OUR_TAB_TEMPLATE)
        template[FIELD_CONFIDENCE] = dict(template[FIELD_CONFIDENCE])
        template[FIELD_CONFIDENCE]["value"] = str(confidence_default)

        if ca is None:
            ca = CustomAttribute()
            ca.attribute_for = ATTRIBUTE_FOR
            ca.attribute_display_name = "IOCs"
            ca.attribute_description = "Defines default attributes for IOCs"
            ca.attribute_content = {ATTRIBUTE_TAB: template}
            db.session.add(ca)
            db.session.commit()
            logger.info("Created IOC CustomAttribute with OpenCTI tab")
            return

        content = ca.attribute_content or {}

        if ATTRIBUTE_TAB not in content:
            content[ATTRIBUTE_TAB] = template
            ca.attribute_content = content
            flag_modified(ca, "attribute_content")
            db.session.commit()
            logger.info("Added OpenCTI tab to IOC custom attribute template")
        else:
            changed = False
            # Add any fields that are entirely missing from the tab.
            for field_name, field_def in template.items():
                if field_name not in content[ATTRIBUTE_TAB]:
                    content[ATTRIBUTE_TAB][field_name] = field_def
                    changed = True
                    logger.info("Added missing field '%s' to OpenCTI tab template", field_name)

            # Keep the template confidence default in sync with the module setting.
            # Only update when the field already existed — if it was just added by
            # the loop above it already carries the correct value from `template`.
            # This ensures the "Add IOC" modal shows the updated pre-fill after an
            # admin changes opencti_confidence in the module settings.
            if FIELD_CONFIDENCE in content[ATTRIBUTE_TAB]:
                current_confidence = content[ATTRIBUTE_TAB][FIELD_CONFIDENCE].get("value")
                new_confidence = template[FIELD_CONFIDENCE]["value"]
                if current_confidence != new_confidence:
                    content[ATTRIBUTE_TAB][FIELD_CONFIDENCE] = dict(content[ATTRIBUTE_TAB][FIELD_CONFIDENCE])
                    content[ATTRIBUTE_TAB][FIELD_CONFIDENCE]["value"] = new_confidence
                    changed = True
                    logger.info(
                        "Updated OpenCTI Confidence Score template default: %s → %s",
                        current_confidence, new_confidence,
                    )

            if changed:
                ca.attribute_content = content
                flag_modified(ca, "attribute_content")
                db.session.commit()

        # Backfill existing IOCs that are missing the tab or its fields.
        global _backfill_done
        if not _backfill_done:
            _propagate_missing_fields(logger, template)
            _backfill_done = True

    except Exception:
        logger.exception("Failed to ensure OpenCTI IOC custom attribute template")


def _propagate_missing_fields(logger, template: dict) -> None:
    """
    Add any fields from our template that are absent from existing IOC records.

    Purely additive — never touches existing field values.
    """
    try:
        from app import db
        from app.models.models import Ioc
        from sqlalchemy.orm.attributes import flag_modified
        import copy

        iocs = Ioc.query.all()
        updated = 0
        for ioc in iocs:
            attrs = ioc.custom_attributes or {}
            tab = attrs.get(ATTRIBUTE_TAB)
            changed = False

            if tab is None:
                attrs[ATTRIBUTE_TAB] = copy.deepcopy(template)
                changed = True
            else:
                for field_name, field_def in template.items():
                    if field_name not in tab:
                        tab[field_name] = copy.deepcopy(field_def)
                        changed = True

            if changed:
                ioc.custom_attributes = attrs
                flag_modified(ioc, "custom_attributes")
                updated += 1

        if updated:
            db.session.commit()
            logger.info("Backfilled missing OpenCTI fields on %d IOC(s)", updated)

    except Exception:
        logger.exception("Failed to backfill OpenCTI fields on existing IOCs")
