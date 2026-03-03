"""
IRIS module interface for OpenCTI integration.

This is the main entry point loaded by IRIS when the module is
registered.  It handles hook registration, configuration loading,
and dispatching events to the OpenCTI handler.
"""

from __future__ import annotations

from typing import Any

from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes
from iris_interface import IrisInterfaceStatus

import iris_opencti_module.IrisOpenCTIConfig as interface_conf
from iris_opencti_module.opencti_handler.opencti_handler import OpenCTIHandler
from iris_opencti_module.opencti_handler.opencti_client import OpenCTIClient, OpenCTIClientError


class IrisOpenCTIInterface(IrisModuleInterface):
    """
    IRIS processor module that pushes IOCs to OpenCTI on creation,
    update, or manual trigger.
    """

    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _module_type = IrisModuleTypes.module_processor
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration

    # ── Hook registration ───────────────────────────────────────

    def register_hooks(self, module_id: int) -> None:
        """
        Register or deregister hooks based on the current module
        configuration.  Called by IRIS on module load and config
        changes.
        """
        self.module_id = module_id

        status = self.get_configuration_dict()
        if not status.is_success():
            self.log.error("Failed to load module configuration")
            return

        conf = self._dict_conf

        # on_postload_ioc_create
        if conf.get("opencti_on_create_hook_enabled", True):
            self.register_to_hook(
                module_id,
                iris_hook_name="on_postload_ioc_create",
            )
        else:
            self.deregister_from_hook(module_id, iris_hook_name="on_postload_ioc_create")

        # on_postload_ioc_update
        if conf.get("opencti_on_update_hook_enabled", True):
            self.register_to_hook(
                module_id,
                iris_hook_name="on_postload_ioc_update",
            )
        else:
            self.deregister_from_hook(module_id, iris_hook_name="on_postload_ioc_update")

        # on_manual_trigger_ioc
        if conf.get("opencti_manual_hook_enabled", True):
            self.register_to_hook(
                module_id,
                iris_hook_name="on_manual_trigger_ioc",
                manual_hook_name="Sync to OpenCTI",
            )
        else:
            self.deregister_from_hook(module_id, iris_hook_name="on_manual_trigger_ioc")

        # on_preload_ioc_delete (fires before DB commit so enrichment data is still readable)
        if conf.get("opencti_on_delete_hook_enabled", True):
            self.register_to_hook(module_id, iris_hook_name="on_preload_ioc_delete")
        else:
            self.deregister_from_hook(module_id, iris_hook_name="on_preload_ioc_delete")
        # Deregister the old postload hook in case it was previously registered
        self.deregister_from_hook(module_id, iris_hook_name="on_postload_ioc_delete")

        # ── Validate connectivity at registration time ──────────
        self._check_opencti_connection(conf)

    # ── Health check ──────────────────────────────────────────────

    def _check_opencti_connection(self, conf: dict) -> None:
        """
        Verify OpenCTI connectivity and credentials during module
        registration.  Logs clear warnings but does NOT prevent hook
        registration — the connection may come up later.
        """
        url = (conf.get("opencti_url") or "").strip()
        api_key = (conf.get("opencti_api_key") or "").strip()

        if not url or not api_key:
            self.log.warning(
                "OpenCTI URL or API key not configured — skipping health check"
            )
            return

        try:
            client = OpenCTIClient(
                url=url,
                api_key=api_key,
                ssl_verify=conf.get("opencti_ssl_verify", True),
                http_proxy=conf.get("opencti_http_proxy", "") or "",
                https_proxy=conf.get("opencti_https_proxy", "") or "",
                logger=self.log,
            )
        except OpenCTIClientError as exc:
            self.log.error(
                "OpenCTI health check — cannot create client: %s", exc
            )
            return

        status = client.health_check_detailed()

        if status["ok"]:
            version = status.get("version") or "unknown"
            self.log.info(
                "OpenCTI health check PASSED — connected to %s (v%s), "
                "credentials valid",
                url,
                version,
            )
        else:
            self.log.warning(
                "OpenCTI health check FAILED — %s  "
                "(reachable=%s, authenticated=%s)",
                status.get("error", "unknown error"),
                status["reachable"],
                status["authenticated"],
            )

    # ── Hook dispatcher ─────────────────────────────────────────

    def hooks_handler(
        self,
        hook_name: str,
        hook_ui_name: str,
        data: Any,
    ) -> IrisInterfaceStatus:
        """
        Called by IRIS each time a registered hook fires.

        Dispatches all IOC-related hooks (create, update, manual
        trigger) to the common ``_handle_iocs`` method.
        """
        self.log.info(
            "IrisOpenCTI hook fired: %s (%s)", hook_name, hook_ui_name
        )

        status = self.get_configuration_dict()
        if not status.is_success():
            self.log.error("Failed to load module configuration on hook call")
            return IrisInterfaceStatus.I2Error(
                data=data,
                logs=list(self.message_queue),
                message="Configuration error",
            )

        if hook_name in (
            "on_postload_ioc_create",
            "on_postload_ioc_update",
            "on_manual_trigger_ioc",
        ):
            is_manual = hook_name == "on_manual_trigger_ioc"
            return self._handle_iocs(data, is_manual=is_manual)

        if hook_name == "on_preload_ioc_delete":
            return self._handle_ioc_deletes(data)

        self.log.warning("Unhandled hook: %s", hook_name)
        return IrisInterfaceStatus.I2Success(
            data=data, logs=list(self.message_queue)
        )

    # ── IOC processing ──────────────────────────────────────────

    def _handle_iocs(self, data: Any, is_manual: bool = False) -> IrisInterfaceStatus:
        """
        Iterate over all IOC objects in ``data`` and push each to
        OpenCTI via the handler.
        """
        def _process(handler, ioc):
            cases = self._lookup_cases_for_ioc(ioc)
            return handler.handle_ioc(ioc, cases_info=cases)

        handler = self._create_handler(data)
        if not hasattr(handler, 'handle_ioc'):
            return handler  # creation failed — error status
        handler._is_manual = is_manual
        return self._iterate_iocs(data, handler, _process, "push")

    # ── IOC deletion ────────────────────────────────────────────

    def _handle_ioc_deletes(self, data: Any) -> IrisInterfaceStatus:
        """
        Delete OpenCTI observables corresponding to deleted IRIS IOCs.

        IRIS passes the IOC primary-key (int) to preload hooks rather than
        the full SQLAlchemy object, so we resolve the model object here
        while the row is still present in the DB.
        """
        handler = self._create_handler(data)
        if not hasattr(handler, 'handle_ioc'):
            return handler

        # Normalise: IRIS may pass a single int ID or a list of int IDs
        raw = data if isinstance(data, list) else [data]
        resolved = []
        for item in raw:
            if isinstance(item, int):
                ioc_obj = self._resolve_ioc_by_id(item)
                if ioc_obj is None:
                    self.log.warning(
                        "on_preload_ioc_delete: IOC id=%s not found in DB", item
                    )
                    continue
                resolved.append(ioc_obj)
            else:
                resolved.append(item)

        if not resolved:
            self.log.warning("on_preload_ioc_delete: no resolvable IOCs in data")
            return IrisInterfaceStatus.I2Success(
                data=data, logs=list(self.message_queue)
            )

        return self._iterate_iocs(
            resolved, handler, lambda h, ioc: h.handle_ioc_delete(ioc), "delete sync",
        )

    # ── Shared helpers ──────────────────────────────────────────

    def _create_handler(self, data: Any):
        """
        Instantiate an ``OpenCTIHandler``.  Returns the handler on
        success or an ``IrisInterfaceStatus`` error on failure.
        """
        try:
            handler = OpenCTIHandler(
                mod_config=self._dict_conf,
                logger=self.log,
            )
            return handler
        except OpenCTIClientError as exc:
            msg = f"OpenCTI connection failed: {exc}"
            self.log.error(msg)
            self.message_queue.append(msg)
            return IrisInterfaceStatus.I2Error(
                data=data,
                logs=list(self.message_queue),
                message=msg,
            )
        except Exception as exc:
            msg = f"Failed to initialise OpenCTI handler: {exc}"
            self.log.error(msg, exc_info=True)
            self.message_queue.append(msg)
            return IrisInterfaceStatus.I2Error(
                data=data,
                logs=list(self.message_queue),
                message=msg,
            )

    def _iterate_iocs(
        self,
        data: Any,
        handler: OpenCTIHandler,
        action,
        label: str,
    ) -> IrisInterfaceStatus:
        """
        Common iteration pattern: normalise data, call *action* per
        IOC, count successes/failures, build summary.
        """
        iocs = data if isinstance(data, list) else [data]
        success_count = 0
        fail_count = 0

        for ioc in iocs:
            try:
                if action(handler, ioc):
                    success_count += 1
                else:
                    fail_count += 1
            except Exception as exc:
                ioc_val = getattr(ioc, "ioc_value", "unknown")
                msg = f"Unexpected error during {label} for IOC '{ioc_val}': {exc}"
                self.log.error(msg, exc_info=True)
                self.message_queue.append(msg)
                fail_count += 1

        self.message_queue.extend(handler.message_queue)

        summary = f"OpenCTI {label} complete: {success_count} succeeded, {fail_count} failed"
        self.log.info(summary)
        self.message_queue.append(summary)

        if fail_count > 0 and success_count == 0:
            return IrisInterfaceStatus.I2Error(
                data=data,
                logs=list(self.message_queue),
                message=summary,
            )

        return IrisInterfaceStatus.I2Success(
            data=data,
            logs=list(self.message_queue),
        )

    def _resolve_ioc_by_id(self, ioc_id: int):
        """
        Load an Ioc model object by primary key while the row still
        exists (i.e. during a preload hook, before the DB commit).
        Returns None if the row is not found or the import fails.
        """
        try:
            from app.models.models import Ioc
            return Ioc.query.filter_by(ioc_id=ioc_id).first()
        except Exception as exc:
            self.log.error(
                "on_preload_ioc_delete: failed to load IOC id=%s: %s", ioc_id, exc
            )
            return None

    # ── Case lookup ─────────────────────────────────────────────

    def _lookup_cases_for_ioc(self, ioc: Any) -> list:
        """
        Resolve ALL IRIS cases linked to an IOC via the IocLink table.

        Returns a list of Cases objects (may be empty).
        """
        ioc_id = getattr(ioc, "ioc_id", None)
        if ioc_id is None:
            return []

        try:
            from app.models.models import IocLink

            links = IocLink.query.filter(
                IocLink.ioc_id == ioc_id
            ).all()

            cases = [link.case for link in links if link.case]
            if cases:
                self.log.info(
                    "IOC %s is linked to %d case(s): %s",
                    ioc_id,
                    len(cases),
                    ", ".join(
                        str(getattr(c, "case_id", "?")) for c in cases
                    ),
                )
            return cases
        except Exception as exc:
            # Log but don't crash — the IOC can still be pushed without
            # a case association.
            self.log.warning(
                "Failed to look up cases for IOC %s: %s", ioc_id, exc
            )

        return []
