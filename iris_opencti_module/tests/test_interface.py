"""
Unit tests for IrisOpenCTIInterface — hook dispatch, IOC processing
loop, and error handling paths.

The IRIS SDK (iris_interface) is not available outside the IRIS worker
container, so it is mocked in sys.modules before any imports occur.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

# ── Mock the IRIS SDK ─────────────────────────────────────────────────────────
# Must happen before iris_opencti_module.IrisOpenCTIInterface is imported.


class _FakeIrisModuleBase:
    """
    Minimal stand-in for IrisModuleInterface so that IrisOpenCTIInterface
    can inherit from it and be instantiated in tests.
    """

    # Class-level attributes that the real SDK uses; subclass overrides them
    _module_name = ""
    _module_description = ""
    _interface_version = ""
    _module_version = ""
    _module_type = None
    _pipeline_support = False
    _pipeline_info = {}
    _module_configuration = []

    def __init__(self):
        self.log = MagicMock()
        self.message_queue: list[str] = []
        self._dict_conf: dict = {}
        self.module_id: int = 0
        # default: get_configuration_dict() succeeds and reflects _dict_conf
        self._config_success = True

    def get_configuration_dict(self):
        status = MagicMock()
        status.is_success.return_value = self._config_success
        return status

    def register_to_hook(self, module_id, iris_hook_name, manual_hook_name=None):
        pass

    def deregister_from_hook(self, module_id, iris_hook_name):
        pass


# Fake IrisModuleTypes enum-like
_FakeIrisModuleTypes = SimpleNamespace(module_processor="processor")

# IrisInterfaceStatus: create real return objects (not MagicMock) so
# isinstance checks or attribute access in the interface works correctly.
class _FakeI2Status:
    def __init__(self, ok: bool, data=None, logs=None, message=""):
        self.ok = ok
        self.data = data
        self.logs = logs or []
        self.message = message


class _FakeIrisInterfaceStatus:
    @staticmethod
    def I2Success(data=None, logs=None):
        return _FakeI2Status(ok=True, data=data, logs=logs)

    @staticmethod
    def I2Error(data=None, logs=None, message=""):
        return _FakeI2Status(ok=False, data=data, logs=logs, message=message)


# Inject fakes into sys.modules
_iris_mod_iface_module = MagicMock()
_iris_mod_iface_module.IrisModuleInterface = _FakeIrisModuleBase
_iris_mod_iface_module.IrisModuleTypes = _FakeIrisModuleTypes

_iris_iface_module = MagicMock()
_iris_iface_module.IrisInterfaceStatus = _FakeIrisInterfaceStatus

sys.modules["iris_interface"] = _iris_iface_module
sys.modules["iris_interface.IrisModuleInterface"] = _iris_mod_iface_module

# Also ensure pycti / stix2 are mocked (conftest may have done this, but be safe)
_pycti_mock = MagicMock()
_stix2_mock = MagicMock()
_stix2_mock.TLP_WHITE = {"id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"}
_stix2_mock.TLP_GREEN = {"id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"}
_stix2_mock.TLP_AMBER = {"id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"}
_stix2_mock.TLP_RED = {"id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}
sys.modules.setdefault("pycti", _pycti_mock)
sys.modules.setdefault("stix2", _stix2_mock)


# ── Import after mocks are in place ──────────────────────────────────────────

from iris_opencti_module.IrisOpenCTIInterface import IrisOpenCTIInterface  # noqa: E402
from iris_opencti_module.opencti_handler.opencti_client import OpenCTIClientError  # noqa: E402


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_interface(conf: dict | None = None) -> IrisOpenCTIInterface:
    """Create an interface instance with a pre-loaded config."""
    iface = IrisOpenCTIInterface.__new__(IrisOpenCTIInterface)
    _FakeIrisModuleBase.__init__(iface)
    iface._dict_conf = conf or {
        "opencti_url": "https://opencti.test",
        "opencti_api_key": "tok-123",
        "opencti_ssl_verify": True,
        "opencti_on_create_hook_enabled": True,
        "opencti_on_update_hook_enabled": True,
        "opencti_manual_hook_enabled": True,
        "opencti_on_delete_hook_enabled": False,
    }
    return iface


def _make_ioc(value="evil.com", type_name="domain"):
    ioc = SimpleNamespace()
    ioc.ioc_id = 1
    ioc.ioc_value = value
    ioc.ioc_type = SimpleNamespace(type_name=type_name)
    ioc.ioc_tags = ""
    ioc.ioc_description = ""
    ioc.tlp = None
    ioc.ioc_enrichment = None
    return ioc


def _success_status():
    return _FakeIrisInterfaceStatus.I2Success(data=None, logs=[])


# ── hooks_handler dispatch ────────────────────────────────────────────────────


@patch("iris_opencti_module.IrisOpenCTIInterface.OpenCTIHandler")
class TestHooksHandlerDispatch:

    def test_create_hook_calls_handle_iocs(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        ioc = _make_ioc()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "Create IOC", ioc)

        assert result.ok is True
        handler.handle_ioc.assert_called_once_with(ioc, cases_info=[])

    def test_update_hook_calls_handle_iocs(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        ioc = _make_ioc()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_update", "Update IOC", ioc)

        assert result.ok is True
        handler.handle_ioc.assert_called_once()

    def test_manual_trigger_sets_is_manual_true(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        ioc = _make_ioc()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            iface.hooks_handler("on_manual_trigger_ioc", "Sync to OpenCTI", ioc)

        assert handler._is_manual is True

    def test_create_hook_does_not_set_is_manual(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        ioc = _make_ioc()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            iface.hooks_handler("on_postload_ioc_create", "", ioc)

        assert handler._is_manual is False

    def test_delete_hook_calls_handle_ioc_delete(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc_delete.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        ioc = _make_ioc()

        result = iface.hooks_handler("on_preload_ioc_delete", "Delete IOC", ioc)

        assert result.ok is True
        handler.handle_ioc_delete.assert_called_once_with(ioc)

    def test_delete_hook_resolves_integer_id(self, MockHandler):
        """IRIS passes an int IOC ID to preload hooks — must be resolved to an object."""
        handler = MockHandler.return_value
        handler.handle_ioc_delete.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        ioc = _make_ioc()

        with patch.object(iface, "_resolve_ioc_by_id", return_value=ioc) as mock_resolve:
            result = iface.hooks_handler("on_preload_ioc_delete", "Delete IOC", 42)

        assert result.ok is True
        mock_resolve.assert_called_once_with(42)
        handler.handle_ioc_delete.assert_called_once_with(ioc)

    def test_delete_hook_int_not_in_db_returns_success(self, MockHandler):
        """If the int ID resolves to nothing we skip silently."""
        handler = MockHandler.return_value
        handler.handle_ioc_delete.return_value = True
        handler.message_queue = []

        iface = _make_interface()

        with patch.object(iface, "_resolve_ioc_by_id", return_value=None):
            result = iface.hooks_handler("on_preload_ioc_delete", "Delete IOC", 99)

        assert result.ok is True
        handler.handle_ioc_delete.assert_not_called()

    def test_unknown_hook_returns_success(self, MockHandler):
        iface = _make_interface()
        ioc = _make_ioc()

        result = iface.hooks_handler("on_unknown_hook", "Unknown", ioc)

        assert result.ok is True
        MockHandler.return_value.handle_ioc.assert_not_called()

    def test_config_load_failure_returns_error(self, MockHandler):
        iface = _make_interface()
        iface._config_success = False
        ioc = _make_ioc()

        result = iface.hooks_handler("on_postload_ioc_create", "", ioc)

        assert result.ok is False
        MockHandler.return_value.handle_ioc.assert_not_called()


# ── _iterate_iocs: list vs single IOC, success/failure counting ───────────────


@patch("iris_opencti_module.IrisOpenCTIInterface.OpenCTIHandler")
class TestIterateIocs:

    def test_list_of_iocs_all_processed(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = True
        handler.message_queue = []

        iface = _make_interface()
        iocs = [_make_ioc("a.com"), _make_ioc("b.com"), _make_ioc("c.com")]

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", iocs)

        assert result.ok is True
        assert handler.handle_ioc.call_count == 3

    def test_all_failures_returns_error_status(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = False
        handler.message_queue = []

        iface = _make_interface()
        iocs = [_make_ioc("a.com"), _make_ioc("b.com")]

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", iocs)

        assert result.ok is False

    def test_mixed_success_failure_returns_success(self, MockHandler):
        """Partial success (some succeeded) → I2Success, not I2Error."""
        handler = MockHandler.return_value
        handler.handle_ioc.side_effect = [True, False, True]
        handler.message_queue = []

        iface = _make_interface()
        iocs = [_make_ioc("a.com"), _make_ioc("b.com"), _make_ioc("c.com")]

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", iocs)

        assert result.ok is True

    def test_unexpected_exception_counted_as_failure(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.side_effect = RuntimeError("unexpected crash")
        handler.message_queue = []

        iface = _make_interface()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", _make_ioc())

        assert result.ok is False

    def test_handler_message_queue_merged_into_response_logs(self, MockHandler):
        handler = MockHandler.return_value
        handler.handle_ioc.return_value = True
        handler.message_queue = ["Created observable X in OpenCTI"]

        iface = _make_interface()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", _make_ioc())

        assert any("Created observable X" in log for log in result.logs)


# ── _create_handler: OpenCTIClientError → I2Error ─────────────────────────────


@patch("iris_opencti_module.IrisOpenCTIInterface.OpenCTIHandler")
class TestCreateHandler:

    def test_opencti_client_error_returns_i2error(self, MockHandler):
        MockHandler.side_effect = OpenCTIClientError("bad URL")

        iface = _make_interface()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", _make_ioc())

        assert result.ok is False
        assert "OpenCTI connection failed" in result.message or "bad URL" in result.message

    def test_unexpected_exception_in_handler_init_returns_i2error(self, MockHandler):
        MockHandler.side_effect = RuntimeError("some unexpected error")

        iface = _make_interface()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", _make_ioc())

        assert result.ok is False

    def test_health_check_failure_returns_i2error(self, MockHandler):
        """If the handler is created but health_check_detailed fails,
        _create_handler must return I2Error with a clear message."""
        handler = MockHandler.return_value
        handler.client.health_check_detailed.return_value = {
            "ok": False,
            "reachable": True,
            "authenticated": False,
            "version": None,
            "error": "Authentication failed: FORBIDDEN_ACCESS",
        }
        handler.message_queue = []

        iface = _make_interface()

        with patch.object(iface, "_lookup_cases_for_ioc", return_value=[]):
            result = iface.hooks_handler("on_postload_ioc_create", "", _make_ioc())

        assert result.ok is False
        assert "connection check failed" in result.message.lower()
        assert "authenticated=False" in result.message


# ── _lookup_cases_for_ioc ─────────────────────────────────────────────────────


class TestLookupCasesForIoc:

    def test_ioc_without_ioc_id_returns_empty(self):
        iface = _make_interface()
        ioc = SimpleNamespace()  # no ioc_id attribute

        result = iface._lookup_cases_for_ioc(ioc)

        assert result == []

    def test_ioc_link_db_unavailable_returns_empty(self):
        """If app.models.models can't be imported, return empty list gracefully."""
        iface = _make_interface()
        ioc = SimpleNamespace(ioc_id=1)

        # IocLink import raises (as it would outside the worker container)
        with patch.dict("sys.modules", {"app.models.models": None}):
            result = iface._lookup_cases_for_ioc(ioc)

        assert result == []

    def test_ioc_link_query_exception_returns_empty(self):
        """DB query raising an exception should return empty, not crash."""
        iface = _make_interface()
        ioc = SimpleNamespace(ioc_id=42)

        mock_ioc_link = MagicMock()
        mock_ioc_link.query.filter.return_value.all.side_effect = Exception("DB down")

        mock_models = MagicMock()
        mock_models.IocLink = mock_ioc_link

        with patch.dict("sys.modules", {"app.models.models": mock_models}):
            result = iface._lookup_cases_for_ioc(ioc)

        assert result == []

    def test_ioc_with_linked_cases_returns_them(self):
        iface = _make_interface()
        ioc = SimpleNamespace(ioc_id=7)

        case_a = SimpleNamespace(case_id=1, name="Case A")
        case_b = SimpleNamespace(case_id=2, name="Case B")

        fake_links = [
            SimpleNamespace(case=case_a),
            SimpleNamespace(case=case_b),
        ]
        mock_ioc_link = MagicMock()
        mock_ioc_link.query.filter.return_value.all.return_value = fake_links

        mock_models = MagicMock()
        mock_models.IocLink = mock_ioc_link

        with patch.dict("sys.modules", {"app.models.models": mock_models}):
            result = iface._lookup_cases_for_ioc(ioc)

        assert len(result) == 2
        assert case_a in result
        assert case_b in result

    def test_links_with_none_case_are_filtered(self):
        iface = _make_interface()
        ioc = SimpleNamespace(ioc_id=8)

        fake_links = [
            SimpleNamespace(case=SimpleNamespace(case_id=1, name="Real")),
            SimpleNamespace(case=None),  # orphaned link
        ]
        mock_ioc_link = MagicMock()
        mock_ioc_link.query.filter.return_value.all.return_value = fake_links

        mock_models = MagicMock()
        mock_models.IocLink = mock_ioc_link

        with patch.dict("sys.modules", {"app.models.models": mock_models}):
            result = iface._lookup_cases_for_ioc(ioc)

        assert len(result) == 1


# ── register_hooks ────────────────────────────────────────────────────────────


@patch("iris_opencti_module.IrisOpenCTIInterface.OpenCTIClient")
class TestRegisterHooks:

    def test_all_hooks_enabled_calls_register_four_times(self, MockClient):
        MockClient.return_value.health_check_detailed.return_value = {
            "ok": True, "reachable": True, "authenticated": True,
            "version": "6.0", "error": None,
        }

        iface = _make_interface({
            "opencti_url": "https://opencti.test",
            "opencti_api_key": "tok",
            "opencti_ssl_verify": True,
            "opencti_http_proxy": "",
            "opencti_https_proxy": "",
            "opencti_on_create_hook_enabled": True,
            "opencti_on_update_hook_enabled": True,
            "opencti_manual_hook_enabled": True,
            "opencti_on_delete_hook_enabled": True,
        })

        with patch.object(iface, "register_to_hook") as mock_reg, \
             patch.object(iface, "deregister_from_hook") as mock_dereg:
            iface.register_hooks(module_id=7)

        registered_hooks = [c.kwargs.get("iris_hook_name") or c.args[1]
                            for c in mock_reg.call_args_list]
        assert "on_postload_ioc_create" in registered_hooks
        assert "on_postload_ioc_update" in registered_hooks
        assert "on_manual_trigger_ioc" in registered_hooks
        assert "on_preload_ioc_delete" in registered_hooks
        # postload delete should always be deregistered (legacy cleanup)
        deregistered = [c.kwargs.get("iris_hook_name") or c.args[1]
                        for c in mock_dereg.call_args_list]
        assert "on_postload_ioc_delete" in deregistered

    def test_disabled_hook_calls_deregister(self, MockClient):
        MockClient.return_value.health_check_detailed.return_value = {
            "ok": True, "reachable": True, "authenticated": True,
            "version": "6.0", "error": None,
        }

        iface = _make_interface({
            "opencti_url": "https://opencti.test",
            "opencti_api_key": "tok",
            "opencti_ssl_verify": True,
            "opencti_http_proxy": "",
            "opencti_https_proxy": "",
            "opencti_on_create_hook_enabled": False,    # disabled
            "opencti_on_update_hook_enabled": True,
            "opencti_manual_hook_enabled": True,
            "opencti_on_delete_hook_enabled": False,     # disabled
        })

        with patch.object(iface, "register_to_hook") as mock_reg, \
             patch.object(iface, "deregister_from_hook") as mock_dereg:
            iface.register_hooks(module_id=7)

        deregistered = [c.kwargs.get("iris_hook_name") or c.args[1]
                        for c in mock_dereg.call_args_list]
        assert "on_postload_ioc_create" in deregistered
        assert "on_preload_ioc_delete" in deregistered
        assert "on_postload_ioc_delete" in deregistered  # legacy cleanup always fires

    def test_config_load_failure_exits_early(self, MockClient):
        iface = _make_interface()
        iface._config_success = False

        with patch.object(iface, "register_to_hook") as mock_reg:
            iface.register_hooks(module_id=7)

        mock_reg.assert_not_called()

    def test_manual_hook_registers_with_ui_name(self, MockClient):
        MockClient.return_value.health_check_detailed.return_value = {
            "ok": True, "reachable": True, "authenticated": True,
            "version": "6.0", "error": None,
        }

        iface = _make_interface({
            "opencti_url": "https://opencti.test",
            "opencti_api_key": "tok",
            "opencti_ssl_verify": True,
            "opencti_http_proxy": "",
            "opencti_https_proxy": "",
            "opencti_on_create_hook_enabled": True,
            "opencti_on_update_hook_enabled": True,
            "opencti_manual_hook_enabled": True,
            "opencti_on_delete_hook_enabled": False,
        })

        with patch.object(iface, "register_to_hook") as mock_reg, \
             patch.object(iface, "deregister_from_hook"):
            iface.register_hooks(module_id=7)

        manual_calls = [
            c for c in mock_reg.call_args_list
            if (c.kwargs.get("iris_hook_name") or (c.args[1] if len(c.args) > 1 else "")) == "on_manual_trigger_ioc"
        ]
        assert len(manual_calls) == 1
        manual_call = manual_calls[0]
        ui_name = manual_call.kwargs.get("manual_hook_name") or (
            manual_call.args[2] if len(manual_call.args) > 2 else None
        )
        assert ui_name == "Sync to OpenCTI"
