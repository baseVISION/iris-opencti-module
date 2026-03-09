"""
IrisOpenCTI module configuration.

Defines module metadata and the configuration schema exposed in the
IRIS UI under Manage → Modules → IrisOpenCTI.
"""

module_name = "IrisOpenCTI"
module_description = "Pushes IRIS IOCs to OpenCTI as observables and indicators, linked to Case Incidents"
interface_version = "1.2.0"
module_version = "1.0.2"

pipeline_support = False
pipeline_info = {}

module_configuration = [
    # ── Connection ──────────────────────────────────────────────
    {
        "param_name": "opencti_url",
        "param_human_name": "OpenCTI URL",
        "param_description": "Base URL of the OpenCTI platform (e.g. https://opencti.example.com)",
        "default": "",
        "mandatory": True,
        "type": "string",
        "section": "Connection",
    },
    {
        "param_name": "opencti_api_key",
        "param_human_name": "OpenCTI API Key",
        "param_description": "API token for authenticating with OpenCTI",
        "default": "",
        "mandatory": True,
        "type": "sensitive_string",
        "section": "Connection",
    },
    {
        "param_name": "opencti_ssl_verify",
        "param_human_name": "Verify SSL",
        "param_description": "Verify TLS certificates when connecting to OpenCTI",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Connection",
    },
    {
        "param_name": "opencti_http_proxy",
        "param_human_name": "HTTP Proxy",
        "param_description": "HTTP proxy URL (leave empty for direct connection)",
        "default": "",
        "mandatory": False,
        "type": "string",
        "section": "Connection",
    },
    {
        "param_name": "opencti_https_proxy",
        "param_human_name": "HTTPS Proxy",
        "param_description": "HTTPS proxy URL (leave empty for direct connection)",
        "default": "",
        "mandatory": False,
        "type": "string",
        "section": "Connection",
    },
    # ── Triggers ────────────────────────────────────────────────
    {
        "param_name": "opencti_on_create_hook_enabled",
        "param_human_name": "Push on IOC create",
        "param_description": "Automatically push new IOCs to OpenCTI when they are created",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Triggers",
    },
    {
        "param_name": "opencti_on_update_hook_enabled",
        "param_human_name": "Push on IOC update",
        "param_description": "Automatically re-push IOCs to OpenCTI when they are updated",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Triggers",
    },
    {
        "param_name": "opencti_manual_hook_enabled",
        "param_human_name": "Manual push button",
        "param_description": "Show a 'Sync to OpenCTI' button on IOCs for on-demand syncing",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Triggers",
    },
    {
        "param_name": "opencti_on_delete_hook_enabled",
        "param_human_name": "Delete on IOC removal",
        "param_description": "Delete the corresponding OpenCTI observable when an IOC is removed from IRIS",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Triggers",
    },
    # ── Behavior ────────────────────────────────────────────────
    {
        "param_name": "opencti_create_indicator",
        "param_human_name": "Create indicator",
        "param_description": "Also create an Indicator (detection pattern) alongside the Observable",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Behavior",
    },
    {
        "param_name": "opencti_create_case_incident",
        "param_human_name": "Create Case Incident",
        "param_description": "Create or link to an OpenCTI Case Incident (Incident Response) per IRIS case",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Behavior",
    },
    {
        "param_name": "opencti_default_tlp",
        "param_human_name": "Default TLP",
        "param_description": "Fallback TLP marking when no tlp:* tag is found on the IOC. "
                             "One of: clear, green, amber, amber+strict, red",
        "default": "amber",
        "mandatory": False,
        "type": "string",
        "section": "Behavior",
    },
    {
        "param_name": "opencti_author_name",
        "param_human_name": "Author organization",
        "param_description": "Organization name used as the 'Created by' identity in OpenCTI. "
                             "Leave empty to omit.",
        "default": "",
        "mandatory": False,
        "type": "string",
        "section": "Behavior",
    },
    {
        "param_name": "opencti_confidence",
        "param_human_name": "Default confidence",
        "param_description": "Default confidence level (0–100) for created observables and indicators",
        "default": 50,
        "mandatory": False,
        "type": "int",
        "section": "Behavior",
    },
    # ── Case Naming ─────────────────────────────────────────────
    {
        "param_name": "opencti_case_naming_mode",
        "param_human_name": "Case naming mode",
        "param_description": "How to name the OpenCTI Case Incident: "
                             "'case_name' = use IRIS case name, "
                             "'case_id' = use 'IRIS-Case-{id}', "
                             "'custom_prefix_id' = use '{prefix}-{id}', "
                             "'custom_attribute' = use a custom case attribute value",
        "default": "case_name",
        "mandatory": False,
        "type": "string",
        "section": "Case Naming",
    },
    {
        "param_name": "opencti_case_name_prefix",
        "param_human_name": "Case name prefix",
        "param_description": "Prefix for case names when using 'custom_prefix_id' mode (e.g. 'IR-2026')",
        "default": "IRIS-Case",
        "mandatory": False,
        "type": "string",
        "section": "Case Naming",
    },
    {
        "param_name": "opencti_case_custom_attribute",
        "param_human_name": "Custom attribute name",
        "param_description": "Name of the custom case attribute to use as the Case Incident name "
                             "when naming mode is 'custom_attribute' (e.g. 'CSIRT Case ID'). "
                             "The attribute is looked up in all sections of case custom_attributes.",
        "default": "",
        "mandatory": False,
        "type": "string",
        "section": "Case Naming",
    },
    {
        "param_name": "opencti_case_description_enabled",
        "param_human_name": "Include case description",
        "param_description": "Copy the IRIS case description to the OpenCTI Case Incident. "
                             "Disable to prevent leaking sensitive details.",
        "default": True,
        "mandatory": False,
        "type": "bool",
        "section": "Case Naming",
    },
]
