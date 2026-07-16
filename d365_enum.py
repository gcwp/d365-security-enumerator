#!/usr/bin/env python3
"""Small Dynamics 365 CE/Dataverse enumeration bootstrap.

The script authenticates through a real browser, reuses the resulting CRM cookies,
and quietly collects:

* WhoAmI identity information
* The organization server build from RetrieveVersion()
* The organization name and pentest-relevant organization settings
* The exact CRM URL supplied by the user
* Direct and team-inherited security roles
* Role privilege depths and privilege metadata with adaptive name resolution
* A complete privilege inventory, ordered by depth with role/team source attribution
* Custom entities plus a focused set of default entities, with endpoint URLs, held privilege matrices, and a lightweight read-access probe
* A masked secrets/configuration scan using attribute metadata, key/value store detection, structured JSON/XML inspection, and per-finding verification URLs

Setup:
    pip install requests playwright
    playwright install chromium

Usage:
    python d365_enum.py https://host/OrgName
    python d365_enum.py https://host/OrgName --output d365_enum.json
    python d365_enum.py https://host/OrgName --verify

Authorized testing only.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3


WHOAMI_FIELDS = ("UserId", "BusinessUnitId", "OrganizationId")
API_VERSION_CANDIDATES = ("v9.2", "v9.1", "v9.0")
ENTITY_PRIVILEGE_ORDER = ("Create", "Read", "Write", "Delete", "Assign", "Share", "Append", "AppendTo")
PROJECT_VERSION = "0.1.0"

SENSITIVE_STANDARD_ENTITY_LOGICAL_NAMES = (
    "organization",
    "pluginassembly",
    "plugintype",
    "sdkmessageprocessingstep",
    "sdkmessageprocessingstepimage",
    "workflow",
    "webresource",
    "plugintracelog",
    "emailserverprofile",
    "mailbox",
    "serviceendpoint",
    "sharepointsite",
    "sharepointdocumentlocation",
    "audit",
    "fieldsecurityprofile",
    "fieldpermission",
    "principalobjectattributeaccess",
    "principalobjectaccess",
    "role",
    "team",
    "businessunit",
    "systemuser",
    "teamtemplate",
)

# Fields are grouped by why they matter during a pentest. The organization
# response is filtered locally so the script remains compatible with different
# Dynamics 365 9.1 patch levels and custom deployments.
ORGANIZATION_FIELD_GROUPS: dict[str, set[str]] = {
    "identity": {
        "organizationid",
        "name",
        "uniquename",
        "friendlyname",
        "urlname",
        "statecode",
        "statuscode",
        "initialversion",
        "isdisabled",
        "disabledreason",
        "organizationtype",
        "organizationstate",
        "languagecode",
        "localeid",
        "createdon",
        "modifiedon",
        "versionnumber",
        "orgdborgsettings",
    },
    "auditing": {
        "isauditenabled",
        "isuseraccessauditenabled",
        "isreadauditenabled",
        "allowentityonlyaudit",
        "useraccessauditinginterval",
        "auditretentionperiod",
        "auditretentionperiodv2",
        "auditsettings",
    },
    "access_model": {
        "ishierarchicalsecuritymodelenabled",
        "maxdepthforhierarchicalsecuritymodel",
        "usepositionhierarchy",
        "isdelegateaccessenabled",
        "issharinginorgallowed",
        "allowapplicationuseraccess",
        "applicationbasedaccesscontrolmode",
        "restrictguestuseraccess",
        "allowedapplicationsfordvaccess",
        "blockedapplicationsfordvaccess",
    },
    "network_and_application_access": {
        "enableipbasedfirewallrule",
        "enableipbasedfirewallruleinauditmode",
        "enableipbasedcookiebinding",
        "allowediprangeforfirewall",
        "allowedlistofiprangesforfirewall",
        "allowmicrosofttrustedservicetags",
        "allowedservicetagsforfirewall",
        "allowediprangeforstorageaccesssignatures",
        "reverseproxyipaddresses",
        "grantaccesstonetworkservice",
    },
    "data_exposure": {
        "allowwebexcelexport",
        "maxrecordsforexporttoexcel",
        "isfulltextsearchenabled",
        "isexternalsearchindexenabled",
        "ismobileofflineenabled",
        "allowofflinescheduledsyncs",
        "allowoutlookscheduledsyncs",
        "isfolderbasedtrackingenabled",
        "isfolderautocreatedonsp",
        "isonedriveenabled",
        "isexternalfilestorageenabled",
        "allowunresolvedpartiesonemailsend",
    },
    "attachments_and_uploads": {
        "blockedattachments",
        "blockedmimetypes",
        "allowedmimetypes",
        "maxuploadfilesize",
        "isrichtextnotesenabled",
    },
    "browser_and_content": {
        "iscontentsecuritypolicyenabled",
        "iscontentsecuritypolicyenabledforcanvas",
        "contentsecuritypolicyconfiguration",
        "contentsecuritypolicyconfigurationforcanvas",
        "contentsecuritypolicyoptions",
        "contentsecuritypolicyreporturi",
        "samesitemodeforsessioncookie",
        "rendersecureiframeforemail",
        "postmessagewhitelistdomains",
        "allowlegacyclientexperience",
        "allowlegacydialogsembedding",
    },
    "email_and_sync": {
        "requireapprovalforuseremail",
        "requireapprovalforqueueemail",
        "isemailmonitoringallowed",
        "isemailserverprofilecontentfilteringenabled",
        "allowautoresponsecreation",
        "allowautounsubscribe",
        "allowautounsubscribeacknowledgement",
        "generatealertsforerrors",
        "generatealertsforwarnings",
        "generatealertsforinformation",
        "isfolderbasedtrackingenabled",
        "allowoutlookscheduledsyncs",
        "allowofflinescheduledsyncs",
    },
    "diagnostics_and_plugins": {
        "plugintracelogsetting",
        "tracelogmaximumageindays",
        "enforcereadonlyplugins",
        "reportscripterrors",
        "enableplugintracelog",
        "ispluginprofilerenabled",
    },
    "sessions_and_tokens": {
        "tokenexpiry",
        "sessiontimeoutenabled",
        "sessiontimeoutinmins",
        "sessiontimeoutreminderinmins",
        "inactivitytimeoutenabled",
        "inactivitytimeoutinmins",
        "inactivitytimeoutreminderinmins",
    },
    "integrations": {
        "issopintegrationenabled",
        "ismsteamsenabled",
        "ismsteamscollaborationenabled",
        "powerbifeatureenabled",
        "powerbiallowcrossregionoperations",
        "microsoftflowenvironment",
        "bingmapsapikey",
        "azureschedulerjobcollectionname",
        "isexternalsearchindexenabled",
        "isexternalfilestorageenabled",
        "isonedriveenabled",
        "isfolderautocreatedonsp",
    },
    "enumeration_references": {
        "_basecurrencyid_value",
        "_businessclosurecalendarid_value",
        "_defaultemailserverprofileid_value",
        "_defaultmobileofflineprofileid_value",
        "_integrationuserid_value",
        "_supportuserid_value",
        "_systemuserid_value",
        "integrationuserid",
        "supportuserid",
        "systemuserid",
        "privilegeusergroupid",
        "privilegeusergroupname",
        "sqlaccessgroupid",
        "sqlaccessgroupname",
        "reportinggroupid",
        "reportinggroupname",
    },
}

# Catch deployment-specific or newly introduced properties that are not yet in
# the curated list but are clearly interesting for security review.
RELEVANT_NAME_FRAGMENTS = (
    "audit",
    "security",
    "contentsecurity",
    "attachment",
    "upload",
    "mimetype",
    "token",
    "session",
    "timeout",
    "plugin",
    "trace",
    "iframe",
    "whitelist",
    "allowlist",
    "blocklist",
    "blocked",
    "firewall",
    "iprange",
    "oauth",
    "certificate",
    "integration",
    "externalstorage",
    "externalfile",
    "externalsearch",
    "mobileoffline",
    "sharepoint",
    "onedrive",
    "emailserverprofile",
    "delegateaccess",
    "hierarchical",
    "positionhierarchy",
    "unresolvedparties",
    "exporttoexcel",
    "webexcelexport",
    "readonlyplugin",
    "postmessage",
    "orgdborgsettings",
    "legacyclient",
    "guestuser",
    "cookiebinding",
    "reverseproxy",
    "networkservice",
)

PLUGIN_TRACE_LABELS = {0: "off", 1: "exception", 2: "all"}
REPORT_SCRIPT_ERROR_LABELS = {
    0: "no_preference",
    1: "ask_before_sending",
    2: "send_automatically",
    3: "never_send",
}


APPLICATION_ACCESS_MODE_LABELS = {
    0: "disabled",
    1: "enabled",
    2: "audit_mode",
    3: "enabled_for_roles",
}
SAMESITE_MODE_LABELS = {0: "default", 1: "none", 2: "lax", 3: "strict"}

# These are expected security-review inputs. If neither a first-class
# organization column nor an OrgDbOrgSettings element is readable, the check is
# explicitly reported as not evaluated rather than silently treated as safe.
EXPECTED_ORGANIZATION_SECURITY_SETTINGS: dict[str, tuple[str, ...]] = {
    "organization_auditing": ("isauditenabled",),
    "user_access_auditing": ("isuseraccessauditenabled",),
    "content_security_policy": ("iscontentsecuritypolicyenabled",),
    "content_security_policy_report_uri": ("contentsecuritypolicyreporturi",),
    "postmessage_whitelist": ("postmessagewhitelistdomains",),
    "secure_email_iframe": ("rendersecureiframeforemail",),
    "read_only_plugins": ("enforcereadonlyplugins",),
    "plugin_trace": ("plugintracelogsetting",),
    "attachment_extension_blocklist": ("blockedattachments",),
    "attachment_mime_blocklist": ("blockedmimetypes",),
    "maximum_upload_size": ("maxuploadfilesize",),
    "session_timeout_enabled": ("sessiontimeoutenabled",),
    "session_timeout_minutes": ("sessiontimeoutinmins", "sessiontimeoutinminutes"),
    "inactivity_timeout_enabled": ("inactivitytimeoutenabled",),
    "inactivity_timeout_minutes": ("inactivitytimeoutinmins", "inactivitytimeoutinminutes"),
    "session_cookie_samesite": ("samesitemodeforsessioncookie",),
    "token_expiry": ("tokenexpiry",),
    "application_access_control": ("applicationbasedaccesscontrolmode",),
    "allow_all_application_users": ("allowapplicationuseraccess",),
    "in_organization_sharing": ("issharinginorgallowed",),
    "guest_user_restriction": ("restrictguestuseraccess",),
    "ip_firewall": ("enableipbasedfirewallrule",),
    "ip_firewall_ranges": ("allowediprangeforfirewall", "allowedlistofiprangesforfirewall"),
    "ip_cookie_binding": ("enableipbasedcookiebinding",),
    "network_service_access": ("grantaccesstonetworkservice",),
    "reverse_proxy_trust": ("reverseproxyipaddresses",),
    "user_email_approval": ("requireapprovalforuseremail",),
    "queue_email_approval": ("requireapprovalforqueueemail",),
    "legacy_web_client": ("allowlegacyclientexperience",),
}


def xml_element_to_value(element: ET.Element) -> Any:
    """Convert an XML element into JSON-serializable nested data."""
    children = list(element)
    text = (element.text or "").strip()
    if not children:
        if element.attrib:
            result: dict[str, Any] = {"@attributes": dict(element.attrib)}
            if text:
                result["#text"] = text
            return result
        return text

    result: dict[str, Any] = {}
    if element.attrib:
        result["@attributes"] = dict(element.attrib)
    for child in children:
        value = xml_element_to_value(child)
        tag = child.tag.split("}")[-1]
        if tag in result:
            if not isinstance(result[tag], list):
                result[tag] = [result[tag]]
            result[tag].append(value)
        else:
            result[tag] = value
    if text:
        result["#text"] = text
    return result


def flatten_nested_settings(value: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten parsed OrgDbOrgSettings while retaining duplicate values."""
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "@attributes":
                for attr, attr_value in child.items():
                    flat_key = f"{prefix}.@{attr}" if prefix else f"@{attr}"
                    flattened[flat_key] = attr_value
                continue
            child_prefix = f"{prefix}.{key}" if prefix else key
            flattened.update(flatten_nested_settings(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            flattened.update(flatten_nested_settings(child, f"{prefix}[{index}]"))
    else:
        flattened[prefix] = value
    return flattened


def parse_orgdborgsettings(raw_value: Any) -> dict[str, Any]:
    """Parse the XML stored in Organization.OrgDbOrgSettings safely."""
    if not isinstance(raw_value, str) or not raw_value.strip():
        return {
            "status": "empty",
            "raw_length": len(raw_value) if isinstance(raw_value, str) else 0,
            "setting_count": 0,
            "settings": {},
            "flat_settings": {},
        }

    raw = raw_value.strip()
    decoded = html.unescape(raw)
    candidates = [decoded, f"<OrgDbOrgSettingsRoot>{decoded}</OrgDbOrgSettingsRoot>"]
    parse_error: str | None = None
    root: ET.Element | None = None
    for candidate in candidates:
        try:
            root = ET.fromstring(candidate)
            break
        except ET.ParseError as exc:
            parse_error = str(exc)

    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    if root is None:
        return {
            "status": "parse_error",
            "raw_length": len(raw),
            "sha256": digest,
            "error": parse_error or "Unknown XML parse error",
            "setting_count": 0,
            "settings": {},
            "flat_settings": {},
        }

    root_name = root.tag.split("}")[-1]
    parsed = {root_name: xml_element_to_value(root)}
    flat = flatten_nested_settings(parsed)

    return {
        "status": "success",
        "raw_length": len(raw),
        "sha256": digest,
        "root": root_name,
        "setting_count": len(flat),
        "settings": parsed,
        "flat_settings": flat,
    }


def build_orgdb_leaf_index(flat_settings: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Index XML values by final element name for case-insensitive lookup."""
    index: dict[str, list[dict[str, Any]]] = {}
    for path, value in flat_settings.items():
        leaf = re.sub(r"\[\d+\]$", "", path.split(".")[-1]).lstrip("@").lower()
        index.setdefault(leaf, []).append({"path": path, "value": value})
    return index


def lookup_organization_setting(
    record: dict[str, Any],
    orgdb_leaf_index: dict[str, list[dict[str, Any]]],
    *names: str,
) -> dict[str, Any] | None:
    """Resolve a setting from a first-class column or the OrgDb XML blob."""
    direct = {key.lower(): key for key in record if not key.startswith("@odata.")}
    for name in names:
        actual = direct.get(name.lower())
        if actual is not None:
            return {"name": actual, "value": record[actual], "source": "organization_column"}
    for name in names:
        matches = orgdb_leaf_index.get(name.lower(), [])
        if matches:
            first = matches[0]
            return {
                "name": name,
                "value": first.get("value"),
                "source": "orgdborgsettings",
                "path": first.get("path"),
                "all_matches": matches,
            }
    return None


def coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "enabled", "on"}:
            return True
        if lowered in {"false", "0", "no", "disabled", "off"}:
            return False
    return None


def coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def capture_browser_session(login_url: str, verify_tls: bool) -> list[dict[str, Any]]:
    """Authenticate in Chromium and return the resulting CRM cookies."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit(
            "Playwright is not installed. Run:\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        )

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=False)
            context = browser.new_context(ignore_https_errors=not verify_tls)
            page = context.new_page()
            page.goto(login_url, wait_until="domcontentloaded")
            input("Log in to CRM in the opened browser, then press Enter here. ")
            cookies = context.cookies()
            browser.close()
            return cookies
    except PlaywrightError as exc:
        sys.exit(f"Browser login failed: {exc}")


def build_session(cookies: list[dict[str, Any]]) -> requests.Session:
    """Create a requests session using browser-authenticated cookies."""
    session = requests.Session()

    for cookie in cookies:
        session.cookies.set(
            cookie["name"],
            cookie["value"],
            domain=(cookie.get("domain") or "").lstrip("."),
            path=cookie.get("path", "/"),
        )

    session.headers.update(
        {
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
        }
    )
    return session


def compact_error(response: requests.Response) -> str:
    """Return a short error without disclosing full requests or response bodies."""
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"

    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, dict):
            message = message.get("value")
        if isinstance(message, str) and message.strip():
            return f"HTTP {response.status_code}: {message.strip()[:240]}"

    return f"HTTP {response.status_code}"


def get_json(
    session: requests.Session,
    url: str,
    verify_tls: bool,
    *,
    timeout: int = 30,
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """Perform a quiet GET and return JSON, a compact error, and HTTP status."""
    try:
        response = session.get(url, verify=verify_tls, timeout=timeout)
    except requests.exceptions.SSLError as exc:
        return None, f"TLS error: {exc}", None
    except requests.exceptions.RequestException as exc:
        return None, f"Request failed: {exc}", None

    if not response.ok:
        return None, compact_error(response), response.status_code

    try:
        payload = response.json()
    except ValueError:
        return None, "Response was not valid JSON", response.status_code

    if not isinstance(payload, dict):
        return None, "Response JSON was not an object", response.status_code

    return payload, None, response.status_code


def query_whoami(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
) -> dict[str, str]:
    """Return the three identity identifiers required by later modules."""
    payload, error, _ = get_json(session, f"{api_base}/WhoAmI", verify_tls)
    if error or payload is None:
        sys.exit(
            f"WhoAmI failed: {error or 'unknown error'}. "
            "Check authentication, the organization URL, and API version."
        )

    missing = [field for field in WHOAMI_FIELDS if not payload.get(field)]
    if missing:
        sys.exit(f"WhoAmI response is missing: {', '.join(missing)}")

    return {field: str(payload[field]) for field in WHOAMI_FIELDS}


def normalize_api_version(value: str) -> str:
    """Normalize API version input to the vX.Y path format."""
    normalized = value.strip().lower()
    if normalized == "auto":
        return "auto"
    if not normalized.startswith("v"):
        normalized = f"v{normalized}"
    if not re.fullmatch(r"v\d+\.\d+", normalized):
        raise ValueError(f"Invalid API version: {value!r}")
    return normalized


def detect_api_endpoint(
    session: requests.Session,
    base_url: str,
    verify_tls: bool,
    requested_version: str,
) -> dict[str, Any]:
    """Select a working Organization Web API version and return WhoAmI data."""
    try:
        normalized = normalize_api_version(requested_version)
    except ValueError as exc:
        sys.exit(str(exc))

    candidates = list(API_VERSION_CANDIDATES) if normalized == "auto" else [normalized]
    attempts: list[dict[str, Any]] = []

    for version in candidates:
        api_base = f"{base_url}/api/data/{version}"
        payload, error, http_status = get_json(
            session,
            f"{api_base}/WhoAmI",
            verify_tls,
        )
        missing = (
            [field for field in WHOAMI_FIELDS if not payload.get(field)]
            if isinstance(payload, dict)
            else list(WHOAMI_FIELDS)
        )
        if payload is not None and not error and not missing:
            return {
                "status": "success",
                "api_version": version,
                "api_base": api_base,
                "identity": {field: str(payload[field]) for field in WHOAMI_FIELDS},
                "attempts": attempts + [{"api_version": version, "http_status": http_status, "status": "success"}],
            }
        attempts.append(
            {
                "api_version": version,
                "http_status": http_status,
                "status": "error",
                "error": error or (f"WhoAmI response missing: {', '.join(missing)}" if missing else "Unknown error"),
            }
        )

    detail = "; ".join(
        f"{item['api_version']}: {item.get('error') or item.get('http_status') or 'failed'}"
        for item in attempts
    )
    sys.exit(
        "Could not find a working Dynamics Web API endpoint. "
        f"Tried {', '.join(candidates)}. {detail}"
    )


def query_version(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
) -> dict[str, Any]:
    """Query the exact server build reported by the organization endpoint."""
    payload, error, http_status = get_json(
        session,
        f"{api_base}/RetrieveVersion()",
        verify_tls,
    )
    if error or payload is None:
        return {
            "status": "error",
            "http_status": http_status,
            "error": error or "Unknown error",
            "version": None,
        }

    version = payload.get("Version")
    return {
        "status": "success" if version else "unexpected_response",
        "http_status": http_status,
        "version": version,
    }


def normalize_guid(value: Any) -> str:
    """Normalize Dynamics GUIDs for reliable identifier comparison."""
    return str(value or "").strip().strip("{}").lower()


def is_relevant_organization_field(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith("@odata."):
        return False
    if any(lowered in fields for fields in ORGANIZATION_FIELD_GROUPS.values()):
        return True
    return any(fragment in lowered for fragment in RELEVANT_NAME_FRAGMENTS)


def classify_organization_fields(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Group readable organization properties by pentest use case."""
    grouped: dict[str, dict[str, Any]] = {
        group: {} for group in ORGANIZATION_FIELD_GROUPS
    }
    grouped["additional_relevant"] = {}

    assigned: set[str] = set()
    lower_to_actual = {key.lower(): key for key in record if not key.startswith("@odata.")}

    for group, wanted_fields in ORGANIZATION_FIELD_GROUPS.items():
        for wanted in sorted(wanted_fields):
            actual = lower_to_actual.get(wanted)
            if actual is None:
                continue
            grouped[group][actual] = record[actual]
            assigned.add(actual)

    for key, value in record.items():
        if key in assigned or key.startswith("@odata."):
            continue
        if is_relevant_organization_field(key):
            grouped["additional_relevant"][key] = value

    return {group: values for group, values in grouped.items() if values}


def first_present(record: dict[str, Any], *names: str) -> tuple[str | None, Any]:
    lower_to_actual = {key.lower(): key for key in record}
    for name in names:
        actual = lower_to_actual.get(name.lower())
        if actual is not None:
            return actual, record[actual]
    return None, None


def build_security_signals(
    record: dict[str, Any],
    orgdb_leaf_index: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create explicit review signals and a visible list of unevaluated checks."""
    signals: list[dict[str, Any]] = []

    def add(
        signal_id: str,
        title: str,
        category: str,
        setting: dict[str, Any],
        rationale: str,
        severity: str = "review",
    ) -> None:
        signals.append(
            {
                "id": signal_id,
                "title": title,
                "severity": severity,
                "category": category,
                "field": setting.get("name"),
                "value": setting.get("value"),
                "source": setting.get("source"),
                "source_path": setting.get("path"),
                "rationale": rationale,
            }
        )

    resolved_checks: dict[str, dict[str, Any] | None] = {
        check_id: lookup_organization_setting(record, orgdb_leaf_index, *aliases)
        for check_id, aliases in EXPECTED_ORGANIZATION_SECURITY_SETTINGS.items()
    }

    boolean_checks = (
        ("organization_auditing", False, "organization_auditing_disabled", "Organization auditing is disabled", "configuration_review", "Record changes may not be captured by the platform audit subsystem."),
        ("user_access_auditing", False, "user_access_auditing_disabled", "User-access auditing is disabled", "configuration_review", "User access events may not be captured by organization auditing."),
        ("content_security_policy", False, "organization_csp_disabled", "Organization CSP setting is disabled", "browser_security", "Confirm the effective CSP on CRM HTML pages; API responses alone are not sufficient."),
        ("secure_email_iframe", False, "email_secure_iframe_disabled", "Restricted email-body iframe is disabled", "browser_security", "HTML email rendering should be reviewed for active-content exposure."),
        ("read_only_plugins", False, "readonly_plugins_not_enforced", "Read-only plug-ins are not enforced", "plugin_security", "Plug-ins registered for read-only behavior are not being constrained by this organization control."),
        ("session_timeout_enabled", False, "session_timeout_disabled", "Session timeout is disabled", "session_security", "Long-lived authenticated browser sessions may increase exposure after compromise."),
        ("inactivity_timeout_enabled", False, "inactivity_timeout_disabled", "Inactivity timeout is disabled", "session_security", "Idle authenticated sessions may remain usable longer than expected."),
        ("allow_all_application_users", True, "all_application_users_allowed", "All application users are allowed access", "application_access", "Application-user access is not restricted by the organization-wide application access control."),
        ("in_organization_sharing", True, "in_org_sharing_enabled", "In-organization record sharing is enabled", "access_model", "Record sharing expands effective access beyond role privileges and must be included in record-level testing.", "informational"),
        ("guest_user_restriction", False, "guest_user_access_not_restricted", "Guest-user access is not restricted", "application_access", "Guest identities may have a broader attack surface than intended; validate deployment-specific behavior."),
        ("ip_firewall", False, "ip_firewall_disabled", "IP-based firewall rules are disabled", "network_access", "No organization-level IP range enforcement was observed; confirm whether perimeter controls provide the intended restriction.", "informational"),
        ("ip_cookie_binding", False, "ip_cookie_binding_disabled", "IP-based session-cookie binding is disabled", "session_security", "Stolen session cookies are not bound to the originating client IP by this organization control.", "informational"),
        ("network_service_access", True, "network_service_access_granted", "Network Service access is granted", "service_identity", "Review why the platform Network Service identity requires access and what resources inherit that trust."),
        ("user_email_approval", False, "user_email_approval_not_required", "User email addresses do not require approval", "email_security", "Unapproved user email addresses may be activated for server-side email processing."),
        ("queue_email_approval", False, "queue_email_approval_not_required", "Queue email addresses do not require approval", "email_security", "Unapproved queue email addresses may be activated for server-side email processing."),
        ("legacy_web_client", True, "legacy_web_client_enabled", "Legacy web client experience is enabled", "attack_surface", "The legacy client remains reachable and should be included in application attack-surface testing."),
    )

    for item in boolean_checks:
        check_id, expected, signal_id, title, category, rationale, *severity = item
        setting = resolved_checks.get(check_id)
        if setting is not None and coerce_bool(setting.get("value")) is expected:
            add(signal_id, title, category, setting, rationale, severity[0] if severity else "review")

    # Existing exposure-oriented columns not part of the required expected list.
    for aliases, expected, signal_id, title, category, rationale in (
        (("allowunresolvedpartiesonemailsend",), True, "unresolved_email_recipients_allowed", "Unresolved email recipients are allowed", "attack_surface", "Review whether users can send CRM email to arbitrary external addresses."),
        (("allowwebexcelexport",), True, "excel_export_enabled", "Export to Excel is enabled", "data_exposure", "Effective privileges should be reviewed for broad exportable data access."),
        (("ishierarchicalsecuritymodelenabled",), True, "hierarchy_security_enabled", "Hierarchy security is enabled", "access_model", "Hierarchy-derived record access must be included in effective-access analysis."),
    ):
        setting = lookup_organization_setting(record, orgdb_leaf_index, *aliases)
        if setting is not None and coerce_bool(setting.get("value")) is expected:
            add(signal_id, title, category, setting, rationale, "informational")

    trace_setting = resolved_checks.get("plugin_trace")
    if trace_setting is not None:
        trace_value = coerce_int(trace_setting.get("value"))
        label = PLUGIN_TRACE_LABELS.get(trace_value, "unknown")
        if trace_value in (1, 2):
            add("plugin_trace_enabled", f"Plug-in tracing is enabled ({label})", "information_exposure", trace_setting, "Accessible plug-in trace logs can disclose internal code paths and sensitive values.")

    blocked_setting = resolved_checks.get("attachment_extension_blocklist")
    if blocked_setting is not None and not str(blocked_setting.get("value") or "").strip():
        add("attachment_extension_blocklist_empty", "Attachment extension block list is empty", "upload_security", blocked_setting, "Validate effective upload controls and server-side content handling.")

    app_mode = resolved_checks.get("application_access_control")
    if app_mode is not None:
        value = coerce_int(app_mode.get("value"))
        if value == 0:
            add("application_access_control_disabled", "Application-based access control is disabled", "application_access", app_mode, "Application access restrictions are not enforced by this organization setting.", "informational")

    firewall = resolved_checks.get("ip_firewall")
    ranges = resolved_checks.get("ip_firewall_ranges")
    if firewall is not None and coerce_bool(firewall.get("value")) is True:
        if ranges is not None and not str(ranges.get("value") or "").strip():
            add("ip_firewall_enabled_without_ranges", "IP firewall is enabled without a readable allowed range", "network_access", ranges, "Confirm that the firewall is not effectively configured with an empty or malformed allow list.")

    samesite = resolved_checks.get("session_cookie_samesite")
    if samesite is not None:
        mode = coerce_int(samesite.get("value"))
        if mode == 1 or str(samesite.get("value")).strip().lower() == "none":
            add("session_cookie_samesite_none", "Session cookie SameSite mode is None", "session_security", samesite, "Cross-site cookie sending is permitted; validate Secure cookie enforcement and cross-origin authentication flows.")

    token_expiry = resolved_checks.get("token_expiry")
    if token_expiry is not None:
        token_value = coerce_int(token_expiry.get("value"))
        if token_value is not None and token_value <= 0:
            add("token_expiry_non_positive", "Token expiry is non-positive", "session_security", token_expiry, "Validate whether authentication tokens can remain valid indefinitely or use an unexpected expiry configuration.")

    whitelist = resolved_checks.get("postmessage_whitelist")
    if whitelist is not None:
        whitelist_text = str(whitelist.get("value") or "")
        tokens = [token.strip() for token in re.split(r"[;,\s]+", whitelist_text) if token.strip()]
        if "*" in tokens or whitelist_text.strip() == "*":
            add("postmessage_whitelist_wildcard", "postMessage whitelist contains a wildcard", "browser_security", whitelist, "A wildcard postMessage trust list can permit messages from arbitrary origins.", "high")

    csp_enabled = resolved_checks.get("content_security_policy")
    csp_report = resolved_checks.get("content_security_policy_report_uri")
    if csp_enabled is not None and coerce_bool(csp_enabled.get("value")) is True:
        if csp_report is not None and not str(csp_report.get("value") or "").strip():
            add("csp_report_uri_empty", "CSP is enabled without a report URI", "browser_security", csp_report, "This is not a bypass by itself, but CSP violations may not be centrally observable.", "informational")

    reverse_proxy = resolved_checks.get("reverse_proxy_trust")
    if reverse_proxy is not None and str(reverse_proxy.get("value") or "").strip():
        add("reverse_proxy_trust_configured", "Reverse-proxy IP trust is configured", "network_access", reverse_proxy, "Treat the configured reverse proxies as a trust boundary and test forwarded-header handling.", "informational")

    checks_not_evaluated = [
        {
            "check": check_id,
            "expected_settings": list(EXPECTED_ORGANIZATION_SECURITY_SETTINGS[check_id]),
            "reason": "No matching readable organization column or OrgDbOrgSettings element was found.",
        }
        for check_id, setting in resolved_checks.items()
        if setting is None
    ]
    return signals, checks_not_evaluated


def query_organization(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    organization_id: str,
) -> dict[str, Any]:
    """Retrieve organization-wide settings and retain security-relevant values."""
    payload, error, http_status = get_json(
        session,
        f"{api_base}/organizations",
        verify_tls,
        timeout=45,
    )
    if error or payload is None:
        return {
            "status": "error",
            "http_status": http_status,
            "error": error or "Unknown error",
        }

    values = payload.get("value", [])
    if not isinstance(values, list):
        return {
            "status": "unexpected_response",
            "http_status": http_status,
            "error": "Organization response did not contain a record list",
        }

    records = [item for item in values if isinstance(item, dict)]
    expected_id = normalize_guid(organization_id)
    selected: dict[str, Any] | None = None

    for record in records:
        candidate = record.get("organizationid") or record.get("OrganizationId")
        if normalize_guid(candidate) == expected_id:
            selected = record
            break

    if selected is None and len(records) == 1:
        selected = records[0]

    if selected is None:
        return {
            "status": "not_found",
            "http_status": http_status,
            "organization_count": len(records),
            "error": "No organization record matched the WhoAmI OrganizationId",
        }

    orgdb_field, orgdb_raw = first_present(selected, "orgdborgsettings")
    orgdb_parsed = parse_orgdborgsettings(orgdb_raw)
    orgdb_leaf_index = build_orgdb_leaf_index(orgdb_parsed.get("flat_settings", {}))
    grouped = classify_organization_fields(selected)
    # Avoid duplicating a potentially huge raw XML blob in the generic settings.
    for group_values in grouped.values():
        group_values.pop(orgdb_field, None) if orgdb_field else None
    flat_relevant = {
        key: value
        for key, value in selected.items()
        if is_relevant_organization_field(key) and key != orgdb_field
    }

    normalized: dict[str, Any] = {}
    trace_field, trace_value = first_present(selected, "plugintracelogsetting")
    if trace_field is not None:
        normalized["plugintracelogsetting_label"] = PLUGIN_TRACE_LABELS.get(
            trace_value,
            "unknown",
        )

    app_access = lookup_organization_setting(selected, orgdb_leaf_index, "applicationbasedaccesscontrolmode")
    if app_access is not None:
        app_value = coerce_int(app_access.get("value"))
        normalized["applicationbasedaccesscontrolmode_label"] = APPLICATION_ACCESS_MODE_LABELS.get(app_value, "unknown")

    samesite = lookup_organization_setting(selected, orgdb_leaf_index, "samesitemodeforsessioncookie")
    if samesite is not None:
        same_value = coerce_int(samesite.get("value"))
        normalized["samesitemodeforsessioncookie_label"] = SAMESITE_MODE_LABELS.get(same_value, "unknown")

    report_field, report_value = first_present(selected, "reportscripterrors")
    if report_field is not None:
        normalized["reportscripterrors_label"] = REPORT_SCRIPT_ERROR_LABELS.get(
            report_value,
            "unknown",
        )

    security_signals, checks_not_evaluated = build_security_signals(selected, orgdb_leaf_index)

    return {
        "status": "success",
        "http_status": http_status,
        "organization_count": len(records),
        "name": selected.get("name"),
        "selected_organization_id": selected.get("organizationid")
        or selected.get("OrganizationId")
        or organization_id,
        "readable_field_count": len(
            [key for key in selected if not key.startswith("@odata.")]
        ),
        "relevant_field_count": len(flat_relevant),
        "available_field_names": sorted(
            key for key in selected if not key.startswith("@odata.")
        ),
        "settings": grouped,
        "flat_relevant_settings": flat_relevant,
        "normalized_values": normalized,
        "orgdborgsettings": orgdb_parsed,
        "security_signals": security_signals,
        "checks_not_evaluated": checks_not_evaluated,
    }



ROLE_SELECT = (
    "roleid,name,_businessunitid_value,"
    "_parentrootroleid_value,_roletemplateid_value"
)
TEAM_SELECT = (
    "teamid,name,teamtype,_businessunitid_value,isdefault,systemmanaged"
)
PRIVILEGE_SELECT = (
    "privilegeid,name,accessright,canbebasic,canbelocal,canbedeep,canbeglobal"
)
DEPTH_RANK = {"None": 0, "Basic": 1, "Local": 2, "Deep": 3, "Global": 4}

CUSTOM_ENTITY_FIELDS = (
    "MetadataId,LogicalName,SchemaName,EntitySetName,IsCustomEntity,"
    "PrimaryIdAttribute,PrimaryNameAttribute,ObjectTypeCode,OwnershipType,"
    "IsActivity,IsBPFEntity,IsIntersect,IsAuditEnabled,AutoCreateAccessTeams,"
    "DataProviderId,DataSourceId,Privileges"
)
CUSTOM_ENTITY_FALLBACK_FIELDS = (
    "MetadataId,LogicalName,SchemaName,EntitySetName,IsCustomEntity,"
    "PrimaryIdAttribute,PrimaryNameAttribute,ObjectTypeCode,OwnershipType,"
    "IsActivity,IsIntersect,IsAuditEnabled,Privileges"
)
CUSTOM_ENTITY_MINIMAL_FIELDS = (
    "MetadataId,LogicalName,SchemaName,EntitySetName,"
    "PrimaryIdAttribute,PrimaryNameAttribute,ObjectTypeCode,OwnershipType,"
    "IsCustomEntity"
)
PRIVILEGE_TYPE_LABELS = {
    0: "None",
    1: "Create",
    2: "Read",
    3: "Write",
    4: "Delete",
    5: "Assign",
    6: "Share",
    7: "Append",
    8: "AppendTo",
}
ENTITY_PROBE_ORDER = (
    "READABLE_WITH_DATA",
    "READABLE_EMPTY_OR_FILTERED",
    "ACCESS_DENIED",
    "AUTHENTICATION_FAILED",
    "NOT_ADDRESSABLE",
    "INVALID_OR_UNSUPPORTED",
    "RATE_LIMITED",
    "BACKEND_ERROR",
    "NON_JSON_RESPONSE",
    "REQUEST_ERROR",
    "NOT_PROBED",
)


def normalize_privilege_metadata(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize privilege entity metadata returned by any compatible endpoint."""
    return {
        "privilege_id": normalize_guid(record.get("privilegeid")),
        "name": record.get("name"),
        "access_right": record.get("accessright"),
        "entity_targets": record.get("entity_targets", []),
        "privilege_type": record.get("privilege_type"),
        "supported_depths": {
            "basic": record.get("canbebasic"),
            "local": record.get("canbelocal"),
            "deep": record.get("canbedeep"),
            "global": record.get("canbeglobal"),
        },
    }


def get_case_insensitive(record: dict[str, Any], *names: str) -> Any:
    """Return the first matching key without relying on response casing."""
    lowered = {key.lower(): value for key, value in record.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def query_collection(
    session: requests.Session,
    url: str,
    verify_tls: bool,
    *,
    timeout: int = 45,
) -> dict[str, Any]:
    """Retrieve an OData collection and follow every @odata.nextLink."""
    records: list[dict[str, Any]] = []
    pages = 0
    next_url: str | None = url

    while next_url:
        payload, error, http_status = get_json(
            session,
            next_url,
            verify_tls,
            timeout=timeout,
        )
        if error or payload is None:
            return {
                "status": "error",
                "http_status": http_status,
                "error": error or "Unknown error",
                "records": records,
                "record_count": len(records),
                "page_count": pages,
            }

        values = payload.get("value")
        if not isinstance(values, list):
            return {
                "status": "unexpected_response",
                "http_status": http_status,
                "error": "Response did not contain an OData value array",
                "records": records,
                "record_count": len(records),
                "page_count": pages,
            }

        records.extend(item for item in values if isinstance(item, dict))
        pages += 1

        raw_next = payload.get("@odata.nextLink")
        if isinstance(raw_next, str) and raw_next.strip():
            next_url = urljoin(next_url, raw_next)
        else:
            next_url = None

    return {
        "status": "success",
        "records": records,
        "record_count": len(records),
        "page_count": pages,
    }


def normalize_role(
    record: dict[str, Any],
    *,
    assignment_type: str,
    source_team: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize a role record and preserve how it reaches the user."""
    assignment: dict[str, Any] = {"type": assignment_type}
    if source_team is not None:
        assignment["team"] = {
            "team_id": source_team.get("team_id"),
            "name": source_team.get("name"),
            "team_type": source_team.get("team_type"),
            "business_unit_id": source_team.get("business_unit_id"),
        }

    return {
        "role_id": normalize_guid(record.get("roleid")),
        "name": record.get("name"),
        "business_unit_id": normalize_guid(record.get("_businessunitid_value")),
        "parent_root_role_id": normalize_guid(record.get("_parentrootroleid_value")),
        "role_template_id": normalize_guid(record.get("_roletemplateid_value")),
        "assignment": assignment,
    }


def normalize_team(record: dict[str, Any]) -> dict[str, Any]:
    team_type = record.get("teamtype")
    return {
        "team_id": normalize_guid(record.get("teamid")),
        "name": record.get("name"),
        "team_type": team_type,
        "team_type_label": {0: "owner", 1: "access"}.get(team_type, "other"),
        "business_unit_id": normalize_guid(record.get("_businessunitid_value")),
        "is_default": record.get("isdefault"),
        "system_managed": record.get("systemmanaged"),
    }


def query_direct_roles(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    user_id: str,
) -> dict[str, Any]:
    result = query_collection(
        session,
        f"{api_base}/systemusers({user_id})/systemuserroles_association"
        f"?$select={ROLE_SELECT}",
        verify_tls,
    )
    roles = [
        normalize_role(record, assignment_type="direct")
        for record in result.pop("records", [])
    ]
    result["roles"] = roles
    result["role_count"] = len(roles)
    return result


def query_team_memberships(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    user_id: str,
) -> dict[str, Any]:
    result = query_collection(
        session,
        f"{api_base}/systemusers({user_id})/teammembership_association"
        f"?$select={TEAM_SELECT}",
        verify_tls,
    )
    teams = [normalize_team(record) for record in result.pop("records", [])]
    owner_teams = [team for team in teams if team.get("team_type") == 0]
    access_teams = [team for team in teams if team.get("team_type") == 1]
    other_teams = [team for team in teams if team.get("team_type") not in (0, 1)]
    result.update(
        {
            "teams": teams,
            "team_count": len(teams),
            "owner_team_count": len(owner_teams),
            "access_team_count": len(access_teams),
            "other_team_count": len(other_teams),
            "owner_teams": owner_teams,
            "access_teams": access_teams,
            "other_teams": other_teams,
        }
    )
    return result


def query_owner_team_roles(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    owner_teams: list[dict[str, Any]],
) -> dict[str, Any]:
    inherited_roles: list[dict[str, Any]] = []
    team_results: list[dict[str, Any]] = []

    for team in owner_teams:
        team_id = team.get("team_id")
        if not team_id:
            continue

        result = query_collection(
            session,
            f"{api_base}/teams({team_id})/teamroles_association"
            f"?$select={ROLE_SELECT}",
            verify_tls,
        )
        roles = [
            normalize_role(
                record,
                assignment_type="team",
                source_team=team,
            )
            for record in result.pop("records", [])
        ]
        inherited_roles.extend(roles)
        team_results.append(
            {
                **team,
                "role_query_status": result.get("status"),
                "role_query_error": result.get("error"),
                "role_count": len(roles),
                "roles": roles,
            }
        )

    return {
        "status": "success",
        "team_count": len(team_results),
        "teams_with_roles": sum(1 for team in team_results if team["role_count"]),
        "inherited_role_count": len(inherited_roles),
        "teams": team_results,
        "roles": inherited_roles,
    }


def query_privilege_catalog(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
) -> dict[str, Any]:
    """Retrieve privilege names once, with a compatibility fallback."""
    result = query_collection(
        session,
        f"{api_base}/privileges?$select={PRIVILEGE_SELECT}&$orderby=name",
        verify_tls,
    )
    if result.get("status") != "success":
        result = query_collection(
            session,
            f"{api_base}/privileges?$select=privilegeid,name&$orderby=name",
            verify_tls,
        )
        result["metadata_fallback"] = True
    else:
        result["metadata_fallback"] = False

    records = result.pop("records", [])
    privileges = [normalize_privilege_metadata(record) for record in records]

    result["privileges"] = privileges
    result["privilege_count"] = len(privileges)
    return result



def query_entity_privilege_metadata(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
) -> dict[str, Any]:
    """Map privilege IDs to table metadata using EntityMetadata.Privileges."""
    fields = (
        "LogicalName,SchemaName,ObjectTypeCode,OwnershipType,"
        "IsCustomEntity,IsActivity,IsAuditEnabled,Privileges"
    )
    result = query_collection(
        session,
        f"{api_base}/EntityDefinitions?$select={fields}",
        verify_tls,
        timeout=90,
    )
    records = result.pop("records", [])
    privilege_targets: dict[str, list[dict[str, Any]]] = {}
    entities: list[dict[str, Any]] = []

    for record in records:
        logical_name = record.get("LogicalName")
        entity = {
            "logical_name": logical_name,
            "schema_name": record.get("SchemaName"),
            "object_type_code": record.get("ObjectTypeCode"),
            "ownership_type": record.get("OwnershipType"),
            "is_custom_entity": record.get("IsCustomEntity"),
            "is_activity": record.get("IsActivity"),
            "is_audit_enabled": record.get("IsAuditEnabled"),
        }
        raw_privileges = record.get("Privileges")
        if not isinstance(raw_privileges, list):
            raw_privileges = []
        entity["privilege_count"] = len(raw_privileges)
        entities.append(entity)
        for privilege in raw_privileges:
            if not isinstance(privilege, dict):
                continue
            privilege_id = normalize_guid(privilege.get("PrivilegeId"))
            if not privilege_id:
                continue
            target = {
                **entity,
                "privilege_name": privilege.get("Name"),
                "privilege_type": privilege.get("PrivilegeType"),
            }
            privilege_targets.setdefault(privilege_id, []).append(target)

    result.update(
        {
            "entities": entities,
            "entity_count": len(entities),
            "mapped_privilege_count": len(privilege_targets),
            "privilege_targets": privilege_targets,
        }
    )
    return result


def enrich_privilege_catalog_with_entity_metadata(
    catalog_result: dict[str, Any],
    entity_metadata_result: dict[str, Any],
) -> None:
    mappings = entity_metadata_result.get("privilege_targets", {})
    if not isinstance(mappings, dict):
        mappings = {}
    for item in catalog_result.get("privileges", []):
        targets = mappings.get(item.get("privilege_id"), [])
        item["entity_targets"] = targets
        types = {str(target.get("privilege_type")) for target in targets if target.get("privilege_type") is not None}
        item["privilege_type"] = next(iter(types)) if len(types) == 1 else None


def query_role_privilege_relationship(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    role_id: str,
) -> dict[str, Any]:
    """Try the role-to-privilege relationship without assuming target behavior."""
    result = query_collection(
        session,
        f"{api_base}/roles({role_id})/roleprivileges_association"
        f"?$select={PRIVILEGE_SELECT}&$orderby=name",
        verify_tls,
    )

    # Some Dynamics 365 9.1 targets reject one or more metadata fields even
    # though the relationship itself is readable. Retry with only ID and name.
    if result.get("status") != "success":
        result = query_collection(
            session,
            f"{api_base}/roles({role_id})/roleprivileges_association"
            "?$select=privilegeid,name&$orderby=name",
            verify_tls,
        )
        result["metadata_fallback"] = True
    else:
        result["metadata_fallback"] = False

    records = result.pop("records", [])
    privileges = [normalize_privilege_metadata(record) for record in records]
    result["privileges"] = privileges
    result["privilege_count"] = len(privileges)
    if result.get("status") == "success":
        result["relationship_state"] = "populated" if privileges else "empty"
    else:
        result["relationship_state"] = "unavailable"
    return result


def normalize_role_privilege(
    record: dict[str, Any],
    privilege_catalog: dict[str, dict[str, Any]],
    role_relationship_catalog: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    privilege_id = normalize_guid(
        get_case_insensitive(record, "PrivilegeId", "privilegeid")
    )
    relationship_entry = (role_relationship_catalog or {}).get(privilege_id, {})
    catalog_entry = privilege_catalog.get(privilege_id, {})
    response_name = get_case_insensitive(record, "PrivilegeName", "name")

    if response_name:
        name = response_name
        name_source = "retrieve_role_privileges"
    elif relationship_entry.get("name"):
        name = relationship_entry.get("name")
        name_source = "roleprivileges_association"
    elif catalog_entry.get("name"):
        name = catalog_entry.get("name")
        name_source = "privilege_catalog"
    else:
        name = None
        name_source = None

    access_right = relationship_entry.get("access_right")
    if access_right is None:
        access_right = catalog_entry.get("access_right")

    supported_depths = relationship_entry.get("supported_depths") or {}
    if not any(value is not None for value in supported_depths.values()):
        supported_depths = catalog_entry.get("supported_depths", {})

    return {
        "privilege_id": privilege_id,
        "name": name,
        "depth": get_case_insensitive(record, "Depth"),
        "business_unit_id": normalize_guid(
            get_case_insensitive(record, "BusinessUnitId")
        ),
        "access_right": access_right,
        "entity_targets": relationship_entry.get("entity_targets") or catalog_entry.get("entity_targets", []),
        "privilege_type": relationship_entry.get("privilege_type") or catalog_entry.get("privilege_type"),
        "supported_depths": supported_depths,
        "name_resolved": bool(name),
        "name_resolution_source": name_source,
    }


def query_role_privileges(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    roles: list[dict[str, Any]],
    privilege_catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    role_results: list[dict[str, Any]] = []
    total_assignments = 0
    unresolved_names = 0
    populated_relationships = 0
    empty_relationships = 0
    unavailable_relationships = 0

    for role in roles:
        role_id = role.get("role_id")
        if not role_id:
            continue

        relationship = query_role_privilege_relationship(
            session, api_base, verify_tls, role_id
        )
        relationship_catalog = {
            item["privilege_id"]: item
            for item in relationship.get("privileges", [])
            if item.get("privilege_id")
        }
        relationship_state = relationship.get("relationship_state")
        if relationship_state == "populated":
            populated_relationships += 1
        elif relationship_state == "empty":
            empty_relationships += 1
        else:
            unavailable_relationships += 1

        payload, error, http_status = get_json(
            session,
            f"{api_base}/RetrieveRolePrivilegesRole(RoleId={role_id})",
            verify_tls,
            timeout=45,
        )
        if error or payload is None:
            role_results.append(
                {
                    **role,
                    "status": "error",
                    "http_status": http_status,
                    "error": error or "Unknown error",
                    "privilege_count": 0,
                    "privileges": [],
                    "roleprivileges_association": relationship,
                }
            )
            continue

        raw_privileges = payload.get("RolePrivileges", [])
        if not isinstance(raw_privileges, list):
            raw_privileges = []
        privileges = [
            normalize_role_privilege(
                item, privilege_catalog, relationship_catalog
            )
            for item in raw_privileges
            if isinstance(item, dict)
        ]

        assigned_ids = {
            item.get("privilege_id") for item in privileges if item.get("privilege_id")
        }
        relationship_ids = set(relationship_catalog)
        relationship_validation = {
            "assigned_only": sorted(assigned_ids - relationship_ids)
            if relationship_state == "populated"
            else [],
            "relationship_only": sorted(relationship_ids - assigned_ids)
            if relationship_state == "populated"
            else [],
        }

        total_assignments += len(privileges)
        unresolved_names += sum(
            1 for privilege in privileges if not privilege["name_resolved"]
        )
        role_results.append(
            {
                **role,
                "status": "success",
                "http_status": http_status,
                "privilege_count": len(privileges),
                "privileges": privileges,
                "roleprivileges_association": relationship,
                "relationship_validation": relationship_validation,
            }
        )

    return {
        "status": "success",
        "role_count": len(role_results),
        "privilege_assignment_count": total_assignments,
        "unresolved_name_count": unresolved_names,
        "role_relationships": {
            "populated": populated_relationships,
            "empty": empty_relationships,
            "unavailable": unavailable_relationships,
        },
        "roles": role_results,
    }


def enrich_unresolved_role_privilege_names(
    role_privileges: dict[str, Any],
    user_privileges: dict[str, Any],
) -> None:
    """Use user-level names only as a final compatibility fallback."""
    user_names = {
        item.get("privilege_id"): item.get("name")
        for item in user_privileges.get("privileges", [])
        if item.get("privilege_id") and item.get("name")
    }
    unresolved = 0
    for role in role_privileges.get("roles", []):
        for privilege in role.get("privileges", []):
            if not privilege.get("name"):
                name = user_names.get(privilege.get("privilege_id"))
                if name:
                    privilege["name"] = name
                    privilege["name_resolved"] = True
                    privilege["name_resolution_source"] = "retrieve_user_privileges"
            if not privilege.get("name"):
                unresolved += 1
    role_privileges["unresolved_name_count"] = unresolved


def merge_role_assignments(
    direct_roles: list[dict[str, Any]],
    inherited_roles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate role records while retaining every assignment source."""
    merged: dict[str, dict[str, Any]] = {}
    for role in [*direct_roles, *inherited_roles]:
        role_id = role.get("role_id")
        if not role_id:
            continue
        if role_id not in merged:
            merged[role_id] = {
                "role_id": role_id,
                "name": role.get("name"),
                "business_unit_id": role.get("business_unit_id"),
                "parent_root_role_id": role.get("parent_root_role_id"),
                "role_template_id": role.get("role_template_id"),
                "assignments": [],
            }
        assignment = role.get("assignment")
        if isinstance(assignment, dict) and assignment not in merged[role_id]["assignments"]:
            merged[role_id]["assignments"].append(assignment)
    return sorted(
        merged.values(),
        key=lambda item: ((item.get("name") or "").lower(), item["role_id"]),
    )


def build_effective_privileges(
    role_privilege_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge duplicate role privileges and preserve contributing roles."""
    merged: dict[str, dict[str, Any]] = {}

    for role in role_privilege_results:
        if role.get("status") != "success":
            continue
        for privilege in role.get("privileges", []):
            role_source = {
                "role_id": role.get("role_id"),
                "role_name": role.get("name"),
                "assignments": role.get("assignments", []),
                "assigned_depth": privilege.get("depth"),
                "business_unit_id": privilege.get("business_unit_id"),
            }
            privilege_id = privilege.get("privilege_id")
            if not privilege_id:
                continue
            if privilege_id not in merged:
                merged[privilege_id] = {
                    "privilege_id": privilege_id,
                    "name": privilege.get("name"),
                    "effective_depth": privilege.get("depth"),
                    "access_right": privilege.get("access_right"),
                    "entity_targets": privilege.get("entity_targets", []),
                    "privilege_type": privilege.get("privilege_type"),
                    "supported_depths": privilege.get("supported_depths", {}),
                    "sources": [],
                }
            current_depth = merged[privilege_id].get("effective_depth")
            new_depth = privilege.get("depth")
            if DEPTH_RANK.get(str(new_depth), -1) > DEPTH_RANK.get(str(current_depth), -1):
                merged[privilege_id]["effective_depth"] = new_depth
            if role_source not in merged[privilege_id]["sources"]:
                merged[privilege_id]["sources"].append(role_source)

    return sorted(
        merged.values(),
        key=lambda item: ((item.get("name") or "").lower(), item["privilege_id"]),
    )


def query_user_privileges(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    user_id: str,
    privilege_catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    payload, error, http_status = get_json(
        session,
        f"{api_base}/systemusers({user_id})/Microsoft.Dynamics.CRM.RetrieveUserPrivileges",
        verify_tls,
        timeout=45,
    )
    if error or payload is None:
        return {
            "status": "error",
            "http_status": http_status,
            "error": error or "Unknown error",
            "privileges": [],
            "privilege_count": 0,
        }

    raw_privileges = payload.get("RolePrivileges", [])
    if not isinstance(raw_privileges, list):
        raw_privileges = []
    privileges = [
        normalize_role_privilege(item, privilege_catalog)
        for item in raw_privileges
        if isinstance(item, dict)
    ]
    return {
        "status": "success",
        "http_status": http_status,
        "privilege_count": len(privileges),
        "unresolved_name_count": sum(
            1 for privilege in privileges if not privilege["name_resolved"]
        ),
        "privileges": sorted(
            privileges,
            key=lambda item: ((item.get("name") or "").lower(), item["privilege_id"]),
        ),
    }




def build_privilege_inventory(
    role_derived: list[dict[str, Any]],
    user_reported: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an informational privilege inventory without risk scoring.

    RetrieveUserPrivileges defines the set reported as held by the user. When a
    privilege was also reconstructed from role assignments, the role-derived
    depth is preferred because Dynamics may under-report team-inherited depth.
    """
    role_by_id = {item["privilege_id"]: item for item in role_derived}
    user_by_id = {item["privilege_id"]: item for item in user_reported}

    held: list[dict[str, Any]] = []
    for privilege_id, user_item in user_by_id.items():
        role_item = role_by_id.get(privilege_id)
        role_depth = (role_item or {}).get("effective_depth")
        user_depth = user_item.get("depth")
        effective_depth = role_depth or user_depth or "None"

        held.append(
            {
                "privilege_id": privilege_id,
                "name": (role_item or {}).get("name") or user_item.get("name"),
                "depth": effective_depth,
                "depth_source": "role_assignments" if role_depth else "RetrieveUserPrivileges",
                "role_derived_depth": role_depth,
                "user_reported_depth": user_depth,
                "sources": (role_item or {}).get("sources", []),
                "source_attributed": role_item is not None,
                "access_right": (role_item or {}).get("access_right")
                if (role_item or {}).get("access_right") is not None
                else user_item.get("access_right"),
                "privilege_type": (role_item or {}).get("privilege_type")
                or user_item.get("privilege_type"),
                "entity_targets": (role_item or {}).get("entity_targets")
                or user_item.get("entity_targets", []),
            }
        )

    held.sort(
        key=lambda item: (
            -DEPTH_RANK.get(str(item.get("depth")), 0),
            str(item.get("name") or item.get("privilege_id")).lower(),
        )
    )

    by_depth: dict[str, list[dict[str, Any]]] = {
        depth: [] for depth in ("Global", "Deep", "Local", "Basic", "None")
    }
    for item in held:
        by_depth.setdefault(str(item.get("depth") or "None"), []).append(item)

    role_only = [
        {
            "privilege_id": item.get("privilege_id"),
            "name": item.get("name"),
            "depth": item.get("effective_depth") or "None",
            "sources": item.get("sources", []),
            "access_right": item.get("access_right"),
            "privilege_type": item.get("privilege_type"),
            "entity_targets": item.get("entity_targets", []),
        }
        for privilege_id, item in role_by_id.items()
        if privilege_id not in user_by_id
    ]
    role_only.sort(
        key=lambda item: (
            -DEPTH_RANK.get(str(item.get("depth")), 0),
            str(item.get("name") or item.get("privilege_id")).lower(),
        )
    )

    depth_counts = {
        depth: len(items)
        for depth, items in by_depth.items()
        if items
    }

    return {
        "inventory_version": 1,
        "summary": {
            "held_privilege_count": len(held),
            "source_attributed_count": len([item for item in held if item["source_attributed"]]),
            "user_api_only_count": len([item for item in held if not item["source_attributed"]]),
            "role_derived_not_reported_count": len(role_only),
            "depth_counts": depth_counts,
        },
        "held_privileges": held,
        "by_depth": by_depth,
        "role_derived_not_reported": role_only,
        "depth_note": (
            "The held set comes from RetrieveUserPrivileges. Role-derived depth is used when available "
            "because team-inherited privilege depth may be reported as Basic by RetrieveUserPrivileges."
        ),
    }


def compare_effective_privileges(
    calculated: list[dict[str, Any]],
    reported: list[dict[str, Any]],
) -> dict[str, Any]:
    calculated_by_id = {item["privilege_id"]: item for item in calculated}
    reported_by_id = {item["privilege_id"]: item for item in reported}

    calculated_ids = set(calculated_by_id)
    reported_ids = set(reported_by_id)
    depth_differences: list[dict[str, Any]] = []

    for privilege_id in sorted(calculated_ids & reported_ids):
        calculated_depth = calculated_by_id[privilege_id].get("effective_depth")
        reported_depth = reported_by_id[privilege_id].get("depth")
        if calculated_depth != reported_depth:
            depth_differences.append(
                {
                    "privilege_id": privilege_id,
                    "name": calculated_by_id[privilege_id].get("name")
                    or reported_by_id[privilege_id].get("name"),
                    "calculated_depth": calculated_depth,
                    "reported_depth": reported_depth,
                    "note": (
                        "RetrieveUserPrivileges may report team-inherited privileges "
                        "at Basic depth."
                    ),
                }
            )

    role_derived_only = [
        {
            "privilege_id": privilege_id,
            "name": calculated_by_id[privilege_id].get("name"),
            "role_derived_depth": calculated_by_id[privilege_id].get("effective_depth"),
            "sources": calculated_by_id[privilege_id].get("sources", []),
        }
        for privilege_id in sorted(calculated_ids - reported_ids)
    ]
    user_reported_only = [
        {
            "privilege_id": privilege_id,
            "name": reported_by_id[privilege_id].get("name"),
            "user_reported_depth": reported_by_id[privilege_id].get("depth"),
        }
        for privilege_id in sorted(reported_ids - calculated_ids)
    ]

    return {
        "role_derived_count": len(calculated_ids),
        "user_reported_count": len(reported_ids),
        "role_derived_only": role_derived_only,
        "user_reported_only": user_reported_only,
        # Backward-compatible aliases for existing result consumers.
        "calculated_count": len(calculated_ids),
        "reported_count": len(reported_ids),
        "calculated_only": role_derived_only,
        "reported_only": user_reported_only,
        "depth_differences": depth_differences,
    }




def query_security_roles_and_privileges(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    user_id: str,
) -> dict[str, Any]:
    """Enumerate role sources, role privileges, and the user-level cross-check."""
    direct = query_direct_roles(session, api_base, verify_tls, user_id)
    memberships = query_team_memberships(session, api_base, verify_tls, user_id)
    owner_team_roles = query_owner_team_roles(
        session,
        api_base,
        verify_tls,
        memberships.get("owner_teams", []),
    )

    unique_roles = merge_role_assignments(
        direct.get("roles", []),
        owner_team_roles.get("roles", []),
    )

    catalog_result = query_privilege_catalog(session, api_base, verify_tls)
    catalog_by_id = {
        item["privilege_id"]: item
        for item in catalog_result.get("privileges", [])
        if item.get("privilege_id")
    }

    role_privileges = query_role_privileges(
        session,
        api_base,
        verify_tls,
        unique_roles,
        catalog_by_id,
    )
    user_privileges = query_user_privileges(
        session,
        api_base,
        verify_tls,
        user_id,
        catalog_by_id,
    )
    enrich_unresolved_role_privilege_names(role_privileges, user_privileges)
    calculated_effective = build_effective_privileges(
        role_privileges.get("roles", [])
    )
    comparison = compare_effective_privileges(
        calculated_effective,
        user_privileges.get("privileges", []),
    )
    privilege_inventory = build_privilege_inventory(
        calculated_effective,
        user_privileges.get("privileges", []),
    )

    return {
        "status": "success",
        "direct_roles": direct,
        "team_memberships": memberships,
        "owner_team_roles": owner_team_roles,
        "unique_roles": unique_roles,
        "unique_role_count": len(unique_roles),
        "privilege_catalog": catalog_result,
        "role_privileges": role_privileges,
        "role_derived_privileges": calculated_effective,
        "role_derived_privilege_count": len(calculated_effective),
        # Backward-compatible aliases retained for earlier JSON consumers.
        "calculated_effective_privileges": calculated_effective,
        "calculated_effective_privilege_count": len(calculated_effective),
        "reported_user_privileges": user_privileges,
        "privilege_inventory": privilege_inventory,
        "scope_boundary": {
            "statement": "Privilege enumeration is not a full effective-access review.",
            "not_covered": [
                "field-level security profiles and field permissions",
                "explicit record sharing and principalobjectaccess",
                "access-team rights on individual records",
                "hierarchy-security reach",
                "ownership and cascading access",
            ],
            "next_modules": ["field_security", "record_sharing", "access_team_records", "hierarchy_security"],
        },
        "cross_check": comparison,
    }


def managed_value(value: Any) -> Any:
    """Unwrap Dynamics managed-property values when present."""
    if isinstance(value, dict) and "Value" in value:
        return value.get("Value")
    return value


def normalize_privilege_type(value: Any) -> str | None:
    """Normalize SecurityPrivilegeMetadata.PrivilegeType across response shapes."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return PRIVILEGE_TYPE_LABELS.get(value, str(value))
    if isinstance(value, float) and value.is_integer():
        return PRIVILEGE_TYPE_LABELS.get(int(value), str(int(value)))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return PRIVILEGE_TYPE_LABELS.get(int(stripped), stripped)
        lowered = stripped.lower()
        for label in PRIVILEGE_TYPE_LABELS.values():
            if lowered == label.lower() or lowered.endswith("'" + label.lower() + "'"):
                return label
        return stripped
    return None


def extract_entity_privileges(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return authoritative entity privilege metadata indexed by privilege type."""
    result: dict[str, dict[str, Any]] = {}
    raw_privileges = record.get("Privileges")
    if not isinstance(raw_privileges, list):
        return result

    for raw in raw_privileges:
        if not isinstance(raw, dict):
            continue
        privilege_type = normalize_privilege_type(raw.get("PrivilegeType"))
        name = raw.get("Name")
        if privilege_type not in ENTITY_PRIVILEGE_ORDER and isinstance(name, str):
            lowered = name.lower()
            for candidate in sorted(ENTITY_PRIVILEGE_ORDER, key=len, reverse=True):
                if lowered.startswith(f"prv{candidate.lower()}"):
                    privilege_type = candidate
                    break
        if privilege_type not in ENTITY_PRIVILEGE_ORDER:
            continue
        result[privilege_type] = {
            "privilege_id": normalize_guid(raw.get("PrivilegeId")),
            "name": name,
            "privilege_type": privilege_type,
            "lookup_method": "entity_metadata",
            "metadata_available": True,
        }
    return result


def build_held_privilege_indexes(security: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Index the user's held privileges by GUID and name."""
    inventory = security.get("privilege_inventory", {})
    held = inventory.get("held_privileges", []) if isinstance(inventory, dict) else []
    by_id: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    for item in held:
        if not isinstance(item, dict):
            continue
        privilege_id = normalize_guid(item.get("privilege_id"))
        name = item.get("name")
        if privilege_id:
            by_id[privilege_id] = item
        if isinstance(name, str) and name:
            by_name[name.lower()] = item
    return by_id, by_name


def resolve_entity_privilege(
    privilege_type: str,
    metadata: dict[str, Any] | None,
    logical_name: str | None,
    held_by_id: dict[str, dict[str, Any]],
    held_by_name: dict[str, dict[str, Any]],
    metadata_collection_available: bool,
) -> dict[str, Any]:
    """Map one entity privilege definition to the user's held privilege inventory."""
    item = dict(metadata or {})
    if not item and isinstance(logical_name, str) and logical_name:
        item = {
            "privilege_id": "",
            "name": f"prv{privilege_type}{logical_name}",
            "privilege_type": privilege_type,
            "lookup_method": "derived_from_logical_name",
            "metadata_available": False,
        }

    privilege_id = normalize_guid(item.get("privilege_id"))
    privilege_name = item.get("name")
    held_item = held_by_id.get(privilege_id) if privilege_id else None
    if held_item is None and isinstance(privilege_name, str):
        held_item = held_by_name.get(privilege_name.lower())

    if metadata_collection_available and metadata is None:
        definition_status = "not_defined_for_entity"
        held: bool | None = None
    elif held_item is not None:
        definition_status = "held"
        held = True
    else:
        definition_status = "not_held_or_not_identified"
        held = False

    return {
        **item,
        "definition_status": definition_status,
        "held": held,
        "depth": held_item.get("depth") if held_item else None,
        "user_reported_depth": held_item.get("user_reported_depth") if held_item else None,
        "sources": held_item.get("sources", []) if held_item else [],
    }


def normalize_entity_definition(
    record: dict[str, Any],
    api_base: str,
    held_by_id: dict[str, dict[str, Any]],
    held_by_name: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Normalize entity metadata and map all entity privileges."""
    logical_name = record.get("LogicalName")
    entity_set_name = record.get("EntitySetName")
    raw_privileges = record.get("Privileges")
    metadata_collection_available = isinstance(raw_privileges, list)
    metadata_privileges = extract_entity_privileges(record)

    privilege_matrix = {
        privilege_type: resolve_entity_privilege(
            privilege_type,
            metadata_privileges.get(privilege_type),
            logical_name if isinstance(logical_name, str) else None,
            held_by_id,
            held_by_name,
            metadata_collection_available,
        )
        for privilege_type in ENTITY_PRIVILEGE_ORDER
    }

    endpoint_url = f"{api_base}/{entity_set_name}" if entity_set_name else None
    return {
        "metadata_id": normalize_guid(record.get("MetadataId")),
        "is_custom_entity": record.get("IsCustomEntity"),
        "scope": record.get("_enumeration_scope") or ("custom" if record.get("IsCustomEntity") is True else "sensitive_standard"),
        "logical_name": logical_name,
        "schema_name": record.get("SchemaName"),
        "entity_set_name": entity_set_name,
        "endpoint_url": endpoint_url,
        "primary_id_attribute": record.get("PrimaryIdAttribute"),
        "primary_name_attribute": record.get("PrimaryNameAttribute"),
        "object_type_code": record.get("ObjectTypeCode"),
        "ownership_type": record.get("OwnershipType"),
        "is_activity": record.get("IsActivity"),
        "is_bpf_entity": record.get("IsBPFEntity"),
        "is_intersect": record.get("IsIntersect"),
        "is_audit_enabled": managed_value(record.get("IsAuditEnabled")),
        "auto_create_access_teams": record.get("AutoCreateAccessTeams"),
        "data_provider_id": normalize_guid(record.get("DataProviderId")),
        "data_source_id": normalize_guid(record.get("DataSourceId")),
        "privilege_metadata_available": metadata_collection_available,
        "privileges": privilege_matrix,
        # Compatibility field retained for V13 result consumers.
        "read_privilege": privilege_matrix["Read"],
    }


def probe_entity_set(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    entity: dict[str, Any],
    *,
    include_count: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """Perform a minimal read-only collection probe for one entity set."""
    entity_set = entity.get("entity_set_name")
    primary_id = entity.get("primary_id_attribute")
    if not entity_set or not primary_id:
        return {
            "status": "NOT_PROBED",
            "http_status": None,
            "reason": "EntitySetName or PrimaryIdAttribute is missing",
        }

    url = f"{api_base}/{entity_set}?$select={primary_id}&$top=1"
    try:
        response = session.get(url, verify=verify_tls, timeout=timeout)
    except requests.exceptions.SSLError as exc:
        return {
            "status": "REQUEST_ERROR",
            "http_status": None,
            "error": f"TLS error: {exc}",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "status": "REQUEST_ERROR",
            "http_status": None,
            "error": f"Request failed: {exc}",
        }

    result: dict[str, Any] = {
        "http_status": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
    }

    if response.status_code == 401:
        result.update(status="AUTHENTICATION_FAILED", error=compact_error(response))
        return result
    if response.status_code == 403:
        result.update(status="ACCESS_DENIED", error=compact_error(response))
        return result
    if response.status_code == 404:
        result.update(status="NOT_ADDRESSABLE", error=compact_error(response))
        return result
    if response.status_code == 400:
        result.update(status="INVALID_OR_UNSUPPORTED", error=compact_error(response))
        return result
    if response.status_code == 429:
        result.update(
            status="RATE_LIMITED",
            error=compact_error(response),
            retry_after=response.headers.get("Retry-After"),
        )
        return result
    if 500 <= response.status_code <= 599:
        result.update(status="BACKEND_ERROR", error=compact_error(response))
        return result
    if not response.ok:
        result.update(status="INVALID_OR_UNSUPPORTED", error=compact_error(response))
        return result

    content_type = result["content_type"].lower()
    if "html" in content_type:
        result.update(
            status="AUTHENTICATION_FAILED",
            error="Successful HTTP response returned HTML instead of OData JSON",
        )
        return result

    try:
        payload = response.json()
    except ValueError:
        result.update(status="NON_JSON_RESPONSE", error="Response was not valid JSON")
        return result

    values = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(values, list):
        result.update(
            status="INVALID_OR_UNSUPPORTED",
            error="Response did not contain an OData value array",
        )
        return result

    if include_count:
        count_url = f"{api_base}/{entity_set}?$select={primary_id}&$top=1&$count=true"
        count_payload, count_error, count_status = get_json(
            session,
            count_url,
            verify_tls,
            timeout=timeout,
        )
        if count_payload is not None and count_error is None:
            count_value = count_payload.get("@odata.count")
            if isinstance(count_value, int):
                result["visible_record_count"] = count_value
            elif isinstance(count_value, str) and count_value.isdigit():
                result["visible_record_count"] = int(count_value)
            else:
                result["count_note"] = "The count query succeeded but did not return @odata.count."
        else:
            result["count_note"] = f"Count query unavailable (HTTP {count_status or 'n/a'}): {count_error or 'unknown error'}"

    if not values:
        result.update(
            status="READABLE_EMPTY_OR_FILTERED",
            visible_record_count_in_probe=0,
            note="The table is callable, but it may be empty or security-filtered for this user.",
        )
        return result

    first = values[0] if isinstance(values[0], dict) else {}
    sample_id = first.get(primary_id) if isinstance(first, dict) else None
    result.update(
        status="READABLE_WITH_DATA",
        visible_record_count_in_probe=len(values),
        sample_record_id=normalize_guid(sample_id) if sample_id else None,
    )
    return result


def query_entity_access(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    security: dict[str, Any],
    *,
    include_counts: bool = False,
) -> dict[str, Any]:
    """Enumerate custom and sensitive standard entities and test minimal read access."""
    attempts = [
        (CUSTOM_ENTITY_FIELDS, "rich"),
        (CUSTOM_ENTITY_FALLBACK_FIELDS, "compatibility"),
        (CUSTOM_ENTITY_MINIMAL_FIELDS, "minimal"),
    ]
    metadata_result: dict[str, Any] | None = None
    selected_mode: str | None = None
    attempt_errors: list[dict[str, Any]] = []

    for fields, mode in attempts:
        custom_candidate = query_collection(
            session,
            f"{api_base}/EntityDefinitions?$filter=IsCustomEntity eq true&$select={fields}",
            verify_tls,
            timeout=90,
        )
        standard_records: list[dict[str, Any]] = []
        standard_errors: list[dict[str, Any]] = []
        for logical_name in SENSITIVE_STANDARD_ENTITY_LOGICAL_NAMES:
            standard_candidate = query_collection(
                session,
                f"{api_base}/EntityDefinitions?$filter=LogicalName eq '{logical_name}'&$select={fields}",
                verify_tls,
                timeout=45,
            )
            if standard_candidate.get("status") == "success":
                standard_records.extend(standard_candidate.get("records", []))
            else:
                standard_errors.append({
                    "logical_name": logical_name,
                    "http_status": standard_candidate.get("http_status"),
                    "error": standard_candidate.get("error"),
                })

        if custom_candidate.get("status") == "success":
            custom_records = custom_candidate.get("records", [])
            for record in custom_records:
                if isinstance(record, dict):
                    record["_enumeration_scope"] = "custom"
            for record in standard_records:
                if isinstance(record, dict):
                    record["_enumeration_scope"] = "sensitive_standard"

            metadata_result = custom_candidate
            metadata_result["records"] = custom_records + standard_records
            metadata_result["sensitive_standard_errors"] = standard_errors
            selected_mode = mode
            break
        attempt_errors.append(
            {
                "mode": mode,
                "http_status": custom_candidate.get("http_status"),
                "error": custom_candidate.get("error"),
                "sensitive_standard_errors": standard_errors,
            }
        )

    if metadata_result is None:
        return {
            "status": "error",
            "metadata_attempts": attempt_errors,
            "entity_count": 0,
            "entities": [],
        }

    held_by_id, held_by_name = build_held_privilege_indexes(security)
    raw_records = metadata_result.pop("records", [])
    normalized_entities = [
        normalize_entity_definition(record, api_base, held_by_id, held_by_name)
        for record in raw_records
        if isinstance(record, dict)
    ]
    deduplicated: dict[str, dict[str, Any]] = {}
    for entity in normalized_entities:
        key = str(entity.get("logical_name") or entity.get("metadata_id") or "").lower()
        if key:
            deduplicated[key] = entity
    entities = sorted(
        deduplicated.values(),
        key=lambda item: (str(item.get("scope") or ""), str(item.get("logical_name") or "").lower()),
    )

    status_counts: dict[str, int] = {}
    privilege_counts = {"held": 0, "not_held": 0, "unknown": 0}
    privilege_type_counts = {privilege_type: {"held": 0, "not_held": 0, "not_defined": 0} for privilege_type in ENTITY_PRIVILEGE_ORDER}
    for entity in entities:
        probe = probe_entity_set(session, api_base, verify_tls, entity, include_count=include_counts)
        entity["probe"] = probe
        status = str(probe.get("status") or "NOT_PROBED")
        status_counts[status] = status_counts.get(status, 0) + 1

        held = entity.get("read_privilege", {}).get("held")
        if held is True:
            privilege_counts["held"] += 1
        elif held is False:
            privilege_counts["not_held"] += 1
        else:
            privilege_counts["unknown"] += 1

        for privilege_type, privilege in entity.get("privileges", {}).items():
            definition_status = privilege.get("definition_status")
            if privilege.get("held") is True:
                privilege_type_counts[privilege_type]["held"] += 1
            elif definition_status == "not_defined_for_entity":
                privilege_type_counts[privilege_type]["not_defined"] += 1
            else:
                privilege_type_counts[privilege_type]["not_held"] += 1

        if held is True and status == "ACCESS_DENIED":
            entity["consistency_note"] = "Read privilege is reported as held, but the collection probe returned access denied."
        elif held is False and status in ("READABLE_WITH_DATA", "READABLE_EMPTY_OR_FILTERED"):
            entity["consistency_note"] = "The collection is readable although the entity Read privilege was not found in the held inventory."

    return {
        "status": "success",
        "metadata_mode": selected_mode,
        "metadata_attempts": attempt_errors,
        "metadata_page_count": metadata_result.get("page_count", 0),
        "entity_count": len(entities),
        "custom_entity_count": sum(1 for item in entities if item.get("scope") == "custom"),
        "sensitive_standard_entity_count": sum(1 for item in entities if item.get("scope") == "sensitive_standard"),
        "sensitive_standard_requested": list(SENSITIVE_STANDARD_ENTITY_LOGICAL_NAMES),
        "sensitive_standard_errors": metadata_result.get("sensitive_standard_errors", []),
        "visible_record_counts_requested": include_counts,
        "probe_status_counts": status_counts,
        "read_privilege_counts": privilege_counts,
        "privilege_type_counts": privilege_type_counts,
        "entities": entities,
        "probe_method": {
            "method": "GET collection with primary ID only and $top=1",
            "read_only": True,
            "empty_result_note": "READABLE_EMPTY_OR_FILTERED cannot distinguish an empty table from security-filtered rows.",
        },
    }


SECRET_ENTITY_STORE_TERMS = (
    "secret", "credential", "configuration", "config", "setting", "parameter",
    "environmentvariable", "connection", "keyvault", "keystore", "certificate",
    "endpoint", "webhook",
)
SECRET_CONTEXT_FIELD_TERMS = (
    "name", "key", "setting", "parameter", "property", "code", "identifier", "title",
)
SECRET_VALUE_FIELD_TERMS = (
    "value", "content", "data", "text", "payload", "configuration", "config",
    "secret", "password", "token", "connectionstring", "url", "uri", "endpoint",
)
TEXTUAL_ATTRIBUTE_TYPES = {"string", "memo", "entityname"}

SECRET_CATEGORY_LABELS = {
    "client_secret": "Client secret",
    "api_key": "API key",
    "password": "Password or passphrase",
    "token": "Token",
    "connection_string": "Connection string",
    "private_key": "Private key",
    "certificate": "Certificate material",
    "credential": "Credential",
    "secret": "Secret",
    "endpoint_url": "Endpoint or URL",
}


def split_identifier_tokens(value: Any) -> list[str]:
    """Split schema-style identifiers and dotted setting keys into normalized tokens."""
    text = str(value or "").strip()
    if not text:
        return []
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    return [token.lower() for token in re.findall(r"[A-Za-z0-9]+", text)]


def identifier_forms(value: Any) -> tuple[list[str], str, str]:
    tokens = split_identifier_tokens(value)
    joined = " ".join(tokens)
    compact = "".join(tokens)
    return tokens, joined, compact


def classify_sensitive_identifier(value: Any) -> str | None:
    """Classify names/keys without treating generic words such as 'key' as secrets."""
    tokens, joined, compact = identifier_forms(value)
    token_set = set(tokens)
    if not tokens:
        return None
    if "clientsecret" in compact or ("client" in token_set and "secret" in token_set):
        return "client_secret"
    if "apikey" in compact or ("api" in token_set and "key" in token_set) or "subscriptionkey" in compact:
        return "api_key"
    if token_set.intersection({"password", "passwords", "passwd", "pwd", "passphrase", "passphrases"}):
        return "password"
    if token_set.intersection({"token", "tokens", "jwt"}) or any(term in compact for term in ("accesstoken", "refreshtoken", "bearertoken", "idtoken")):
        return "token"
    if "connectionstring" in compact or ("connection" in token_set and "string" in token_set):
        return "connection_string"
    if "privatekey" in compact or ("private" in token_set and "key" in token_set) or token_set.intersection({"pfx", "pem", "pkcs12"}):
        return "private_key"
    if token_set.intersection({"certificate", "certificates", "thumbprint", "thumbprints"}) or "certificate" in compact:
        return "certificate"
    if token_set.intersection({"credential", "credentials", "creds"}):
        return "credential"
    if token_set.intersection({"secret", "secrets"}):
        return "secret"
    if token_set.intersection({"endpoint", "endpoints", "url", "urls", "uri", "uris", "webhook", "webhooks", "callback", "callbacks"}) or any(term in compact for term in ("baseurl", "serviceurl", "redirecturl", "redirecturi")):
        return "endpoint_url"
    return None


def is_configuration_store_entity(entity: dict[str, Any]) -> bool:
    names = " ".join(
        str(entity.get(key) or "")
        for key in ("logical_name", "schema_name", "entity_set_name")
    )
    _, _, compact = identifier_forms(names)
    logical_name = str(entity.get("logical_name") or "").lower()
    if logical_name == "organization":
        return True
    return any(term in compact for term in SECRET_ENTITY_STORE_TERMS)


def is_context_field(name: str) -> bool:
    tokens, _, compact = identifier_forms(name)
    return any(term in tokens or term in compact for term in SECRET_CONTEXT_FIELD_TERMS)


def is_value_field(name: str) -> bool:
    tokens, _, compact = identifier_forms(name)
    return any(term in tokens or term in compact for term in SECRET_VALUE_FIELD_TERMS)


def is_pair_value_field(name: str) -> bool:
    """Identify generic sibling fields likely to hold the value named by a key field."""
    tokens, _, _ = identifier_forms(name)
    return bool(set(tokens).intersection({"value", "content", "data", "text", "payload", "configuration", "config"}))


def pair_value_rank(name: str) -> int:
    tokens, _, _ = identifier_forms(name)
    priorities = ("value", "content", "payload", "data", "text", "configuration", "config")
    for index, term in enumerate(priorities):
        if term in tokens:
            return index
    return len(priorities)


def is_likely_sensitive_value_attribute(name: str, category: str) -> bool:
    """Avoid treating context fields such as token expiry or secret name as the secret itself."""
    tokens, _, compact = identifier_forms(name)
    token_set = set(tokens)
    contextual = {
        "name", "names", "id", "identifier", "type", "status", "enabled", "disabled",
        "expiry", "expiration", "lifetime", "timeout", "length", "count", "date", "time",
        "required", "present", "exists", "reference", "ref",
    }
    value_markers = {"value", "content", "data", "payload", "text"}
    if category == "endpoint_url":
        return True
    if token_set.intersection(value_markers) or any(compact.endswith(term) for term in value_markers):
        return True
    if token_set.intersection(contextual) or any(compact.endswith(term) for term in contextual):
        return False
    if category == "token" and "token" in token_set and len(token_set) > 1:
        return any(term in compact for term in ("accesstoken", "refreshtoken", "bearertoken", "idtoken", "authtoken"))
    return True


def managed_boolean(value: Any) -> bool | None:
    """Normalize metadata booleans that may be returned directly or as managed values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        inner = value.get("Value")
        return inner if isinstance(inner, bool) else None
    return None


def normalize_attribute_metadata(record: dict[str, Any]) -> dict[str, Any]:
    attribute_type = record.get("AttributeType")
    if isinstance(attribute_type, dict):
        attribute_type = attribute_type.get("Value")
    return {
        "metadata_id": normalize_guid(record.get("MetadataId")),
        "logical_name": record.get("LogicalName"),
        "schema_name": record.get("SchemaName"),
        "attribute_type": str(attribute_type or ""),
        "is_valid_for_read": managed_boolean(record.get("IsValidForRead")),
        "is_primary_id": record.get("IsPrimaryId") is True,
        "is_primary_name": record.get("IsPrimaryName") is True,
    }


def query_entity_attributes(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    logical_name: str,
) -> dict[str, Any]:
    escaped = logical_name.replace("'", "''")
    attempts = (
        "MetadataId,LogicalName,SchemaName,AttributeType,IsValidForRead,IsPrimaryId,IsPrimaryName",
        "MetadataId,LogicalName,SchemaName,AttributeType,IsValidForRead",
        "MetadataId,LogicalName,SchemaName,AttributeType",
    )
    errors: list[dict[str, Any]] = []
    for fields in attempts:
        result = query_collection(
            session,
            f"{api_base}/EntityDefinitions(LogicalName='{escaped}')/Attributes?$select={fields}",
            verify_tls,
            timeout=60,
        )
        if result.get("status") == "success":
            attributes = [
                normalize_attribute_metadata(record)
                for record in result.pop("records", [])
                if isinstance(record, dict)
            ]
            result["attributes"] = attributes
            result["attribute_count"] = len(attributes)
            result["selected_fields"] = fields
            result["attempt_errors"] = errors
            return result
        errors.append({
            "selected_fields": fields,
            "http_status": result.get("http_status"),
            "error": result.get("error"),
        })
    return {
        "status": "error",
        "logical_name": logical_name,
        "attributes": [],
        "attribute_count": 0,
        "attempt_errors": errors,
        "error": errors[-1].get("error") if errors else "Attribute metadata query failed",
    }


def detect_value_pattern(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", text, re.I):
        return "private_key"
    if re.search(r"-----BEGIN CERTIFICATE-----", text, re.I):
        return "certificate"
    if re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", text):
        return "token"
    if re.match(r"(?i)^bearer\s+\S+", text):
        return "token"
    if re.search(r"(?i)(?:^|;)\s*(?:server|data source|host|accountname|database|initial catalog|endpoint)\s*=", text) and re.search(r"(?i)(?:password|pwd|accountkey|sharedaccesssignature|user id|uid)\s*=", text):
        return "connection_string"
    if re.search(r"(?i)\b(?:https?|ftp|sftp|amqp|tcp)://", text):
        return "endpoint_url"
    return None


def sanitize_url_preview(value: str) -> str:
    """Keep an endpoint useful while removing userinfo and common secret query values."""
    text = value.strip()
    match = re.search(r"(?i)(https?://[^\s\"'<>]+)", text)
    candidate = match.group(1) if match else text
    candidate = re.sub(r"(?i)(https?://)([^/@:]+):([^/@]+)@", r"\1\2:••••@", candidate)
    candidate = re.sub(
        r"(?i)([?&](?:token|access_token|api[_-]?key|key|sig|signature|code|password|client_secret)=)[^&#]+",
        r"\1••••",
        candidate,
    )
    return candidate[:240]


def masked_value_details(value: Any, category: str) -> dict[str, Any]:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    if category == "endpoint_url":
        preview = sanitize_url_preview(text)
    elif len(text) <= 4:
        preview = "•" * max(1, len(text))
    elif len(text) <= 10:
        preview = f"{text[:1]}{'•' * max(4, len(text) - 2)}{text[-1:]}"
    else:
        preview = f"{text[:4]}••••••••{text[-4:]}"
    return {
        "masked_value": preview,
        "value_length": len(text),
        "sha256": digest,
    }


def verification_record_url(
    api_base: str,
    entity: dict[str, Any],
    record_id: str | None,
    fields: list[str],
    record_limit: int,
) -> str | None:
    entity_set = entity.get("entity_set_name")
    if not entity_set:
        return None
    unique_fields = [field for field in dict.fromkeys(fields) if field]
    select = ",".join(unique_fields)
    if record_id:
        base = f"{api_base}/{entity_set}({record_id})"
        return f"{base}?$select={select}" if select else base
    suffix = f"?$select={select}" if select else "?"
    separator = "&" if select else ""
    return f"{api_base}/{entity_set}{suffix}{separator}$top={record_limit}"


def scalar_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


def structured_sensitive_values(value: str, outer_field: str) -> list[dict[str, Any]]:
    """Return sensitive JSON/XML leaf values without retaining complete structures."""
    findings: list[dict[str, Any]] = []
    stripped = value.strip()
    if not stripped:
        return findings

    try:
        parsed = json.loads(stripped)
    except (ValueError, TypeError):
        parsed = None

    def walk_json(node: Any, path_parts: list[str]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                key_text = str(key)
                category = classify_sensitive_identifier(key_text)
                child_path = path_parts + [key_text]
                if category and not isinstance(child, (dict, list)):
                    findings.append({
                        "category": category,
                        "value": child,
                        "source_path": ".".join(child_path),
                        "detection_method": "structured_key",
                    })
                walk_json(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk_json(child, path_parts + [str(index)])

    if parsed is not None:
        walk_json(parsed, [outer_field])
        return findings

    if stripped.startswith("<") and stripped.endswith(">"):
        try:
            root = ET.fromstring(stripped)
        except ET.ParseError:
            return findings
        for element in root.iter():
            tag = element.tag.split("}")[-1]
            category = classify_sensitive_identifier(tag)
            text = (element.text or "").strip()
            if category and text:
                findings.append({
                    "category": category,
                    "value": text,
                    "source_path": f"{outer_field}.{tag}",
                    "detection_method": "structured_key",
                })
            for attribute_name, attribute_value in element.attrib.items():
                attribute_category = classify_sensitive_identifier(attribute_name)
                if attribute_category and attribute_value:
                    findings.append({
                        "category": attribute_category,
                        "value": attribute_value,
                        "source_path": f"{outer_field}.{tag}.@{attribute_name}",
                        "detection_method": "structured_key",
                    })
    return findings


def inspect_secret_record(
    record: dict[str, Any],
    entity: dict[str, Any],
    api_base: str,
    text_fields: set[str],
    record_limit: int,
) -> list[dict[str, Any]]:
    primary_id = str(entity.get("primary_id_attribute") or "")
    raw_id = record.get(primary_id) if primary_id else None
    record_id = normalize_guid(raw_id) if raw_id else None
    results: list[dict[str, Any]] = []

    def add_finding(
        category: str,
        value: Any,
        *,
        value_field: str,
        source_path: str,
        detection_method: str,
        key_field: str | None = None,
        key_value: str | None = None,
    ) -> None:
        scalar = scalar_text(value)
        if scalar is None:
            return
        details = masked_value_details(scalar, category)
        verification_fields = [primary_id, key_field or "", value_field]
        results.append({
            "category": category,
            "category_label": SECRET_CATEGORY_LABELS.get(category, category.replace("_", " ").title()),
            "entity_logical_name": entity.get("logical_name"),
            "entity_set_name": entity.get("entity_set_name"),
            "scope": entity.get("scope"),
            "record_id": record_id,
            "key_field": key_field,
            "key_value": key_value,
            "value_field": value_field,
            "source_path": source_path,
            "detection_method": detection_method,
            "verification_url": verification_record_url(api_base, entity, record_id, verification_fields, record_limit),
            **details,
        })

    # Directly sensitive field names and value signatures.
    for field, value in record.items():
        if field.startswith("@odata.") or field not in text_fields:
            continue
        category = classify_sensitive_identifier(field)
        if category and is_likely_sensitive_value_attribute(field, category):
            add_finding(category, value, value_field=field, source_path=field, detection_method="attribute_name")
        else:
            pattern_category = detect_value_pattern(value)
            if pattern_category:
                add_finding(pattern_category, value, value_field=field, source_path=field, detection_method="value_pattern")

        if isinstance(value, str) and value.lstrip().startswith(("{", "[", "<")):
            for nested in structured_sensitive_values(value, field):
                add_finding(
                    nested["category"],
                    nested["value"],
                    value_field=field,
                    source_path=nested["source_path"],
                    detection_method=nested["detection_method"],
                )

    # Configuration-store key/value records, e.g. name=Api.X.ClientSecret and value=<secret>.
    key_candidates: list[tuple[str, str, str]] = []
    for field, value in record.items():
        if field.startswith("@odata.") or field not in text_fields or not is_context_field(field):
            continue
        text = scalar_text(value)
        category = classify_sensitive_identifier(text) if text else None
        if category and text:
            key_candidates.append((field, text, category))

    value_candidates = sorted(
        [
            (field, value)
            for field, value in record.items()
            if field in text_fields and not field.startswith("@odata.") and is_pair_value_field(field) and scalar_text(value) is not None
        ],
        key=lambda item: (pair_value_rank(item[0]), item[0]),
    )
    for key_field, key_value, category in key_candidates:
        usable = [(field, value) for field, value in value_candidates if field != key_field]
        if not usable:
            continue
        best_rank = pair_value_rank(usable[0][0])
        for value_field, value in usable:
            if pair_value_rank(value_field) != best_rank:
                break
            add_finding(
                category,
                value,
                value_field=value_field,
                source_path=value_field,
                detection_method="configuration_key_value_pair",
                key_field=key_field,
                key_value=key_value,
            )

    deduplicated: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in results:
        key = (
            finding.get("entity_logical_name"), finding.get("record_id"),
            finding.get("category"), finding.get("source_path"), finding.get("sha256"),
        )
        current = deduplicated.get(key)
        # Prefer the key/value explanation when both direct and paired detections identify the same value.
        if current is None or finding.get("detection_method") == "configuration_key_value_pair":
            deduplicated[key] = finding
    return list(deduplicated.values())


def query_secret_candidate_records(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    entity: dict[str, Any],
    attributes: list[dict[str, Any]],
    record_limit: int,
) -> dict[str, Any]:
    entity_set = entity.get("entity_set_name")
    if not entity_set:
        return {"status": "not_scanned", "error": "EntitySetName is unavailable", "records": []}

    primary_id = str(entity.get("primary_id_attribute") or "")
    primary_name = str(entity.get("primary_name_attribute") or "")
    readable_text_attributes = [
        item for item in attributes
        if item.get("logical_name")
        and item.get("attribute_type", "").lower() in TEXTUAL_ATTRIBUTE_TYPES
        and item.get("is_valid_for_read") is not False
    ]
    text_fields = {str(item["logical_name"]) for item in readable_text_attributes}
    candidate_fields = {
        str(item["logical_name"])
        for item in readable_text_attributes
        if classify_sensitive_identifier(item.get("logical_name"))
        or is_context_field(str(item.get("logical_name") or ""))
        or is_value_field(str(item.get("logical_name") or ""))
    }
    config_store = is_configuration_store_entity(entity)
    if not config_store and not any(classify_sensitive_identifier(field) for field in candidate_fields):
        return {
            "status": "not_candidate",
            "config_store": False,
            "candidate_attributes": sorted(candidate_fields),
            "text_fields": sorted(text_fields),
            "records": [],
        }

    query_url = f"{api_base}/{entity_set}"
    params: list[str] = []
    if not config_store:
        selected = [field for field in dict.fromkeys([primary_id, primary_name, *sorted(candidate_fields)]) if field]
        if selected:
            params.append(f"$select={','.join(selected)}")
    if record_limit > 0:
        params.append(f"$top={record_limit}")
    if params:
        query_url += "?" + "&".join(params)

    result = query_collection(session, query_url, verify_tls, timeout=90)
    records = result.pop("records", [])
    result.update({
        "query_url": query_url,
        "config_store": config_store,
        "candidate_attributes": sorted(candidate_fields),
        "text_fields": sorted(text_fields),
        "records": records,
        "records_returned": len(records),
    })
    return result


def query_secret_configuration_scan(
    session: requests.Session,
    api_base: str,
    verify_tls: bool,
    entity_access: dict[str, Any],
    *,
    record_limit: int = 200,
) -> dict[str, Any]:
    """Inspect readable entities for credential-like fields and configuration key/value stores."""
    if entity_access.get("status") != "success":
        return {
            "status": "not_run",
            "reason": "Entity access enumeration was not successful",
            "findings": [],
            "finding_count": 0,
        }

    readable_entities = [
        entity for entity in entity_access.get("entities", [])
        if isinstance(entity, dict)
        and entity.get("probe", {}).get("status") == "READABLE_WITH_DATA"
        and entity.get("entity_set_name")
        and entity.get("logical_name")
    ]
    findings: list[dict[str, Any]] = []
    scan_entities: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    records_inspected = 0
    attribute_metadata_success = 0

    for entity in readable_entities:
        logical_name = str(entity.get("logical_name"))
        attribute_result = query_entity_attributes(session, api_base, verify_tls, logical_name)
        if attribute_result.get("status") != "success":
            errors.append({
                "entity_logical_name": logical_name,
                "stage": "attribute_metadata",
                "http_status": attribute_result.get("http_status"),
                "error": attribute_result.get("error"),
                "attempt_errors": attribute_result.get("attempt_errors", []),
            })
            continue
        attribute_metadata_success += 1
        attributes = attribute_result.get("attributes", [])
        record_result = query_secret_candidate_records(
            session,
            api_base,
            verify_tls,
            entity,
            attributes,
            record_limit,
        )
        status = record_result.get("status")
        if status in ("not_candidate", "not_scanned"):
            continue
        if status != "success":
            errors.append({
                "entity_logical_name": logical_name,
                "stage": "record_query",
                "http_status": record_result.get("http_status"),
                "error": record_result.get("error"),
                "query_url": record_result.get("query_url"),
            })
            continue

        records = record_result.pop("records", [])
        text_fields = set(record_result.get("text_fields", []))
        entity_findings: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            records_inspected += 1
            entity_findings.extend(
                inspect_secret_record(record, entity, api_base, text_fields, record_limit)
            )
        findings.extend(entity_findings)
        scan_entities.append({
            "entity_logical_name": logical_name,
            "entity_set_name": entity.get("entity_set_name"),
            "scope": entity.get("scope"),
            "config_store": record_result.get("config_store"),
            "attribute_count": attribute_result.get("attribute_count", 0),
            "candidate_attributes": record_result.get("candidate_attributes", []),
            "records_inspected": len(records),
            "finding_count": len(entity_findings),
            "query_url": record_result.get("query_url"),
        })

    deduplicated: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        key = (
            finding.get("entity_logical_name"), finding.get("record_id"),
            finding.get("category"), finding.get("source_path"), finding.get("sha256"),
        )
        deduplicated[key] = finding
    findings = sorted(
        deduplicated.values(),
        key=lambda item: (
            str(item.get("category_label") or ""),
            str(item.get("entity_logical_name") or ""),
            str(item.get("key_value") or item.get("source_path") or ""),
        ),
    )
    category_counts: dict[str, int] = {}
    for finding in findings:
        category = str(finding.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "status": "success",
        "mode": "all readable attribute metadata; targeted values; broad values for configuration-like entities",
        "read_only": True,
        "record_limit_per_entity": record_limit,
        "raw_secret_values_stored": False,
        "readable_entities_considered": len(readable_entities),
        "attribute_metadata_success_count": attribute_metadata_success,
        "attribute_metadata_error_count": len([error for error in errors if error.get("stage") == "attribute_metadata"]),
        "candidate_entity_count": len(scan_entities),
        "records_inspected": records_inspected,
        "finding_count": len(findings),
        "category_counts": category_counts,
        "entities": scan_entities,
        "findings": findings,
        "errors": errors,
    }

def print_entity_access(custom_entities: dict[str, Any]) -> None:
    """Print entity access grouped first by scope, then by probe result."""
    print("\nEntity access")
    print("-------------")
    if custom_entities.get("status") != "success":
        print("Enumeration failed")
        for attempt in custom_entities.get("metadata_attempts", []):
            print(
                f"- {attempt.get('mode')}: "
                f"{attempt.get('error') or attempt.get('http_status') or 'unknown error'}"
            )
        return

    print(f"Metadata mode        : {custom_entities.get('metadata_mode', 'unknown')}")

    entities = custom_entities.get("entities", [])
    scope_definitions = (
        ("sensitive_standard", "Default entities"),
        ("custom", "Custom entities"),
    )
    primary_statuses = (
        ("READABLE_WITH_DATA", "Access with data"),
        ("READABLE_EMPTY_OR_FILTERED", "Access with no visible data"),
        ("ACCESS_DENIED", "Access denied"),
    )

    def print_entity(entity: dict[str, Any]) -> None:
        logical_name = entity.get("logical_name") or "unknown"
        entity_set = entity.get("entity_set_name") or "no entity set"
        privilege_labels: list[str] = []
        for privilege_type in ENTITY_PRIVILEGE_ORDER:
            privilege = entity.get("privileges", {}).get(privilege_type, {})
            if privilege.get("held") is True:
                privilege_labels.append(
                    f"{privilege_type}={privilege.get('depth') or 'held'}"
                )
        line = f"- {logical_name} | set={entity_set}"
        if privilege_labels:
            line += " | " + " ".join(privilege_labels)
        print(line)
        if entity.get("endpoint_url"):
            print(f"  URL: {entity['endpoint_url']}")

    for scope, scope_title in scope_definitions:
        scope_entities = [entity for entity in entities if entity.get("scope") == scope]
        print(f"\n{scope_title} ({len(scope_entities)})")
        print("=" * (len(scope_title) + len(str(len(scope_entities))) + 3))

        by_status: dict[str, list[dict[str, Any]]] = {}
        for entity in scope_entities:
            status = str(entity.get("probe", {}).get("status") or "NOT_PROBED")
            by_status.setdefault(status, []).append(entity)

        for status, label in primary_statuses:
            items = by_status.get(status, [])
            print(f"\n{label} ({len(items)})")
            print("-" * (len(label) + len(str(len(items))) + 3))
            for entity in items:
                print_entity(entity)

        other_statuses = [
            status for status in ENTITY_PROBE_ORDER
            if status not in {item[0] for item in primary_statuses} and by_status.get(status)
        ]
        other_statuses.extend(
            sorted(
                status
                for status in set(by_status) - set(ENTITY_PROBE_ORDER)
                if status not in {item[0] for item in primary_statuses}
            )
        )
        if other_statuses:
            other_count = sum(len(by_status.get(status, [])) for status in other_statuses)
            print(f"\nOther probe results ({other_count})")
            print("-" * (len("Other probe results") + len(str(other_count)) + 3))
            for status in other_statuses:
                items = by_status.get(status, [])
                if not items:
                    continue
                print(f"{status} ({len(items)})")
                for entity in items:
                    print_entity(entity)


def save_results(results: dict[str, Any], output_path: Path) -> None:
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(results, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        sys.exit(f"Could not save {output_path}: {exc}")


def format_signal_value(value: Any, *, max_length: int = 160) -> str:
    """Render a signal value compactly for terminal output."""
    rendered = json.dumps(value, ensure_ascii=False, default=str)
    if len(rendered) > max_length:
        return rendered[: max_length - 3] + "..."
    return rendered


def print_checks_not_evaluated(checks: list[dict[str, Any]], limit: int = 20) -> None:
    if not checks:
        return
    print("\nChecks not evaluated")
    print("--------------------")
    for item in checks[:limit]:
        expected = ", ".join(item.get("expected_settings", []))
        print(f"- {item.get('check')}: {expected}")
    remaining = len(checks) - limit
    if remaining > 0:
        print(f"... {remaining} more unevaluated check(s) saved to JSON")


def print_review_signals(signals: list[dict[str, Any]]) -> None:
    """Display actionable context for each organization review signal."""
    if not signals:
        return

    print("\nReview signal details")
    print("---------------------")
    for index, signal in enumerate(signals, start=1):
        title = signal.get("title") or signal.get("id") or "Unnamed signal"
        category = signal.get("category") or "uncategorized"
        field = signal.get("field") or "unknown"
        value = format_signal_value(signal.get("value"))
        rationale = signal.get("rationale") or "No rationale provided."

        print(f"{index}. {title}")
        print(f"   Category : {category}")
        print(f"   Setting  : {field} = {value}")
        print(f"   Why      : {rationale}")



def privilege_source_labels(sources: list[dict[str, Any]]) -> list[str]:
    """Render direct and team role provenance without exposing internal IDs."""
    labels: list[str] = []
    for source in sources:
        role_name = source.get("role_name") or source.get("role_id") or "unknown role"
        assignments = source.get("assignments", [])
        if not assignments:
            label = str(role_name)
            if label not in labels:
                labels.append(label)
            continue
        for assignment in assignments:
            assignment_type = assignment.get("type")
            if assignment_type == "direct":
                label = f"{role_name} (direct)"
            elif assignment_type == "team":
                team = assignment.get("team") or {}
                team_name = team.get("name") or team.get("team_id") or "unknown team"
                label = f"{role_name} (team: {team_name})"
            else:
                label = str(role_name)
            if label not in labels:
                labels.append(label)
    return labels


def print_privilege_inventory(
    inventory: dict[str, Any],
) -> None:
    """Print every user-held privilege, grouped from Global to Basic."""
    summary = inventory.get("summary", {})
    print("\nPrivilege inventory")
    print("-------------------")
    print(f"Held privileges       : {summary.get('held_privilege_count', 0)}")
    print(f"Source attributed     : {summary.get('source_attributed_count', 0)}")
    print(f"User API only         : {summary.get('user_api_only_count', 0)}")
    print(f"Role-only discrepancy : {summary.get('role_derived_not_reported_count', 0)}")

    counts = summary.get("depth_counts", {})
    if counts:
        rendered = ", ".join(
            f"{depth}={counts.get(depth, 0)}"
            for depth in ("Global", "Deep", "Local", "Basic", "None")
            if counts.get(depth, 0)
        )
        print(f"Depths                : {rendered}")

    by_depth = inventory.get("by_depth", {})
    for depth in ("Global", "Deep", "Local", "Basic", "None"):
        items = by_depth.get(depth, [])
        if not items:
            continue
        print(f"\n{depth} ({len(items)})")
        print("-" * (len(depth) + len(str(len(items))) + 3))
        for item in items:
            name = item.get("name") or item.get("privilege_id")
            labels = privilege_source_labels(item.get("sources", []))
            source = "; ".join(labels) if labels else "source not resolved"
            line = f"- {name} | {source}"
            reported = item.get("user_reported_depth")
            effective = item.get("depth")
            if reported and effective and reported != effective:
                line += f" | user API depth: {reported}"
            print(line)

    role_only = inventory.get("role_derived_not_reported", [])
    if role_only:
        print("\nRole-derived but not returned by RetrieveUserPrivileges")
        print("------------------------------------------------------")
        for item in role_only:
            name = item.get("name") or item.get("privilege_id")
            depth = item.get("depth") or "None"
            labels = privilege_source_labels(item.get("sources", []))
            source = "; ".join(labels) if labels else "source not resolved"
            print(f"- [{depth}] {name} | {source}")


def print_role_privilege_summary(security: dict[str, Any]) -> None:
    """Display role sources and privilege counts without dumping every privilege."""
    direct = security.get("direct_roles", {})
    memberships = security.get("team_memberships", {})
    owner_roles = security.get("owner_team_roles", {})
    role_privileges = security.get("role_privileges", {})
    user_privileges = security.get("reported_user_privileges", {})
    cross_check = security.get("cross_check", {})

    print("\nRoles and privileges")
    print("--------------------")
    print(f"Direct roles       : {direct.get('role_count', 0)}")
    print(f"Owner teams        : {memberships.get('owner_team_count', 0)}")
    print(f"Access teams       : {memberships.get('access_team_count', 0)}")
    print(f"Inherited roles    : {owner_roles.get('inherited_role_count', 0)}")
    print(f"Unique roles       : {security.get('unique_role_count', 0)}")
    print(
        "Role privileges    : "
        f"{role_privileges.get('privilege_assignment_count', 0)} assignment(s)"
    )
    print(
        "Role-derived privileges: "
        f"{security.get('role_derived_privilege_count', security.get('calculated_effective_privilege_count', 0))}"
    )
    print(
        "User-confirmed       : "
        f"{user_privileges.get('privilege_count', 0)}"
    )
    print(
        "Unresolved names    : "
        f"{role_privileges.get('unresolved_name_count', 0)}"
    )
    relationship_counts = role_privileges.get("role_relationships", {})
    if relationship_counts:
        print(
            "Role relationships: "
            f"{relationship_counts.get('populated', 0)} populated, "
            f"{relationship_counts.get('empty', 0)} empty, "
            f"{relationship_counts.get('unavailable', 0)} unavailable"
        )

    direct_roles = direct.get("roles", [])
    owner_teams = owner_roles.get("teams", [])
    if direct_roles or owner_teams:
        print("\nRole assignments")
        print("----------------")
        if direct_roles:
            print("Direct:")
            for role in direct_roles:
                print(f"- {role.get('name') or role.get('role_id')}")
        if owner_teams:
            print("Owner teams:")
            for team in owner_teams:
                team_name = team.get("name") or team.get("team_id")
                roles = team.get("roles", [])
                if roles:
                    names = ", ".join(
                        str(role.get("name") or role.get("role_id"))
                        for role in roles
                    )
                    print(f"- {team_name}: {names}")
                else:
                    print(f"- {team_name}: no assigned roles")

    manual_only = cross_check.get("role_derived_only", cross_check.get("calculated_only", []))
    reported_only = cross_check.get("user_reported_only", cross_check.get("reported_only", []))
    depth_differences = cross_check.get("depth_differences", [])
    print("\nPrivilege cross-check")
    print("---------------------")
    print(f"Role-derived only : {len(manual_only)}")
    print(f"User API only     : {len(reported_only)}")
    print(f"Depth differences : {len(depth_differences)}")

    boundary = security.get("scope_boundary", {})
    if boundary:
        print("\nScope boundary")
        print("--------------")
        print(boundary.get("statement"))
        print("Not covered yet: field-level security, record sharing/access teams, hierarchy reach, and ownership/cascading access.")

    inventory = security.get("privilege_inventory", {})
    if isinstance(inventory, dict):
        print_privilege_inventory(inventory)


def print_summary(results: dict[str, Any], output_path: Path) -> None:
    identity = results["identity"]
    target = results["target"]
    version = target.get("server_version") or "unavailable"
    organization = results.get("organization", {})

    if organization.get("status") == "success":
        organization_name = organization.get("name") or "unavailable"
        organization_summary = (
            f"{organization.get('relevant_field_count', 0)} relevant setting(s)"
        )
        signals = organization.get("security_signals", [])
        checks_not_evaluated = organization.get("checks_not_evaluated", [])
        orgdb = organization.get("orgdborgsettings", {})
        if not isinstance(signals, list):
            signals = []
    else:
        organization_name = "unavailable"
        organization_summary = "unavailable"
        signals = []
        checks_not_evaluated = []
        orgdb = {}

    print("\nDynamics 365")
    print("------------")
    print(f"Name             : {organization_name}")
    print(f"URL              : {target['display_url']}")
    print(f"Server version   : {version}")
    print(f"API version      : {target['api_version']}")
    print(f"User ID          : {identity['UserId']}")
    print(f"Business Unit ID : {identity['BusinessUnitId']}")
    print(f"Organization ID  : {identity['OrganizationId']}")
    print(f"Organization     : {organization_summary}")
    print(f"Potential insecure: {len(signals)}")
    print(f"Checks not eval. : {len(checks_not_evaluated)}")
    if orgdb:
        print(f"OrgDb settings   : {orgdb.get('setting_count', 0)} parsed ({orgdb.get('status', 'unknown')})")

    print_review_signals(signals)
    print_checks_not_evaluated(checks_not_evaluated)
    security = results.get("security", {})
    if isinstance(security, dict):
        print_role_privilege_summary(security)
    custom_entities = results.get("entity_access", results.get("custom_entities", {}))
    if isinstance(custom_entities, dict):
        print_entity_access(custom_entities)
    secret_scan = results.get("secret_scan", {})
    if isinstance(secret_scan, dict):
        print("\nSecrets and configuration")
        print("-------------------------")
        print(f"Status            : {secret_scan.get('status', 'unknown')}")
        print(f"Candidate entities: {secret_scan.get('candidate_entity_count', 0)}")
        print(f"Records inspected : {secret_scan.get('records_inspected', 0)}")
        print(f"Flagged values    : {secret_scan.get('finding_count', 0)}")
    print(f"\nSaved to: {output_path}")



def print_compact_summary(results: dict[str, Any], output_path: Path) -> None:
    """Print a compact CLI summary; detailed results belong in JSON/dashboard."""
    target = results.get("target", {})
    identity = results.get("identity", {})
    organization = results.get("organization", {})
    security = results.get("security", {})
    entity_access = results.get("entity_access", results.get("custom_entities", {}))
    inventory = security.get("privilege_inventory", {}) if isinstance(security, dict) else {}
    inventory_summary = inventory.get("summary", {}) if isinstance(inventory, dict) else {}
    counts = entity_access.get("probe_status_counts", {}) if isinstance(entity_access, dict) else {}

    print("\nDynamics 365 Enumeration")
    print("========================")
    print(f"Organization        : {organization.get('name') or target.get('organization_name') or 'unknown'}")
    print(f"Target              : {target.get('display_url') or target.get('base_url') or 'unknown'}")
    print(f"API                 : {target.get('api_version') or 'unknown'}")
    print(f"Server version      : {target.get('server_version') or 'unavailable'}")
    print(f"User                : {identity.get('UserId') or 'unknown'}")
    print(f"Held privileges     : {inventory_summary.get('held_count', 0)}")
    print(f"Direct roles        : {security.get('direct_roles', {}).get('role_count', 0) if isinstance(security, dict) else 0}")
    print(f"Inherited roles     : {security.get('owner_team_roles', {}).get('inherited_role_count', 0) if isinstance(security, dict) else 0}")
    print(f"Default entities    : {entity_access.get('sensitive_standard_entity_count', 0) if isinstance(entity_access, dict) else 0}")
    print(f"Custom entities     : {entity_access.get('custom_entity_count', 0) if isinstance(entity_access, dict) else 0}")
    print(f"Readable with data  : {counts.get('READABLE_WITH_DATA', 0)}")
    print(f"No visible data     : {counts.get('READABLE_EMPTY_OR_FILTERED', 0)}")
    print(f"Access denied       : {counts.get('ACCESS_DENIED', 0)}")
    print(f"Potential insecure  : {len(organization.get('security_signals', [])) if isinstance(organization, dict) else 0}")
    secret_scan = results.get("secret_scan", {})
    print(f"Secret/config flags : {secret_scan.get('finding_count', 0) if isinstance(secret_scan, dict) else 0}")
    print(f"\nResults saved to   : {output_path}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Authenticate to Dynamics 365 and save initial enumeration data."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {PROJECT_VERSION}")
    parser.add_argument(
        "base_url",
        help="CRM organization URL, for example https://host/OrgName",
    )
    parser.add_argument(
        "--api-version",
        default="auto",
        help="Dynamics Web API version, e.g. v9.0, v9.1, v9.2 (default: auto-detect)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("d365_enum.json"),
        help="JSON output file (default: d365_enum.json)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify server TLS certificates",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the full CLI output instead of the compact summary",
    )
    parser.add_argument(
        "--entity-counts",
        action="store_true",
        help="Request @odata.count for each entity probe (slower; counts only records visible to this user)",
    )
    parser.add_argument(
        "--no-secret-scan",
        action="store_true",
        help="Skip the metadata-driven secrets and configuration scan",
    )
    parser.add_argument(
        "--secret-scan-limit",
        type=int,
        default=200,
        help="Maximum records inspected per candidate entity; 0 follows all pages (default: 200)",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the localhost dashboard after enumeration",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8765,
        help="Local dashboard port (default: 8765)",
    )
    args = parser.parse_args()
    if args.secret_scan_limit < 0:
        parser.error("--secret-scan-limit must be 0 or greater")

    base_url = args.base_url.rstrip("/")
    if not args.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cookies = capture_browser_session(base_url, args.verify)
    session = build_session(cookies)

    api_detection = detect_api_endpoint(
        session,
        base_url,
        args.verify,
        args.api_version,
    )
    api_base = api_detection["api_base"]
    api_version = api_detection["api_version"]
    identity = api_detection["identity"]
    version_result = query_version(session, api_base, args.verify)
    organization_result = query_organization(
        session,
        api_base,
        args.verify,
        identity["OrganizationId"],
    )
    security_result = query_security_roles_and_privileges(
        session,
        api_base,
        args.verify,
        identity["UserId"],
    )
    entity_access_result = query_entity_access(
        session,
        api_base,
        args.verify,
        security_result,
        include_counts=args.entity_counts,
    )
    if args.no_secret_scan:
        secret_scan_result: dict[str, Any] = {
            "status": "disabled",
            "reason": "Disabled with --no-secret-scan",
            "findings": [],
            "finding_count": 0,
        }
    else:
        secret_scan_result = query_secret_configuration_scan(
            session,
            api_base,
            args.verify,
            entity_access_result,
            record_limit=args.secret_scan_limit,
        )

    results: dict[str, Any] = {
        "target": {
            "display_url": base_url,
            "base_url": base_url,
            "api_version": api_version,
            "api_base_url": api_base,
            "api_detection": api_detection,
            "server_version": version_result.get("version"),
            "retrieve_version": version_result,
            "organization_name": organization_result.get("name"),
        },
        "identity": identity,
        "organization": organization_result,
        "security": security_result,
        "entity_access": entity_access_result,
        "custom_entities": entity_access_result,
        "secret_scan": secret_scan_result,
    }

    save_results(results, args.output)
    if args.verbose:
        print_summary(results, args.output)
    else:
        print_compact_summary(results, args.output)

    if args.dashboard:
        if not 1 <= args.dashboard_port <= 65535:
            parser.error("--dashboard-port must be between 1 and 65535")
        try:
            from d365_dashboard import serve_dashboard
        except ImportError as exc:
            sys.exit(
                "Dashboard module not found. Keep d365_dashboard.py in the same "
                f"directory as this script. ({exc})"
            )
        serve_dashboard(args.output, port=args.dashboard_port, open_browser=True)


if __name__ == "__main__":
    main()
