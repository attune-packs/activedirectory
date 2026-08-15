"""Validated, bounded WinRM transport for a fixed Active Directory program."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_CREDENTIAL_KEY = "activedirectory.credentials"
MAX_INPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DNS = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")
_DN = re.compile(r"^(?i:(?:CN|OU|DC)=).+,(?i:DC=)[^,]+$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ActiveDirectoryPackError(Exception):
    """An action-safe error that never contains remote output or credentials."""


COMMON_FIELDS = {"credential_key", "timeout_seconds"}

# Contract fields are intentionally explicit. There is no generic argument,
# filter, property, credential, script, or command passthrough.
ACTION_FIELDS: dict[str, set[str]] = {
    "user_get": {"object_id"},
    "user_search": {"search_base", "search_scope", "name_prefix", "sam_account_name", "user_principal_name", "enabled", "max_results"},
    "user_create": {"expected_host", "path_dn", "name", "sam_account_name", "user_principal_name", "display_name", "given_name", "surname", "description", "email", "initial_password", "enabled"},
    "user_update": {"expected_host", "object_id", "display_name", "given_name", "surname", "description", "email"},
    "user_enable": {"expected_host", "object_id"},
    "user_disable": {"expected_host", "object_id", "confirmation"},
    "user_unlock": {"expected_host", "object_id"},
    "user_password_reset": {"expected_host", "object_id", "new_password", "force_change_at_logon", "confirmation"},
    "user_expiration_set": {"expected_host", "object_id", "expiration_utc", "clear_expiration"},
    "user_delete": {"expected_host", "object_id", "confirmation"},
    "group_get": {"object_id"},
    "group_search": {"search_base", "search_scope", "name_prefix", "sam_account_name", "group_scope", "group_category", "max_results"},
    "group_create": {"expected_host", "path_dn", "name", "sam_account_name", "group_scope", "group_category", "description"},
    "group_update": {"expected_host", "object_id", "display_name", "description"},
    "group_delete": {"expected_host", "object_id", "confirmation"},
    "group_member_add": {"expected_host", "group_id", "member_id", "confirmation"},
    "group_member_remove": {"expected_host", "group_id", "member_id", "confirmation"},
    "group_member_list": {"group_id", "max_results"},
    "computer_get": {"object_id"},
    "computer_search": {"search_base", "search_scope", "name_prefix", "dns_host_name", "enabled", "max_results"},
    "computer_create": {"expected_host", "path_dn", "name", "dns_host_name", "description", "enabled"},
    "computer_update": {"expected_host", "object_id", "dns_host_name", "description", "location"},
    "computer_enable": {"expected_host", "object_id"},
    "computer_disable": {"expected_host", "object_id", "confirmation"},
    "computer_move": {"expected_host", "object_id", "target_path_dn", "confirmation"},
    "computer_delete": {"expected_host", "object_id", "confirmation"},
    "ou_get": {"object_id"},
    "ou_search": {"search_base", "search_scope", "name_prefix", "max_results"},
    "ou_create": {"expected_host", "path_dn", "name", "description", "protected_from_accidental_deletion"},
    "ou_update": {"expected_host", "object_id", "description", "protected_from_accidental_deletion"},
    "ou_move": {"expected_host", "object_id", "target_path_dn", "confirmation"},
    "ou_delete": {"expected_host", "object_id", "confirmation"},
    "service_account_get": {"object_id"},
    "service_account_search": {"search_base", "search_scope", "name_prefix", "enabled", "max_results"},
    "service_account_create": {"expected_host", "path_dn", "name", "dns_host_name", "description", "enabled", "managed_password_interval_days"},
    "service_account_update": {"expected_host", "object_id", "display_name", "description"},
    "service_account_delete": {"expected_host", "object_id", "confirmation"},
    "domain_get": set(),
    "forest_get": set(),
    "default_password_policy_get": set(),
    "fine_grained_password_policy_search": {"max_results"},
    "user_resultant_password_policy_get": {"object_id"},
    "principal_lookup": {"object_id"},
    "principal_group_memberships": {"object_id", "max_results"},
}

READ_ACTIONS = {
    "user_get", "user_search", "group_get", "group_search", "group_member_list",
    "computer_get", "computer_search", "ou_get", "ou_search", "service_account_get",
    "service_account_search", "domain_get", "forest_get", "default_password_policy_get",
    "fine_grained_password_policy_search", "user_resultant_password_policy_get",
    "principal_lookup", "principal_group_memberships",
}
MUTATING_ACTIONS = set(ACTION_FIELDS) - READ_ACTIONS
REQUIRED_FIELDS: dict[str, set[str]] = {
    "user_get": {"object_id"}, "user_create": {"path_dn", "name", "sam_account_name"},
    "user_update": {"object_id"}, "user_enable": {"object_id"},
    "user_disable": {"object_id", "confirmation"}, "user_unlock": {"object_id"},
    "user_password_reset": {"object_id", "new_password", "confirmation"},
    "user_expiration_set": {"object_id"}, "user_delete": {"object_id", "confirmation"},
    "group_get": {"object_id"}, "group_create": {"path_dn", "name", "sam_account_name", "group_scope", "group_category"},
    "group_update": {"object_id"}, "group_delete": {"object_id", "confirmation"},
    "group_member_add": {"group_id", "member_id", "confirmation"},
    "group_member_remove": {"group_id", "member_id", "confirmation"}, "group_member_list": {"group_id"},
    "computer_get": {"object_id"}, "computer_create": {"path_dn", "name"},
    "computer_update": {"object_id"}, "computer_enable": {"object_id"},
    "computer_disable": {"object_id", "confirmation"},
    "computer_move": {"object_id", "target_path_dn", "confirmation"},
    "computer_delete": {"object_id", "confirmation"}, "ou_get": {"object_id"},
    "ou_create": {"path_dn", "name"}, "ou_update": {"object_id"},
    "ou_move": {"object_id", "target_path_dn", "confirmation"},
    "ou_delete": {"object_id", "confirmation"}, "service_account_get": {"object_id"},
    "service_account_create": {"path_dn", "name", "dns_host_name"},
    "service_account_update": {"object_id"},
    "service_account_delete": {"object_id", "confirmation"},
    "user_resultant_password_policy_get": {"object_id"}, "principal_lookup": {"object_id"},
    "principal_group_memberships": {"object_id"},
}

BOOLEAN_FIELDS = {"enabled", "force_change_at_logon", "clear_expiration", "protected_from_accidental_deletion"}
IDENTITY_FIELDS = {"object_id", "group_id", "member_id"}
DN_FIELDS = {"path_dn", "target_path_dn", "search_base"}
DNS_FIELDS = {"expected_host", "dns_host_name", "user_principal_name"}
STRING_FIELDS = {
    "name", "name_prefix", "sam_account_name", "display_name", "given_name", "surname",
    "description", "email", "location", "confirmation", "initial_password", "new_password",
}
ENUM_VALUES = {
    "search_scope": {"Base", "OneLevel", "Subtree"},
    "group_scope": {"DomainLocal", "Global", "Universal"},
    "group_category": {"Distribution", "Security"},
}
INTEGER_RANGES = {"timeout_seconds": (5, 900), "max_results": (1, 500), "managed_password_interval_days": (1, 365)}


def _fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise ActiveDirectoryPackError("credential_key must be a non-empty string")
    if not key_ref.startswith("activedirectory."):
        raise ActiveDirectoryPackError("credential_key must reference the activedirectory. Key namespace")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:  # noqa: BLE001 - SDK exceptions can contain Key data
        raise ActiveDirectoryPackError(f"could not read Active Directory credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise ActiveDirectoryPackError("Active Directory credential Key was not found")
        raise ActiveDirectoryPackError(f"could not read Active Directory credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise ActiveDirectoryPackError("Active Directory credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise ActiveDirectoryPackError("Active Directory credential Key must contain an object")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ActiveDirectoryPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _string(value: Any, name: str, maximum: int = 256, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value) > maximum or any(ord(c) < 32 for c in value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ActiveDirectoryPackError(f"{name} must be {qualifier} of at most {maximum} characters without controls")
    return value


def _dns(value: Any, name: str) -> str:
    value = _string(value, name, 253)
    if not _DNS.fullmatch(value):
        raise ActiveDirectoryPackError(f"{name} must be a DNS name without a URL, port, wildcard, or IP literal")
    return value.lower()


def _dn(value: Any, name: str) -> str:
    value = _string(value, name, 2048)
    if not _DN.fullmatch(value) or value.endswith("\\"):
        raise ActiveDirectoryPackError(f"{name} must be a distinguished name ending in a multi-label DC suffix")
    return value


def _identity(value: Any, name: str) -> str:
    value = _string(value, name, 2048)
    if _GUID.fullmatch(value):
        return value.lower()
    return _dn(value, name)


def _within(dn: str, base: str) -> bool:
    dn_folded, base_folded = dn.casefold(), base.casefold()
    return dn_folded == base_folded or dn_folded.endswith("," + base_folded)


def _validate_params(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    if operation not in ACTION_FIELDS:
        raise ActiveDirectoryPackError("unsupported Active Directory action")
    unknown = set(params) - COMMON_FIELDS - ACTION_FIELDS[operation]
    if unknown:
        raise ActiveDirectoryPackError("action parameters contain unsupported fields")
    clean = dict(params)
    missing = REQUIRED_FIELDS.get(operation, set()) - {key for key, value in clean.items() if value is not None}
    if missing:
        raise ActiveDirectoryPackError("action parameters are missing required fields")
    for name in BOOLEAN_FIELDS:
        if name in clean and clean[name] is not None and not isinstance(clean[name], bool):
            raise ActiveDirectoryPackError(f"{name} must be a boolean")
    for name, choices in ENUM_VALUES.items():
        if name in clean and clean[name] is not None and (not isinstance(clean[name], str) or clean[name] not in choices):
            raise ActiveDirectoryPackError(f"{name} is invalid")
    for name, bounds in INTEGER_RANGES.items():
        if name in clean and clean[name] is not None:
            clean[name] = _integer(clean[name], name, *bounds)
    for name in IDENTITY_FIELDS:
        if name in clean and clean[name] is not None:
            clean[name] = _identity(clean[name], name)
    for name in DN_FIELDS:
        if name in clean and clean[name] is not None:
            clean[name] = _dn(clean[name], name)
    for name in DNS_FIELDS:
        if name in clean and clean[name] is not None:
            if name == "user_principal_name":
                value = _string(clean[name], name, 256)
                if value.count("@") != 1 or not _DNS.fullmatch(value.rsplit("@", 1)[1]):
                    raise ActiveDirectoryPackError("user_principal_name must be a valid user@dns-domain value")
                clean[name] = value
            else:
                clean[name] = _dns(clean[name], name)
    for name in STRING_FIELDS:
        if name in clean and clean[name] is not None:
            maximum = 2048 if name == "confirmation" else (1024 if name in {"initial_password", "new_password"} else 256)
            clean[name] = _string(clean[name], name, maximum, allow_empty=name in {"description", "email", "location"})
    if "expiration_utc" in clean and clean["expiration_utc"] is not None:
        value = _string(clean["expiration_utc"], "expiration_utc", 20)
        if not _UTC.fullmatch(value):
            raise ActiveDirectoryPackError("expiration_utc must use YYYY-MM-DDTHH:MM:SSZ")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ActiveDirectoryPackError("expiration_utc must be a valid UTC timestamp") from None
    if operation in MUTATING_ACTIONS and clean.get("expected_host") is None:
        raise ActiveDirectoryPackError("expected_host is required for mutating actions")
    if operation in {"user_update", "group_update", "computer_update", "ou_update", "service_account_update"}:
        modeled = ACTION_FIELDS[operation] - {"expected_host", "object_id"}
        if not any(clean.get(field) is not None for field in modeled):
            raise ActiveDirectoryPackError("at least one modeled update field is required")
    if operation == "user_create" and clean.get("enabled") is True and clean.get("initial_password") is None:
        raise ActiveDirectoryPackError("enabled user creation requires initial_password")
    if operation == "user_expiration_set":
        if (clean.get("expiration_utc") is None) == (clean.get("clear_expiration") is not True):
            raise ActiveDirectoryPackError("supply expiration_utc or set clear_expiration true, but not both")
    clean["timeout_seconds"] = _integer(clean.get("timeout_seconds", 120), "timeout_seconds", 5, 900)
    if "max_results" in ACTION_FIELDS[operation]:
        clean["max_results"] = _integer(clean.get("max_results", 100), "max_results", 1, 500)
    if "search_scope" in ACTION_FIELDS[operation] and clean.get("search_scope") is None:
        clean["search_scope"] = "Subtree"
    return clean


def _confirmation_text(operation: str, params: dict[str, Any]) -> str | None:
    host = params.get("expected_host")
    identities = {
        "user_disable": ("DISABLE_USER", "object_id"), "user_password_reset": ("RESET_PASSWORD", "object_id"),
        "user_delete": ("DELETE_USER", "object_id"), "group_delete": ("DELETE_GROUP", "object_id"),
        "computer_disable": ("DISABLE_COMPUTER", "object_id"), "computer_delete": ("DELETE_COMPUTER", "object_id"),
        "ou_delete": ("DELETE_OU", "object_id"), "service_account_delete": ("DELETE_SERVICE_ACCOUNT", "object_id"),
    }
    if operation in identities:
        verb, field = identities[operation]
        return f"{verb}:{host}:{params[field]}"
    if operation in {"computer_move", "ou_move"}:
        verb = "MOVE_COMPUTER" if operation == "computer_move" else "MOVE_OU"
        return f"{verb}:{host}:{params['object_id']}:{params['target_path_dn']}"
    if operation in {"group_member_add", "group_member_remove"}:
        verb = "ADD_GROUP_MEMBER" if operation == "group_member_add" else "REMOVE_GROUP_MEMBER"
        return f"{verb}:{host}:{params['group_id']}:{params['member_id']}"
    return None


def _validate_confirmation(operation: str, params: dict[str, Any]) -> None:
    expected = _confirmation_text(operation, params)
    if expected is not None and params.get("confirmation") != expected:
        raise ActiveDirectoryPackError(f"confirmation must exactly equal {expected}")


def _credential_settings(credential: dict[str, Any], operation: str, params: dict[str, Any]) -> dict[str, Any]:
    allowed = {"host", "port", "username", "password", "auth", "verify_tls", "ca_cert", "domain_dns_name", "base_dn", "allowed_search_bases"}
    if set(credential) - allowed:
        raise ActiveDirectoryPackError("Active Directory credential Key contains unsupported fields")
    host = _dns(credential.get("host"), "credential host")
    domain = _dns(credential.get("domain_dns_name"), "credential domain_dns_name")
    base_dn = _dn(credential.get("base_dn"), "credential base_dn")
    expected_base = ",".join(f"DC={label}" for label in domain.split("."))
    if base_dn.casefold() != expected_base.casefold():
        raise ActiveDirectoryPackError("credential base_dn does not match domain_dns_name")
    auth = credential.get("auth", "kerberos")
    if auth not in {"kerberos", "ntlm"}:
        raise ActiveDirectoryPackError("credential auth must be kerberos or ntlm; Basic and CredSSP are not supported")
    username = _string(credential.get("username"), "credential username", 256)
    password = credential.get("password")
    if auth == "ntlm" and (not isinstance(password, str) or not 1 <= len(password) <= 4096):
        raise ActiveDirectoryPackError("credential password of 1 through 4096 characters is required for ntlm")
    if auth == "kerberos" and password is not None:
        raise ActiveDirectoryPackError("Kerberos uses the worker ticket cache; password is not accepted in the Key")
    if credential.get("verify_tls", True) is not True:
        raise ActiveDirectoryPackError("TLS certificate verification cannot be disabled")
    port = _integer(credential.get("port", 5986), "credential port", 1, 65535)
    ca_cert = credential.get("ca_cert")
    if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip() or len(ca_cert) > 1024 * 1024):
        raise ActiveDirectoryPackError("credential ca_cert must be a non-empty PEM string no larger than 1 MiB")
    bases_value = credential.get("allowed_search_bases", [base_dn])
    if not isinstance(bases_value, list) or not 1 <= len(bases_value) <= 32:
        raise ActiveDirectoryPackError("credential allowed_search_bases must be an array of 1 through 32 distinguished names")
    bases: list[str] = []
    for value in bases_value:
        parsed = _dn(value, "credential allowed_search_base")
        if not _within(parsed, base_dn):
            raise ActiveDirectoryPackError("credential allowed_search_base is outside base_dn")
        bases.append(parsed)
    for name in DN_FIELDS | IDENTITY_FIELDS:
        value = params.get(name)
        if isinstance(value, str) and not _GUID.fullmatch(value) and not any(_within(value, base) for base in bases):
            raise ActiveDirectoryPackError(f"{name} is outside the profile's allowed search bases")
    if operation in MUTATING_ACTIONS and params["expected_host"] != host:
        raise ActiveDirectoryPackError("expected_host does not match the credential profile host")
    return {
        "host": host, "port": port, "username": username, "password": password, "auth": auth,
        "ca_cert": ca_cert, "domain_dns_name": domain, "base_dn": base_dn, "allowed_search_bases": bases,
    }


def _load_script() -> str:
    return Path(__file__).with_name("activedirectory.ps1").read_text(encoding="utf-8")


def _contains_secret_key(value: Any, depth: int = 0) -> bool:
    if depth > 12:
        return True
    if isinstance(value, dict):
        forbidden = {"password", "unicodepwd", "supplementalcredentials", "managedpassword", "initialpassword", "newpassword"}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in forbidden or normalized.endswith("managedpassword") or _contains_secret_key(item, depth + 1):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_secret_key(item, depth + 1) for item in value)
    return False


def _run_winrm(settings: dict[str, Any], payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    try:
        from winrm.exceptions import WinRMOperationTimeoutError
        from winrm.protocol import Protocol
    except ImportError:
        raise ActiveDirectoryPackError("pywinrm runtime dependency is unavailable") from None
    wire_payload = dict(payload)
    wire_payload["target"] = {
        "host": settings["host"], "domain_dns_name": settings["domain_dns_name"],
        "base_dn": settings["base_dn"], "allowed_search_bases": settings["allowed_search_bases"],
    }
    raw_payload = json.dumps(wire_payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(raw_payload) > MAX_INPUT_BYTES:
        raise ActiveDirectoryPackError("encoded action parameters exceed the 64 KiB limit")
    environment = {"ATTUNE_AD_INPUT_B64": base64.b64encode(raw_payload).decode("ascii")}
    encoded_script = base64.b64encode(_load_script().encode("utf-16-le")).decode("ascii")
    operation_timeout = min(20, max(4, timeout_seconds - 2))
    protocol_kwargs: dict[str, Any] = {
        "endpoint": f"https://{settings['host']}:{settings['port']}/wsman", "transport": settings["auth"],
        "username": settings["username"], "password": settings["password"], "server_cert_validation": "validate",
        "operation_timeout_sec": operation_timeout, "read_timeout_sec": operation_timeout + 10,
        "message_encryption": "auto", "kerberos_delegation": False, "proxy": None,
        "send_cbt": True,
    }
    stdout, stderr = bytearray(), bytearray()
    shell_id = command_id = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="attune-activedirectory-") as directory:
            if settings["ca_cert"]:
                ca_path = Path(directory, "ca.pem")
                ca_path.write_text(settings["ca_cert"], encoding="utf-8")
                os.chmod(ca_path, 0o600)
                protocol_kwargs["ca_trust_path"] = str(ca_path)
            protocol = Protocol(**protocol_kwargs)
            shell_id = protocol.open_shell(env_vars=environment, noprofile=True, codepage=65001)
            command_id = protocol.run_command(shell_id, "powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script], skip_cmd_shell=True)
            while True:
                if time.monotonic() - started > timeout_seconds:
                    raise ActiveDirectoryPackError("Active Directory action exceeded its bounded timeout")
                try:
                    out, err, status, done = protocol.get_command_output_raw(shell_id, command_id)
                except WinRMOperationTimeoutError:
                    continue
                stdout.extend(out)
                stderr.extend(err)
                if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
                    raise ActiveDirectoryPackError("Active Directory action output exceeded the 4 MiB limit")
                if done:
                    if status != 0:
                        raise ActiveDirectoryPackError("Active Directory host rejected the operation")
                    break
            protocol.cleanup_command(shell_id, command_id)
            command_id = None
            protocol.close_shell(shell_id)
            shell_id = None
    except ActiveDirectoryPackError:
        raise
    except Exception as exc:  # noqa: BLE001 - WinRM errors may include headers or bodies
        raise ActiveDirectoryPackError(f"WinRM request failed ({type(exc).__name__})") from None
    finally:
        if "protocol" in locals():
            if command_id is not None and shell_id is not None:
                try:
                    protocol.cleanup_command(shell_id, command_id)
                except Exception:  # noqa: BLE001
                    pass
            if shell_id is not None:
                try:
                    protocol.close_shell(shell_id)
                except Exception:  # noqa: BLE001
                    try:
                        protocol.transport.close_session()
                    except Exception:  # noqa: BLE001
                        pass
    try:
        result = json.loads(stdout.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ActiveDirectoryPackError("Active Directory host returned invalid structured output") from None
    expected_keys = {"operation", "target_host", "target_domain", "data", "meta"}
    if not isinstance(result, dict) or set(result) != expected_keys:
        raise ActiveDirectoryPackError("Active Directory host returned an unexpected output schema")
    if not all(isinstance(result[name], str) for name in ("operation", "target_host", "target_domain")) or not isinstance(result["meta"], dict):
        raise ActiveDirectoryPackError("Active Directory host returned invalid structured output types")
    if result["operation"] != payload["operation"]:
        raise ActiveDirectoryPackError("Active Directory host returned an output operation mismatch")
    if result["target_host"].casefold() != settings["host"].casefold():
        raise ActiveDirectoryPackError("Active Directory host returned a host identity mismatch")
    if result["target_domain"].casefold() != settings["domain_dns_name"].casefold():
        raise ActiveDirectoryPackError("Active Directory host returned a domain identity mismatch")
    if _contains_secret_key(result):
        raise ActiveDirectoryPackError("Active Directory host returned prohibited sensitive output")
    return result


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    clean = _validate_params(operation, params)
    _validate_confirmation(operation, clean)
    key_ref = clean.pop("credential_key", DEFAULT_CREDENTIAL_KEY)
    timeout = clean.pop("timeout_seconds")
    settings = _credential_settings(_fetch_key(key_ref), operation, clean)
    clean["operation"] = operation
    return _run_winrm(settings, clean, timeout)
