from __future__ import annotations

import base64
import io
import json
import os
import re
import sys
import types
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import activedirectory_client as client

USER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
GROUP_ID = "11111111-2222-4333-8444-555555555555"
BASE_DN = "DC=example,DC=com"
USERS_DN = "OU=Users,DC=example,DC=com"


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {path.stem: path.read_text(encoding="utf-8") for path in sorted((ROOT / "actions").glob("*.yaml"))}

    def test_curated_action_inventory(self):
        self.assertEqual(set(client.ACTION_FIELDS), set(self.actions))
        self.assertEqual(44, len(self.actions))

    def test_all_contracts_are_flat_json_with_structured_output(self):
        forbidden = re.compile(r"(?m)^  (args|arguments|script|command|shell|filter|ldap_filter|username|password|credential):")
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"activedirectory.{name}", "runner_type": "python", "runtime_version": '">=3.10"',
                    "entry_point": "activedirectory_action.py", "parameter_delivery": "stdin",
                    "parameter_format": "json", "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: activedirectory\.credentials[^\n]*\}")
                for field in ("operation", "target_host", "target_domain", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, forbidden)

    def test_contract_fields_match_runtime_allowlists(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                block = text.split("parameters:", 1)[1].split("\noutput:", 1)[0]
                fields = set(re.findall(r"(?m)^  ([a-z][a-z0-9_]*):", block))
                self.assertEqual(client.COMMON_FIELDS | client.ACTION_FIELDS[name], fields)

    def test_password_contracts_mark_inputs_secret_and_never_model_password_output(self):
        self.assertIn("initial_password: {type: string, secret: true", self.actions["user_create"])
        self.assertIn("new_password: {type: string, secret: true", self.actions["user_password_reset"])
        for text in self.actions.values():
            output = text.split("\noutput:", 1)[1]
            self.assertNotRegex(output, r"(?i)password")

    def test_source_version_license_notice_and_docs_revision(self):
        revision = "2bdf09685f3d80e514eb5b586b344d41b35f063c"
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        source = (ROOT / "SOURCE.md").read_text(encoding="utf-8")
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.0.1"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(revision, source)
        self.assertIn("0ef3f225d29e26d1cf3119f37dfff70bb6165746", source)
        self.assertIn(revision, (ROOT / "NOTICE").read_text(encoding="utf-8"))
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_powershell_is_constant_and_has_no_dynamic_execution_or_delegation(self):
        script = (ROOT / "lib" / "activedirectory.ps1").read_text(encoding="utf-8")
        for forbidden in ("Invoke-Expression", "ScriptBlock]::Create", "Start-Process", "cmd.exe", "Invoke-Command", "-Credential", "-Recursive"):
            self.assertNotIn(forbidden, script)
        self.assertIn("$env:ATTUNE_AD_INPUT_B64", script)
        self.assertIn("ConvertFrom-Json", script)
        self.assertIn("ConvertTo-Json -Compress", script)
        self.assertIn("ConvertTo-LdapFilterValue", script)
        self.assertIn("Assert-DnAllowed", script)
        self.assertIn("Assert-Confirmation", script)
        self.assertIn("nested group membership changes are not supported", script)
        self.assertNotIn("$script:Params.args", script)


class ValidationTests(unittest.TestCase):
    def test_arbitrary_execution_filter_and_privilege_fields_are_rejected(self):
        for field in ("args", "script", "command", "filter", "ldap_filter", "properties", "force", "recursive", "run_as"):
            with self.subTest(field=field), self.assertRaisesRegex(client.ActiveDirectoryPackError, "unsupported fields"):
                client._validate_params("user_get", {"object_id": USER_ID, field: "malicious"})

    def test_only_guid_or_dn_stable_identities_are_accepted(self):
        self.assertEqual(USER_ID, client._validate_params("user_get", {"object_id": USER_ID.upper()})["object_id"])
        dn = "CN=Alice,OU=Users,DC=example,DC=com"
        self.assertEqual(dn, client._validate_params("user_get", {"object_id": dn})["object_id"])
        for value in ("alice", "EXAMPLE\\alice", "S-1-5-21-1", "*", "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}", "CN=x\n,DC=example,DC=com"):
            with self.subTest(value=value), self.assertRaises(client.ActiveDirectoryPackError):
                client._validate_params("user_get", {"object_id": value})

    def test_mutations_require_host_and_modeled_updates(self):
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "expected_host"):
            client._validate_params("user_enable", {"object_id": USER_ID})
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "at least one"):
            client._validate_params("computer_update", {"expected_host": "dc01.example.com", "object_id": USER_ID})

    def test_password_and_expiration_conditions_are_strict(self):
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "initial_password"):
            client._validate_params("user_create", {
                "expected_host": "dc01.example.com", "path_dn": USERS_DN, "name": "Alice",
                "sam_account_name": "alice", "enabled": True,
            })
        for params in (
            {"expected_host": "dc01.example.com", "object_id": USER_ID},
            {"expected_host": "dc01.example.com", "object_id": USER_ID, "expiration_utc": "2026-08-15T00:00:00Z", "clear_expiration": True},
            {"expected_host": "dc01.example.com", "object_id": USER_ID, "expiration_utc": "2026-99-15T00:00:00Z"},
        ):
            with self.subTest(params=params), self.assertRaises(client.ActiveDirectoryPackError):
                client._validate_params("user_expiration_set", params)

    def test_all_destructive_and_membership_confirmations_bind_host_and_ids(self):
        cases = {
            "user_disable": ("object_id", USER_ID, f"DISABLE_USER:dc01.example.com:{USER_ID}"),
            "user_password_reset": ("object_id", USER_ID, f"RESET_PASSWORD:dc01.example.com:{USER_ID}"),
            "user_delete": ("object_id", USER_ID, f"DELETE_USER:dc01.example.com:{USER_ID}"),
            "group_delete": ("object_id", GROUP_ID, f"DELETE_GROUP:dc01.example.com:{GROUP_ID}"),
            "computer_disable": ("object_id", USER_ID, f"DISABLE_COMPUTER:dc01.example.com:{USER_ID}"),
            "computer_delete": ("object_id", USER_ID, f"DELETE_COMPUTER:dc01.example.com:{USER_ID}"),
            "ou_delete": ("object_id", USER_ID, f"DELETE_OU:dc01.example.com:{USER_ID}"),
            "service_account_delete": ("object_id", USER_ID, f"DELETE_SERVICE_ACCOUNT:dc01.example.com:{USER_ID}"),
        }
        for operation, (field, value, confirmation) in cases.items():
            params = {"expected_host": "dc01.example.com", field: value, "confirmation": confirmation}
            if operation == "user_password_reset":
                params["new_password"] = "not-logged"
            clean = client._validate_params(operation, params)
            client._validate_confirmation(operation, clean)
            clean["confirmation"] += " "
            with self.subTest(operation=operation), self.assertRaisesRegex(client.ActiveDirectoryPackError, "exactly equal"):
                client._validate_confirmation(operation, clean)
        move = client._validate_params("computer_move", {
            "expected_host": "dc01.example.com", "object_id": USER_ID, "target_path_dn": USERS_DN,
            "confirmation": f"MOVE_COMPUTER:dc01.example.com:{USER_ID}:{USERS_DN}",
        })
        client._validate_confirmation("computer_move", move)
        membership = client._validate_params("group_member_add", {
            "expected_host": "dc01.example.com", "group_id": GROUP_ID, "member_id": USER_ID,
            "confirmation": f"ADD_GROUP_MEMBER:dc01.example.com:{GROUP_ID}:{USER_ID}",
        })
        client._validate_confirmation("group_member_add", membership)

    def test_scalar_limits_and_search_scope_are_enforced(self):
        bad = [
            ("user_search", {"max_results": 501}), ("user_search", {"enabled": "true"}),
            ("group_search", {"group_scope": "Forest"}), ("user_search", {"search_scope": "GlobalCatalog"}),
        ]
        for operation, params in bad:
            with self.subTest(operation=operation, params=params), self.assertRaises(client.ActiveDirectoryPackError):
                client._validate_params(operation, params)


def profile(**changes):
    value = {
        "host": "dc01.example.com", "username": "svc-attune@EXAMPLE.COM", "auth": "kerberos",
        "domain_dns_name": "example.com", "base_dn": BASE_DN, "allowed_search_bases": [USERS_DN],
    }
    value.update(changes)
    return value


class CredentialTests(unittest.TestCase):
    def test_kerberos_uses_ticket_cache_and_rejects_password_or_unverified_tls(self):
        settings = client._credential_settings(profile(), "user_get", {"object_id": USER_ID})
        self.assertEqual("kerberos", settings["auth"])
        for value in (profile(password="secret"), profile(verify_tls=False), profile(auth="basic"), profile(auth="credssp", password="secret"), profile(kerberos_delegation=True)):
            with self.subTest(value=value), self.assertRaises(client.ActiveDirectoryPackError):
                client._credential_settings(value, "user_get", {"object_id": USER_ID})

    def test_ntlm_requires_password_and_mutation_host_match(self):
        ntlm = profile(auth="ntlm", username=r"EXAMPLE\svc-attune", password="secret")
        settings = client._credential_settings(ntlm, "user_enable", {"object_id": USER_ID, "expected_host": "dc01.example.com"})
        self.assertEqual("ntlm", settings["auth"])
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "does not match"):
            client._credential_settings(ntlm, "user_enable", {"object_id": USER_ID, "expected_host": "dc02.example.com"})
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "required for ntlm"):
            client._credential_settings(profile(auth="ntlm"), "user_get", {"object_id": USER_ID})
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "4096"):
            client._credential_settings(profile(auth="ntlm", password="x" * 4097), "user_get", {"object_id": USER_ID})

    def test_domain_and_allowed_base_constraints_prevent_wrong_domain_objects(self):
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "does not match domain"):
            client._credential_settings(profile(base_dn="DC=other,DC=com"), "user_get", {"object_id": USER_ID})
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "outside"):
            client._credential_settings(profile(), "user_get", {"object_id": "CN=Admin,CN=Users,DC=example,DC=com"})
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "outside"):
            client._credential_settings(profile(allowed_search_bases=["DC=other,DC=com"]), "user_get", {"object_id": USER_ID})

    def test_unknown_profile_fields_and_key_errors_are_redacted(self):
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "unsupported fields"):
            client._credential_settings(profile(run_as="admin"), "user_get", {"object_id": USER_ID})
        with self.assertRaisesRegex(client.ActiveDirectoryPackError, "activedirectory. Key namespace"):
            client._fetch_key("other.credentials")
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=mock.Mock(side_effect=RuntimeError("TOP-SECRET")))
        modules = {
            "attune": fake_attune, "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"), "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules), self.assertRaises(client.ActiveDirectoryPackError) as caught:
            client._fetch_key("activedirectory.credentials")
        self.assertNotIn("TOP-SECRET", str(caught.exception))


class FakeTimeout(Exception):
    pass


class FakeProtocol:
    instances: ClassVar[list["FakeProtocol"]] = []
    output = None
    timeout = False

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.cleaned, self.closed = [], []
        if isinstance(kwargs.get("ca_trust_path"), str):
            path = Path(kwargs["ca_trust_path"])
            self.ca_content = path.read_text(encoding="utf-8")
            self.ca_mode = path.stat().st_mode & 0o777
        self.__class__.instances.append(self)

    def open_shell(self, **kwargs):
        self.shell_kwargs = kwargs
        return "shell-id"

    def run_command(self, shell_id, executable, arguments, **kwargs):
        self.command = (shell_id, executable, list(arguments), kwargs)
        return "command-id"

    def get_command_output_raw(self, shell_id, command_id):
        if self.timeout:
            raise FakeTimeout()
        value = self.output or {
            "operation": "user_get", "target_host": "dc01.example.com", "target_domain": "example.com",
            "data": {"id": USER_ID}, "meta": {"changed": False, "retried": False},
        }
        return json.dumps(value).encode(), b"", 0, True

    def cleanup_command(self, shell_id, command_id):
        self.cleaned.append((shell_id, command_id))

    def close_shell(self, shell_id):
        self.closed.append(shell_id)


def winrm_modules():
    protocol = types.ModuleType("winrm.protocol")
    protocol.Protocol = FakeProtocol
    exceptions = types.ModuleType("winrm.exceptions")
    exceptions.WinRMOperationTimeoutError = FakeTimeout
    return {"winrm": types.ModuleType("winrm"), "winrm.protocol": protocol, "winrm.exceptions": exceptions}


class TransportTests(unittest.TestCase):
    def setUp(self):
        FakeProtocol.instances, FakeProtocol.output, FakeProtocol.timeout = [], None, False
        self.settings = {
            "host": "dc01.example.com", "port": 5986, "username": "svc@EXAMPLE.COM", "password": None,
            "auth": "kerberos", "ca_cert": "PRIVATE CA", "domain_dns_name": "example.com",
            "base_dn": BASE_DN, "allowed_search_bases": [USERS_DN],
        }

    def test_constant_script_and_out_of_band_json_prevent_injection(self):
        attack = "'); Remove-ADUser -Identity * -Confirm:$false; #\n$(Get-Content env:SECRET)"
        payload = {"operation": "user_get", "object_id": USER_ID, "name": attack}
        with mock.patch.dict(sys.modules, winrm_modules()):
            result = client._run_winrm(self.settings, payload, 30)
        self.assertEqual("user_get", result["operation"])
        instance = FakeProtocol.instances[0]
        self.assertEqual("validate", instance.kwargs["server_cert_validation"])
        self.assertFalse(instance.kwargs["kerberos_delegation"])
        self.assertTrue(instance.kwargs["send_cbt"])
        self.assertIsNone(instance.kwargs["proxy"])
        self.assertEqual("PRIVATE CA", instance.ca_content)
        self.assertEqual(0o600, instance.ca_mode)
        _, executable, arguments, options = instance.command
        self.assertEqual("powershell.exe", executable)
        self.assertTrue(options["skip_cmd_shell"])
        decoded_script = base64.b64decode(arguments[arguments.index("-EncodedCommand") + 1]).decode("utf-16-le")
        self.assertEqual((ROOT / "lib" / "activedirectory.ps1").read_text(encoding="utf-8"), decoded_script)
        self.assertNotIn(attack, decoded_script)
        self.assertNotIn(attack, " ".join(arguments))
        decoded = json.loads(base64.b64decode(instance.shell_kwargs["env_vars"]["ATTUNE_AD_INPUT_B64"]))
        self.assertEqual(attack, decoded["name"])
        self.assertEqual("example.com", decoded["target"]["domain_dns_name"])

    def test_timeout_terminates_one_command_without_resubmitting_mutation(self):
        FakeProtocol.timeout = True
        with (
            mock.patch.dict(sys.modules, winrm_modules()),
            mock.patch.object(client.time, "monotonic", side_effect=[0, 0, 6]),
            self.assertRaisesRegex(client.ActiveDirectoryPackError, "bounded timeout"),
        ):
            client._run_winrm(self.settings, {"operation": "user_get", "object_id": USER_ID}, 5)
        instance = FakeProtocol.instances[0]
        self.assertEqual([("shell-id", "command-id")], instance.cleaned)
        self.assertEqual(["shell-id"], instance.closed)

    def test_remote_errors_stderr_and_password_output_are_redacted(self):
        class FailedProtocol(FakeProtocol):
            def get_command_output_raw(self, shell_id, command_id):
                return b"", b"password=TOP-SECRET", 1, True

        modules = winrm_modules()
        modules["winrm.protocol"].Protocol = FailedProtocol
        with mock.patch.dict(sys.modules, modules), self.assertRaises(client.ActiveDirectoryPackError) as caught:
            client._run_winrm(self.settings, {"operation": "user_get", "object_id": USER_ID}, 30)
        self.assertNotIn("TOP-SECRET", str(caught.exception))
        FakeProtocol.output = {
            "operation": "user_get", "target_host": "dc01.example.com", "target_domain": "example.com",
            "data": {"unicodePwd": "TOP-SECRET"}, "meta": {"changed": False},
        }
        with mock.patch.dict(sys.modules, winrm_modules()), self.assertRaisesRegex(client.ActiveDirectoryPackError, "sensitive output"):
            client._run_winrm(self.settings, {"operation": "user_get", "object_id": USER_ID}, 30)

    def test_output_schema_operation_and_domain_are_bound(self):
        cases = [
            ({"operation": "user_get", "data": {}}, "unexpected output schema"),
            ({"operation": "user_delete", "target_host": "dc01.example.com", "target_domain": "example.com", "data": {}, "meta": {}}, "operation mismatch"),
            ({"operation": "user_get", "target_host": "dc02.example.com", "target_domain": "example.com", "data": {}, "meta": {}}, "host identity mismatch"),
            ({"operation": "user_get", "target_host": "dc01.example.com", "target_domain": "other.com", "data": {}, "meta": {}}, "domain identity mismatch"),
        ]
        for output, message in cases:
            FakeProtocol.output = output
            with self.subTest(message=message), mock.patch.dict(sys.modules, winrm_modules()), self.assertRaisesRegex(client.ActiveDirectoryPackError, message):
                client._run_winrm(self.settings, {"operation": "user_get", "object_id": USER_ID}, 30)


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location("activedirectory_action_test", ROOT / "actions" / "activedirectory_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        for raw, error in (("[]", None), ("x" * (client.MAX_INPUT_BYTES + 1), None), ('{"new_password":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))):
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(self.module, "execute_action", side_effect=error) if error else mock.patch.object(self.module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "activedirectory.user_get"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
