# Microsoft Active Directory Attune Pack

This pack translates the useful requirements of the Apache-2.0 StackStorm
Exchange Active Directory pack version `1.0.1` at signed revision
`2bdf09685f3d80e514eb5b586b344d41b35f063c`. It replaces 77 generic cmdlet
wrappers with 44 reviewed actions based on the current Windows Server 2025
ActiveDirectory module. See [SOURCE.md](SOURCE.md) for exact provenance and
Microsoft documentation verification.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- `pywinrm` with the declared Kerberos extra from [requirements.txt](requirements.txt).
- Kerberos client/runtime libraries and a worker ticket obtained outside this
  pack when Kerberos is used.
- A writable Windows Server 2019, 2022, or 2025 domain controller with the
  ActiveDirectory PowerShell module and a WinRM HTTPS listener.
- A listener certificate trusted by the worker and valid for the profile FQDN.
- A least-privilege account delegated only the required directory permissions.
- An encrypted, pack-owned Attune Key such as `activedirectory.credentials`.

The WinRM host must be the domain controller supplied to every AD cmdlet. This
avoids a remoting second hop. The pack does not configure WinRM, certificates,
AD Web Services, RSAT, domains, KDS roots, delegation, permissions, or firewall
policy. Read-only domain controllers and global catalog ports are not valid for
the complete action set.

## Credential Key

Kerberos is preferred. It uses the worker ticket cache and rejects a password
in the Key:

```json
{
  "host": "dc01.example.com",
  "port": 5986,
  "username": "svc-attune@EXAMPLE.COM",
  "auth": "kerberos",
  "verify_tls": true,
  "domain_dns_name": "example.com",
  "base_dn": "DC=example,DC=com",
  "allowed_search_bases": [
    "OU=Managed Users,DC=example,DC=com",
    "OU=Managed Computers,DC=example,DC=com",
    "OU=Managed Groups,DC=example,DC=com",
    "CN=Managed Service Accounts,DC=example,DC=com"
  ],
  "ca_cert": "-----BEGIN CERTIFICATE-----\nPRIVATE-CA-PEM\n-----END CERTIFICATE-----"
}
```

NTLM requires a password and verified HTTPS. Channel binding remains enabled:

```json
{
  "host": "dc01.example.com",
  "username": "EXAMPLE\\svc-attune",
  "password": "REDACTED",
  "auth": "ntlm",
  "verify_tls": true,
  "domain_dns_name": "example.com",
  "base_dn": "DC=example,DC=com",
  "allowed_search_bases": ["OU=Attune Managed,DC=example,DC=com"]
}
```

The Key rejects unknown fields, IP/URL hosts, plaintext WinRM, certificate
validation bypass, Basic, CredSSP, passwords with Kerberos, proxies, endpoint
overrides, and delegation controls. The runtime disables proxies and Kerberos
delegation. CredSSP is not needed because commands run on the selected DC; it
is rejected because it caches reusable credentials on the remote host.

No separate elevated-operation Key is implemented. Use separate pack-owned
profile Keys with independently delegated accounts when duties must be split,
and grant action execution permissions accordingly. A Key chooses identity and
scope; actions cannot request elevation or override credentials.

## Scope and Identity

The runtime verifies three independent identities before work:

- TLS validates the configured host certificate.
- PowerShell verifies the actual Windows host against the Key FQDN.
- `Get-ADDomain` verifies `domain_dns_name` and `base_dn` against that host.

Every supplied DN and every GUID-resolved object's DN must fall within an
`allowed_search_bases` subtree. Searches default to `base_dn` only when that DN
is itself allowed, accept only `Base`, `OneLevel`, or `Subtree`, and return at
most 500 objects. Search fields are modeled; a constant function RFC4515-
escapes values before constructing LDAP filters. Raw LDAP/PowerShell filters,
property lists, SIDs, SAM names as identities, and friendly-name mutation
selectors are not accepted. Mutations require a GUID or DN and `expected_host`.

## Transport Safety

Actions read one flat JSON object from stdin. `lib/activedirectory_client.py`
validates an exact field allowlist and puts base64-encoded structured JSON in
the WinRM shell environment. WinRM always executes the same reviewed
`lib/activedirectory.ps1` with PowerShell `-EncodedCommand`; action values never
enter the command line or script text.

Input is capped at 64 KiB, combined output at 4 MiB, and timeouts at 5 through
900 seconds. Timeout and output-limit paths terminate the command and close the
shell. Mutations are never retried. Remote messages and stderr are discarded;
only exception types reach stderr. Output is compact JSON:

```json
{
  "operation": "user_get",
  "target_host": "dc01.example.com",
  "target_domain": "example.com",
  "data": {"id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"},
  "meta": {"changed": false, "retried": false, "completed_at": "2026-08-15T00:00:00.0000000Z"}
}
```

`initial_password` and `new_password` are secret contract fields. They are
protected by verified TLS and WinRM authentication, immediately converted to
`SecureString` remotely, cleared from parsed parameters, never returned, and
blocked by an output-key denylist. Base64 is transport framing, not encryption;
Attune and worker access controls must protect action inputs and process memory.

## Actions

| Area | Actions |
|---|---|
| Users | `user_get`, `user_search`, `user_create`, `user_update`, `user_enable`, `user_disable`, `user_unlock`, `user_password_reset`, `user_expiration_set`, `user_delete` |
| Groups | `group_get`, `group_search`, `group_create`, `group_update`, `group_delete`, `group_member_add`, `group_member_remove`, `group_member_list` |
| Computers | `computer_get`, `computer_search`, `computer_create`, `computer_update`, `computer_enable`, `computer_disable`, `computer_move`, `computer_delete` |
| Organizational units | `ou_get`, `ou_search`, `ou_create`, `ou_update`, `ou_move`, `ou_delete` |
| Managed service accounts | `service_account_get`, `service_account_search`, `service_account_create`, `service_account_update`, `service_account_delete` |
| Domain and policy reads | `domain_get`, `forest_get`, `default_password_policy_get`, `fine_grained_password_policy_search`, `user_resultant_password_policy_get` |
| Safe principal reads | `principal_lookup`, `principal_group_memberships` |

Group membership reads are direct and bounded. Membership mutation rejects a
group as the member, preventing nested-group additions/removals and unexpected
recursive authorization effects. Existing child groups can be observed in
`group_member_list`, but never expanded.

## Confirmations

Confirmation comparison is case-sensitive and repeated in Python and on the
domain controller. IDs below are normalized GUIDs or the exact supplied DN:

- `DISABLE_USER:<host>:<object_id>`
- `RESET_PASSWORD:<host>:<object_id>`
- `DELETE_USER:<host>:<object_id>`
- `DELETE_GROUP:<host>:<object_id>`
- `ADD_GROUP_MEMBER:<host>:<group_id>:<member_id>`
- `REMOVE_GROUP_MEMBER:<host>:<group_id>:<member_id>`
- `DISABLE_COMPUTER:<host>:<object_id>`
- `MOVE_COMPUTER:<host>:<object_id>:<target_path_dn>`
- `DELETE_COMPUTER:<host>:<object_id>`
- `MOVE_OU:<host>:<object_id>:<target_path_dn>`
- `DELETE_OU:<host>:<object_id>`
- `DELETE_SERVICE_ACCOUNT:<host>:<object_id>`

All membership changes require confirmation, including privileged groups.
Delete actions do not expose recursive or force switches. OU deletion fails if
children exist or accidental-deletion protection applies. Moving an OU moves
its subtree because that is directory behavior; the exact source and target
confirmation is mandatory.

## Deliberate Gaps

- Cross-domain/forest, trust, RID/FSMO, schema, replication, GPO, ACL, SPN,
  delegation, authentication-policy, and optional-feature mutations are omitted.
- Recursive group expansion and nested group mutation are omitted. The pack
  cannot determine effective token membership across trusts or SID history.
- Service-account creation is gMSA only. Standalone MSA password operations,
  host install/uninstall, retrieval-principal mutation, Windows Server 2025
  delegated MSA migration, and KDS root creation are omitted.
- Password policy mutation and fine-grained policy subject mutation are omitted.
- User rename, computer rename, arbitrary attributes, `OtherAttributes`, bulk
  actions, raw filters, global catalog searches, AD LDS, snapshots, RODCs, and
  recycle-bin restore are omitted.
- Live validation is not performed by deterministic tests. Certificate PKI,
  DNS/SPNs, Kerberos tickets, AD Web Services, replication, schema differences,
  password policy, KDS state, and delegated ACLs remain deployment-specific.

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q actions lib tests
attune --output json pack check /home/david/Codebase/attune-packs/activedirectory
attune pack test /home/david/Codebase/attune-packs/activedirectory --detailed
```

Tests use the Python standard library and deterministic stubs. They require no
domain, Windows host, network, credentials, `pywinrm`, or undeclared package.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).
