# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-activedirectory
- Upstream pack version: `1.0.1`
- Version tag: `v1.0.1` points to the verified default-branch revision
- Verified revision: `2bdf09685f3d80e514eb5b586b344d41b35f063c`
- Revision date: `2022-04-06T16:52:52Z`
- Revision signature: GitHub reports `verified: true`, reason `valid`; local
  Git finds DSA key `E55911A29B43F870D8A485AF1A72D048C9AA75BE` but cannot verify it
  because the public key is not installed
- Revision tree: `572dd461fe65f29286b0531ea68fbb26dbf459f5`
- Upstream license: Apache License 2.0
- Upstream pack metadata author: Encore Technologies
- Upstream inventory: 77 generated YAML cmdlet wrappers, one generic action,
  and two transport/support modules

The source was inspected rather than copied wholesale. Its generic action
concatenates caller-controlled `args` into PowerShell, interpolates delegated
usernames/passwords into script text, treats port 5985 as HTTP, disables TLS
certificate validation, and returns raw stdout/stderr. Those implementation
patterns and the generated wrapper surface were not ported.

## Current Microsoft Behavior

The Windows Server 2025 ActiveDirectory module reference was reviewed on
2026-08-15. The module page and cited cmdlet pages report documentation source
commit `0ef3f225d29e26d1cf3119f37dfff70bb6165746` and page update
`2025-05-14T22:44:00Z`.

Behavior reflected in this pack:

- Current search cmdlets support `SearchBase`, `SearchScope` values `Base`,
  `OneLevel`, and `Subtree`, and bounded `ResultSetSize`. Raw `Filter` and
  `LDAPFilter` are intentionally replaced with modeled escaped fields.
- Identity cmdlets accept several friendly forms, but this pack narrows object
  selection to DN or GUID and then checks the resolved DN against profile scope.
- `Get-ADGroupMember` is direct unless `-Recursive` is supplied. This pack does
  not expose that switch and rejects group-as-member mutation.
- `Move-ADObject` can move containers and cross domains. This pack pins one DC,
  one domain, and one allowed target OU, and does not expose `TargetServer`.
- `Set-ADAccountPassword -Reset` consumes a `SecureString` and does not work on
  RODCs, snapshots, or a global catalog port. Password reset is user-only here.
- `New-ADServiceAccount` creates a gMSA by default and Windows Server 2025 adds
  delegated MSA creation/migration. This pack exposes only conservative gMSA
  creation and omits delegation and retrieval-principal mutation.
- AD cmdlets use the running identity unless `-Credential` is supplied and
  choose a server implicitly unless `-Server` is supplied. This pack never uses
  `-Credential` and explicitly pins every operation to the profiled DC.

Authoritative references:

- https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/move-adobject?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security
- https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop
- https://github.com/diyan/pywinrm/tree/v0.5.0

Current Microsoft remoting guidance says Kerberos authenticates both peers,
NTLM does not authenticate the server, and Kerberos/NTLM do not pass reusable
credentials for a second hop. It warns that CredSSP caches credentials on the
remote server. This pack therefore requires verified HTTPS in both modes,
enables NTLM channel binding, disables proxies and Kerberos delegation, rejects
CredSSP, and runs directly on the profiled domain controller.
