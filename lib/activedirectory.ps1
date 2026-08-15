$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
Set-StrictMode -Version 2.0

function Test-Value([string]$Name) {
    return $null -ne $script:Params.PSObject.Properties[$Name] -and $null -ne $script:Params.$Name
}

function Get-RequiredString([string]$Name, [int]$Maximum = 256) {
    if (-not (Test-Value $Name) -or -not ($script:Params.$Name -is [string]) -or
        [string]::IsNullOrEmpty($script:Params.$Name) -or $script:Params.$Name.Length -gt $Maximum) {
        throw [System.ArgumentException]::new('invalid structured string')
    }
    return [string]$script:Params.$Name
}

function Get-Identity([string]$Name = 'object_id') {
    $Value = Get-RequiredString $Name 2048
    $Guid = [guid]::Empty
    if ([guid]::TryParseExact($Value, 'D', [ref]$Guid)) { return $Guid }
    return $Value
}

function Get-Choice([string]$Name, [string[]]$Choices, [string]$Default = '') {
    $Value = if (Test-Value $Name) { [string]$script:Params.$Name } else { $Default }
    if ($Choices -cnotcontains $Value) { throw [System.ArgumentException]::new('invalid structured choice') }
    return $Value
}

function Get-Integer([string]$Name, [int]$Minimum, [int]$Maximum, [int]$Default) {
    $Value = if (Test-Value $Name) { $script:Params.$Name } else { $Default }
    if ($Value -is [bool] -or $Value -isnot [ValueType]) { throw [System.ArgumentException]::new('invalid structured integer') }
    $Parsed = [int]$Value
    if ($Parsed -lt $Minimum -or $Parsed -gt $Maximum) { throw [System.ArgumentOutOfRangeException]::new('structured integer out of range') }
    return $Parsed
}

function Test-DnWithin([string]$Dn, [string]$Base) {
    return $Dn.Equals($Base, [StringComparison]::OrdinalIgnoreCase) -or
        $Dn.EndsWith(',' + $Base, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-DnAllowed([string]$Dn) {
    foreach ($Base in @($script:Target.allowed_search_bases)) {
        if (Test-DnWithin $Dn ([string]$Base)) { return }
    }
    throw [System.InvalidOperationException]::new('directory object is outside allowed search bases')
}

function Get-SearchBase {
    $Base = if (Test-Value 'search_base') { Get-RequiredString 'search_base' 2048 } else { [string]$script:Target.base_dn }
    Assert-DnAllowed $Base
    return $Base
}

function ConvertTo-LdapFilterValue([string]$Value) {
    $Builder = [Text.StringBuilder]::new()
    foreach ($Byte in [Text.Encoding]::UTF8.GetBytes($Value)) {
        if ($Byte -eq 0 -or $Byte -eq 0x28 -or $Byte -eq 0x29 -or $Byte -eq 0x2a -or $Byte -eq 0x5c -or $Byte -lt 0x20 -or $Byte -gt 0x7e) {
            [void]$Builder.Append(('\{0:x2}' -f $Byte))
        } else { [void]$Builder.Append([char]$Byte) }
    }
    return $Builder.ToString()
}

function Get-CommonSearchArguments([string]$Filter, [string[]]$Properties) {
    return @{
        LDAPFilter = $Filter
        SearchBase = Get-SearchBase
        SearchScope = Get-Choice 'search_scope' @('Base', 'OneLevel', 'Subtree') 'Subtree'
        ResultSetSize = Get-Integer 'max_results' 1 500 100
        Properties = $Properties
        Server = [string]$script:Target.host
    }
}

function Assert-ResolvedObject($Object) {
    if ($null -eq $Object -or [string]::IsNullOrEmpty([string]$Object.DistinguishedName)) {
        throw [System.InvalidOperationException]::new('directory identity did not resolve')
    }
    Assert-DnAllowed ([string]$Object.DistinguishedName)
    return $Object
}

function Resolve-User { return Assert-ResolvedObject (Get-ADUser -Identity (Get-Identity) -Properties DisplayName,GivenName,Surname,Description,Mail,UserPrincipalName,Enabled,LockedOut,AccountExpirationDate,PasswordLastSet,PasswordExpired -Server $script:Target.host) }
function Resolve-Group([string]$Name = 'object_id') { return Assert-ResolvedObject (Get-ADGroup -Identity (Get-Identity $Name) -Properties DisplayName,Description,GroupCategory,GroupScope -Server $script:Target.host) }
function Resolve-Computer { return Assert-ResolvedObject (Get-ADComputer -Identity (Get-Identity) -Properties DNSHostName,Description,Location,Enabled,OperatingSystem,OperatingSystemVersion -Server $script:Target.host) }
function Resolve-OU([string]$Name = 'object_id') { return Assert-ResolvedObject (Get-ADOrganizationalUnit -Identity (Get-Identity $Name) -Properties Description,ProtectedFromAccidentalDeletion -Server $script:Target.host) }
function Resolve-ServiceAccount { return Assert-ResolvedObject (Get-ADServiceAccount -Identity (Get-Identity) -Properties DisplayName,Description,DNSHostName,Enabled,ManagedPasswordIntervalInDays,ServicePrincipalNames -Server $script:Target.host) }

function Convert-User($User) {
    return [ordered]@{
        id = $User.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $User.DistinguishedName
        name = $User.Name; sam_account_name = $User.SamAccountName; user_principal_name = $User.UserPrincipalName
        display_name = $User.DisplayName; given_name = $User.GivenName; surname = $User.Surname
        description = $User.Description; email = $User.Mail; enabled = [bool]$User.Enabled
        locked_out = [bool]$User.LockedOut
        account_expiration_utc = if ($null -eq $User.AccountExpirationDate) { $null } else { $User.AccountExpirationDate.ToUniversalTime().ToString('o') }
        password_last_set_utc = if ($null -eq $User.PasswordLastSet) { $null } else { $User.PasswordLastSet.ToUniversalTime().ToString('o') }
        password_expired = [bool]$User.PasswordExpired
    }
}

function Convert-Group($Group) {
    return [ordered]@{
        id = $Group.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $Group.DistinguishedName
        name = $Group.Name; sam_account_name = $Group.SamAccountName; display_name = $Group.DisplayName
        description = $Group.Description; group_scope = $Group.GroupScope.ToString(); group_category = $Group.GroupCategory.ToString()
    }
}

function Convert-Computer($Computer) {
    return [ordered]@{
        id = $Computer.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $Computer.DistinguishedName
        name = $Computer.Name; sam_account_name = $Computer.SamAccountName; dns_host_name = $Computer.DNSHostName
        description = $Computer.Description; location = $Computer.Location; enabled = [bool]$Computer.Enabled
        operating_system = $Computer.OperatingSystem; operating_system_version = $Computer.OperatingSystemVersion
    }
}

function Convert-OU($OU) {
    return [ordered]@{
        id = $OU.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $OU.DistinguishedName
        name = $OU.Name; description = $OU.Description
        protected_from_accidental_deletion = [bool]$OU.ProtectedFromAccidentalDeletion
    }
}

function Convert-ServiceAccount($Account) {
    return [ordered]@{
        id = $Account.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $Account.DistinguishedName
        name = $Account.Name; sam_account_name = $Account.SamAccountName; display_name = $Account.DisplayName
        dns_host_name = $Account.DNSHostName; description = $Account.Description; enabled = [bool]$Account.Enabled
        managed_password_interval_days = if ($null -eq $Account.ManagedPasswordIntervalInDays) { $null } else { [int]$Account.ManagedPasswordIntervalInDays }
        service_principal_names = @($Account.ServicePrincipalNames)
    }
}

function Convert-Principal($Principal) {
    $Classes = @($Principal.ObjectClass)
    $Sam = if ($null -eq $Principal.PSObject.Properties['SamAccountName']) { $null } else { $Principal.SamAccountName }
    $Upn = if ($null -eq $Principal.PSObject.Properties['UserPrincipalName']) { $null } else { $Principal.UserPrincipalName }
    return [ordered]@{
        id = $Principal.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $Principal.DistinguishedName
        name = $Principal.Name; object_class = if ($Classes.Count -eq 0) { $null } else { [string]$Classes[-1] }
        sam_account_name = $Sam; user_principal_name = $Upn
    }
}

function Convert-PasswordPolicy($Policy) {
    if ($null -eq $Policy) { return $null }
    return [ordered]@{
        distinguished_name = $Policy.DistinguishedName; name = $Policy.Name
        complexity_enabled = [bool]$Policy.ComplexityEnabled; reversible_encryption_enabled = [bool]$Policy.ReversibleEncryptionEnabled
        lockout_duration_seconds = [long]$Policy.LockoutDuration.TotalSeconds
        lockout_observation_window_seconds = [long]$Policy.LockoutObservationWindow.TotalSeconds
        lockout_threshold = [int]$Policy.LockoutThreshold; max_password_age_seconds = [long]$Policy.MaxPasswordAge.TotalSeconds
        min_password_age_seconds = [long]$Policy.MinPasswordAge.TotalSeconds; min_password_length = [int]$Policy.MinPasswordLength
        password_history_count = [int]$Policy.PasswordHistoryCount
        precedence = if ($null -eq $Policy.PSObject.Properties['Precedence']) { $null } else { [int]$Policy.Precedence }
    }
}

function Assert-Confirmation {
    $Confirmation = Get-RequiredString 'confirmation' 2048
    $Expected = switch ($script:Operation) {
        'user_disable' { 'DISABLE_USER:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'user_password_reset' { 'RESET_PASSWORD:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'user_delete' { 'DELETE_USER:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'group_delete' { 'DELETE_GROUP:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'group_member_add' { 'ADD_GROUP_MEMBER:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.group_id, $script:Params.member_id }
        'group_member_remove' { 'REMOVE_GROUP_MEMBER:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.group_id, $script:Params.member_id }
        'computer_disable' { 'DISABLE_COMPUTER:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'computer_move' { 'MOVE_COMPUTER:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.object_id, $script:Params.target_path_dn }
        'computer_delete' { 'DELETE_COMPUTER:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'ou_move' { 'MOVE_OU:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.object_id, $script:Params.target_path_dn }
        'ou_delete' { 'DELETE_OU:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
        'service_account_delete' { 'DELETE_SERVICE_ACCOUNT:{0}:{1}' -f $script:Params.expected_host, $script:Params.object_id }
    }
    if ($Confirmation -cne $Expected) { throw [System.InvalidOperationException]::new('destructive confirmation mismatch') }
}

function Assert-Target {
    $Candidates = @([string]$env:COMPUTERNAME)
    try { $Candidates += [Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { Write-Verbose 'FQDN lookup unavailable' }
    if (-not ($Candidates | Where-Object { $_ -ieq [string]$script:Target.host })) {
        throw [System.InvalidOperationException]::new('WinRM host identity mismatch')
    }
    $Domain = Get-ADDomain -Server $script:Target.host
    if ($Domain.DNSRoot -ine [string]$script:Target.domain_dns_name -or $Domain.DistinguishedName -ine [string]$script:Target.base_dn) {
        throw [System.InvalidOperationException]::new('Active Directory domain identity mismatch')
    }
    $script:VerifiedDomain = $Domain
}

function Write-Result($Data, [bool]$Changed = $false) {
    [ordered]@{
        operation = $script:Operation
        target_host = [string]$script:Target.host
        target_domain = [string]$script:VerifiedDomain.DNSRoot
        data = $Data
        meta = [ordered]@{ changed = $Changed; retried = $false; completed_at = [DateTime]::UtcNow.ToString('o') }
    } | ConvertTo-Json -Compress -Depth 10
}

try {
    if ([string]::IsNullOrEmpty($env:ATTUNE_AD_INPUT_B64)) { throw [System.ArgumentException]::new('missing structured input') }
    $InputBytes = [Convert]::FromBase64String($env:ATTUNE_AD_INPUT_B64)
    if ($InputBytes.Length -gt 65536) { throw [System.ArgumentOutOfRangeException]::new('structured input too large') }
    $script:Params = [Text.Encoding]::UTF8.GetString($InputBytes) | ConvertFrom-Json -ErrorAction Stop
    $env:ATTUNE_AD_INPUT_B64 = $null
    [Array]::Clear($InputBytes, 0, $InputBytes.Length)
    $script:Operation = Get-Choice 'operation' @(
        'user_get','user_search','user_create','user_update','user_enable','user_disable','user_unlock','user_password_reset','user_expiration_set','user_delete',
        'group_get','group_search','group_create','group_update','group_delete','group_member_add','group_member_remove','group_member_list',
        'computer_get','computer_search','computer_create','computer_update','computer_enable','computer_disable','computer_move','computer_delete',
        'ou_get','ou_search','ou_create','ou_update','ou_move','ou_delete',
        'service_account_get','service_account_search','service_account_create','service_account_update','service_account_delete',
        'domain_get','forest_get','default_password_policy_get','fine_grained_password_policy_search','user_resultant_password_policy_get',
        'principal_lookup','principal_group_memberships'
    )
    if ($null -eq $script:Params.PSObject.Properties['target']) { throw [System.ArgumentException]::new('missing trusted target profile') }
    $script:Target = $script:Params.target
    $script:Params.PSObject.Properties.Remove('target')
    Import-Module ActiveDirectory -ErrorAction Stop
    Assert-Target
    if ($script:Operation -in @(
        'user_disable','user_password_reset','user_delete','group_delete','group_member_add','group_member_remove',
        'computer_disable','computer_move','computer_delete','ou_move','ou_delete','service_account_delete'
    )) { Assert-Confirmation }

    switch ($script:Operation) {
        'user_get' { Write-Result (Convert-User (Resolve-User)) }
        'user_search' {
            $Parts = @('(objectCategory=person)', '(objectClass=user)')
            if (Test-Value 'name_prefix') { $Parts += '(name=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'name_prefix')) + '*)' }
            if (Test-Value 'sam_account_name') { $Parts += '(sAMAccountName=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'sam_account_name')) + ')' }
            if (Test-Value 'user_principal_name') { $Parts += '(userPrincipalName=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'user_principal_name')) + ')' }
            if (Test-Value 'enabled') {
                if ($script:Params.enabled -isnot [bool]) { throw [System.ArgumentException]::new('invalid structured boolean') }
                $Parts += if ([bool]$script:Params.enabled) { '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' } else { '(userAccountControl:1.2.840.113556.1.4.803:=2)' }
            }
            $Search = Get-CommonSearchArguments ('(&' + ($Parts -join '') + ')') @('DisplayName','GivenName','Surname','Description','Mail','UserPrincipalName','Enabled','LockedOut','AccountExpirationDate','PasswordLastSet','PasswordExpired')
            $Items = @(Get-ADUser @Search)
            Write-Result @($Items | Sort-Object DistinguishedName | ForEach-Object { Convert-User $_ })
        }
        'user_create' {
            $Path = Get-RequiredString 'path_dn' 2048; Assert-DnAllowed $Path
            $Arguments = @{ Name = Get-RequiredString 'name'; SamAccountName = Get-RequiredString 'sam_account_name'; Path = $Path; Server = $script:Target.host; Enabled = $false; PassThru = $true }
            foreach ($Pair in @(@('user_principal_name','UserPrincipalName'),@('display_name','DisplayName'),@('given_name','GivenName'),@('surname','Surname'),@('description','Description'),@('email','EmailAddress'))) {
                if (Test-Value $Pair[0]) { $Arguments[$Pair[1]] = Get-RequiredString $Pair[0] }
            }
            if (Test-Value 'initial_password') {
                $Arguments.AccountPassword = ConvertTo-SecureString (Get-RequiredString 'initial_password' 1024) -AsPlainText -Force
                $script:Params.initial_password = $null
            }
            if (Test-Value 'enabled') {
                if ($script:Params.enabled -isnot [bool]) { throw [System.ArgumentException]::new('invalid structured boolean') }
                $Arguments.Enabled = [bool]$script:Params.enabled
            }
            $Created = New-ADUser @Arguments
            $script:Params.object_id = $Created.ObjectGuid.ToString()
            Write-Result (Convert-User (Resolve-User)) $true
        }
        'user_update' {
            $User = Resolve-User; $Arguments = @{ Identity = $User; Server = $script:Target.host }
            foreach ($Pair in @(@('display_name','DisplayName'),@('given_name','GivenName'),@('surname','Surname'),@('description','Description'),@('email','EmailAddress'))) {
                if (Test-Value $Pair[0]) { $Arguments[$Pair[1]] = [string]$script:Params.($Pair[0]) }
            }
            Set-ADUser @Arguments; Write-Result (Convert-User (Resolve-User)) $true
        }
        'user_enable' { $User = Resolve-User; $Changed = -not [bool]$User.Enabled; if ($Changed) { Enable-ADAccount -Identity $User -Server $script:Target.host }; Write-Result (Convert-User (Resolve-User)) $Changed }
        'user_disable' { $User = Resolve-User; $Changed = [bool]$User.Enabled; if ($Changed) { Disable-ADAccount -Identity $User -Server $script:Target.host }; Write-Result (Convert-User (Resolve-User)) $Changed }
        'user_unlock' { $User = Resolve-User; $Changed = [bool]$User.LockedOut; if ($Changed) { Unlock-ADAccount -Identity $User -Server $script:Target.host }; Write-Result (Convert-User (Resolve-User)) $Changed }
        'user_password_reset' {
            $User = Resolve-User; $Secure = ConvertTo-SecureString (Get-RequiredString 'new_password' 1024) -AsPlainText -Force; $script:Params.new_password = $null
            Set-ADAccountPassword -Identity $User -Reset -NewPassword $Secure -Server $script:Target.host
            if (Test-Value 'force_change_at_logon') {
                if ($script:Params.force_change_at_logon -isnot [bool]) { throw [System.ArgumentException]::new('invalid structured boolean') }
                Set-ADUser -Identity $User -ChangePasswordAtLogon ([bool]$script:Params.force_change_at_logon) -Server $script:Target.host
            }
            Write-Result ([ordered]@{ id = $User.ObjectGuid.ToString().ToLowerInvariant(); distinguished_name = $User.DistinguishedName; password_reset = $true; force_change_at_logon = if (Test-Value 'force_change_at_logon') { [bool]$script:Params.force_change_at_logon } else { $null } }) $true
        }
        'user_expiration_set' {
            $User = Resolve-User
            if ((Test-Value 'clear_expiration') -and [bool]$script:Params.clear_expiration) { Clear-ADAccountExpiration -Identity $User -Server $script:Target.host }
            else {
                $Parsed = [DateTime]::ParseExact((Get-RequiredString 'expiration_utc' 20), 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
                Set-ADAccountExpiration -Identity $User -DateTime $Parsed -Server $script:Target.host
            }
            Write-Result (Convert-User (Resolve-User)) $true
        }
        'user_delete' { $User = Resolve-User; $Deleted = Convert-User $User; Remove-ADUser -Identity $User -Confirm:$false -Server $script:Target.host; Write-Result ([ordered]@{ deleted = $true; user = $Deleted }) $true }
        'group_get' { Write-Result (Convert-Group (Resolve-Group)) }
        'group_search' {
            $Parts = @('(objectCategory=group)')
            if (Test-Value 'name_prefix') { $Parts += '(name=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'name_prefix')) + '*)' }
            if (Test-Value 'sam_account_name') { $Parts += '(sAMAccountName=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'sam_account_name')) + ')' }
            if (Test-Value 'group_scope') {
                $Scope = Get-Choice 'group_scope' @('DomainLocal','Global','Universal')
                $ScopeBit = @{ DomainLocal = 4; Global = 2; Universal = 8 }[$Scope]
                $Parts += '(groupType:1.2.840.113556.1.4.803:=' + $ScopeBit + ')'
            }
            if (Test-Value 'group_category') {
                $Category = Get-Choice 'group_category' @('Distribution','Security')
                $SecurityClause = '(groupType:1.2.840.113556.1.4.803:=2147483648)'
                $Parts += if ($Category -ceq 'Security') { $SecurityClause } else { '(!' + $SecurityClause + ')' }
            }
            $Search = Get-CommonSearchArguments ('(&' + ($Parts -join '') + ')') @('DisplayName','Description','GroupCategory','GroupScope')
            $Items = @(Get-ADGroup @Search)
            Write-Result @($Items | Sort-Object DistinguishedName | ForEach-Object { Convert-Group $_ })
        }
        'group_create' {
            $Path = Get-RequiredString 'path_dn' 2048; Assert-DnAllowed $Path
            $Arguments = @{ Name = Get-RequiredString 'name'; SamAccountName = Get-RequiredString 'sam_account_name'; GroupScope = Get-Choice 'group_scope' @('DomainLocal','Global','Universal'); GroupCategory = Get-Choice 'group_category' @('Distribution','Security'); Path = $Path; Server = $script:Target.host; PassThru = $true }
            if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }
            $Created = New-ADGroup @Arguments; $script:Params.object_id = $Created.ObjectGuid.ToString(); Write-Result (Convert-Group (Resolve-Group)) $true
        }
        'group_update' {
            $Group = Resolve-Group; $Arguments = @{ Identity = $Group; Server = $script:Target.host }
            if (Test-Value 'display_name') { $Arguments.DisplayName = [string]$script:Params.display_name }; if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }
            Set-ADGroup @Arguments; Write-Result (Convert-Group (Resolve-Group)) $true
        }
        'group_delete' { $Group = Resolve-Group; $Deleted = Convert-Group $Group; Remove-ADGroup -Identity $Group -Confirm:$false -Server $script:Target.host; Write-Result ([ordered]@{ deleted = $true; group = $Deleted }) $true }
        'group_member_add' {
            $Group = Resolve-Group 'group_id'; $Member = Assert-ResolvedObject (Get-ADObject -Identity (Get-Identity 'member_id') -Properties ObjectGuid,ObjectClass,SamAccountName,UserPrincipalName -Server $script:Target.host)
            if (@($Member.ObjectClass)[-1] -ieq 'group') { throw [System.InvalidOperationException]::new('nested group membership changes are not supported') }
            $Existing = @(Get-ADGroupMember -Identity $Group -Server $script:Target.host | Where-Object { $_.ObjectGuid -eq $Member.ObjectGuid })
            $Changed = $Existing.Count -eq 0; if ($Changed) { Add-ADGroupMember -Identity $Group -Members $Member -Confirm:$false -Server $script:Target.host }
            Write-Result ([ordered]@{ group = Convert-Group $Group; member = Convert-Principal $Member; direct_member = $true; recursive = $false }) $Changed
        }
        'group_member_remove' {
            $Group = Resolve-Group 'group_id'; $Member = Assert-ResolvedObject (Get-ADObject -Identity (Get-Identity 'member_id') -Properties ObjectGuid,ObjectClass,SamAccountName,UserPrincipalName -Server $script:Target.host)
            if (@($Member.ObjectClass)[-1] -ieq 'group') { throw [System.InvalidOperationException]::new('nested group membership changes are not supported') }
            $Existing = @(Get-ADGroupMember -Identity $Group -Server $script:Target.host | Where-Object { $_.ObjectGuid -eq $Member.ObjectGuid })
            $Changed = $Existing.Count -eq 1; if ($Existing.Count -gt 1) { throw [System.InvalidOperationException]::new('direct membership did not resolve uniquely') }; if ($Changed) { Remove-ADGroupMember -Identity $Group -Members $Member -Confirm:$false -Server $script:Target.host }
            Write-Result ([ordered]@{ group = Convert-Group $Group; member = Convert-Principal $Member; direct_member = $false; recursive = $false }) $Changed
        }
        'group_member_list' {
            $Group = Resolve-Group 'group_id'; $Limit = Get-Integer 'max_results' 1 500 100
            $Members = @(Get-ADGroupMember -Identity $Group -Server $script:Target.host | Select-Object -First $Limit)
            foreach ($Member in $Members) { Assert-DnAllowed $Member.DistinguishedName }
            Write-Result ([ordered]@{ group = Convert-Group $Group; members = @($Members | Sort-Object DistinguishedName | ForEach-Object { Convert-Principal $_ }); recursive = $false; truncated_possible = $Members.Count -eq $Limit })
        }
        'computer_get' { Write-Result (Convert-Computer (Resolve-Computer)) }
        'computer_search' {
            $Parts = @('(objectCategory=computer)')
            if (Test-Value 'name_prefix') { $Parts += '(name=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'name_prefix')) + '*)' }
            if (Test-Value 'dns_host_name') { $Parts += '(dNSHostName=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'dns_host_name')) + ')' }
            if (Test-Value 'enabled') { if ([bool]$script:Params.enabled) { $Parts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' } else { $Parts += '(userAccountControl:1.2.840.113556.1.4.803:=2)' } }
            $Search = Get-CommonSearchArguments ('(&' + ($Parts -join '') + ')') @('DNSHostName','Description','Location','Enabled','OperatingSystem','OperatingSystemVersion')
            $Items = @(Get-ADComputer @Search)
            Write-Result @($Items | Sort-Object DistinguishedName | ForEach-Object { Convert-Computer $_ })
        }
        'computer_create' {
            $Path = Get-RequiredString 'path_dn' 2048; Assert-DnAllowed $Path; $Arguments = @{ Name = Get-RequiredString 'name'; Path = $Path; Server = $script:Target.host; Enabled = $false; PassThru = $true }
            if (Test-Value 'dns_host_name') { $Arguments.DNSHostName = Get-RequiredString 'dns_host_name' }; if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }; if (Test-Value 'enabled') { $Arguments.Enabled = [bool]$script:Params.enabled }
            $Created = New-ADComputer @Arguments; $script:Params.object_id = $Created.ObjectGuid.ToString(); Write-Result (Convert-Computer (Resolve-Computer)) $true
        }
        'computer_update' {
            $Computer = Resolve-Computer; $Arguments = @{ Identity = $Computer; Server = $script:Target.host }
            foreach ($Pair in @(@('dns_host_name','DNSHostName'),@('description','Description'),@('location','Location'))) { if (Test-Value $Pair[0]) { $Arguments[$Pair[1]] = [string]$script:Params.($Pair[0]) } }
            Set-ADComputer @Arguments; Write-Result (Convert-Computer (Resolve-Computer)) $true
        }
        'computer_enable' { $Computer = Resolve-Computer; $Changed = -not [bool]$Computer.Enabled; if ($Changed) { Enable-ADAccount -Identity $Computer -Server $script:Target.host }; Write-Result (Convert-Computer (Resolve-Computer)) $Changed }
        'computer_disable' { $Computer = Resolve-Computer; $Changed = [bool]$Computer.Enabled; if ($Changed) { Disable-ADAccount -Identity $Computer -Server $script:Target.host }; Write-Result (Convert-Computer (Resolve-Computer)) $Changed }
        'computer_move' { $Computer = Resolve-Computer; $TargetOU = Resolve-OU 'target_path_dn'; $Id = $Computer.ObjectGuid.ToString(); Move-ADObject -Identity $Computer -TargetPath $TargetOU.DistinguishedName -Confirm:$false -Server $script:Target.host; $script:Params.object_id = $Id; Write-Result (Convert-Computer (Resolve-Computer)) $true }
        'computer_delete' { $Computer = Resolve-Computer; $Deleted = Convert-Computer $Computer; Remove-ADComputer -Identity $Computer -Confirm:$false -Server $script:Target.host; Write-Result ([ordered]@{ deleted = $true; computer = $Deleted }) $true }
        'ou_get' { Write-Result (Convert-OU (Resolve-OU)) }
        'ou_search' {
            $Filter = '(objectCategory=organizationalUnit)'; if (Test-Value 'name_prefix') { $Filter = '(&' + $Filter + '(name=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'name_prefix')) + '*))' }
            $Search = Get-CommonSearchArguments $Filter @('Description','ProtectedFromAccidentalDeletion')
            $Items = @(Get-ADOrganizationalUnit @Search)
            Write-Result @($Items | Sort-Object DistinguishedName | ForEach-Object { Convert-OU $_ })
        }
        'ou_create' {
            $Path = Get-RequiredString 'path_dn' 2048; Assert-DnAllowed $Path; $Arguments = @{ Name = Get-RequiredString 'name'; Path = $Path; Server = $script:Target.host; PassThru = $true; ProtectedFromAccidentalDeletion = $true }
            if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }; if (Test-Value 'protected_from_accidental_deletion') { $Arguments.ProtectedFromAccidentalDeletion = [bool]$script:Params.protected_from_accidental_deletion }
            $Created = New-ADOrganizationalUnit @Arguments; $script:Params.object_id = $Created.ObjectGuid.ToString(); Write-Result (Convert-OU (Resolve-OU)) $true
        }
        'ou_update' {
            $OU = Resolve-OU; $Arguments = @{ Identity = $OU; Server = $script:Target.host }; if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }; if (Test-Value 'protected_from_accidental_deletion') { $Arguments.ProtectedFromAccidentalDeletion = [bool]$script:Params.protected_from_accidental_deletion }
            Set-ADOrganizationalUnit @Arguments; Write-Result (Convert-OU (Resolve-OU)) $true
        }
        'ou_move' { $OU = Resolve-OU; $TargetOU = Resolve-OU 'target_path_dn'; $Id = $OU.ObjectGuid.ToString(); Move-ADObject -Identity $OU -TargetPath $TargetOU.DistinguishedName -Confirm:$false -Server $script:Target.host; $script:Params.object_id = $Id; Write-Result (Convert-OU (Resolve-OU)) $true }
        'ou_delete' { $OU = Resolve-OU; $Deleted = Convert-OU $OU; Remove-ADOrganizationalUnit -Identity $OU -Confirm:$false -Server $script:Target.host; Write-Result ([ordered]@{ deleted = $true; organizational_unit = $Deleted; recursive = $false }) $true }
        'service_account_get' { Write-Result (Convert-ServiceAccount (Resolve-ServiceAccount)) }
        'service_account_search' {
            $Parts = @('(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))')
            if (Test-Value 'name_prefix') { $Parts += '(name=' + (ConvertTo-LdapFilterValue (Get-RequiredString 'name_prefix')) + '*)' }
            if (Test-Value 'enabled') { if ([bool]$script:Params.enabled) { $Parts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' } else { $Parts += '(userAccountControl:1.2.840.113556.1.4.803:=2)' } }
            $Search = Get-CommonSearchArguments ('(&' + ($Parts -join '') + ')') @('DisplayName','Description','DNSHostName','Enabled','ManagedPasswordIntervalInDays','ServicePrincipalNames')
            $Items = @(Get-ADServiceAccount @Search)
            Write-Result @($Items | Sort-Object DistinguishedName | ForEach-Object { Convert-ServiceAccount $_ })
        }
        'service_account_create' {
            $Path = Get-RequiredString 'path_dn' 2048; Assert-DnAllowed $Path; $Arguments = @{ Name = Get-RequiredString 'name'; DNSHostName = Get-RequiredString 'dns_host_name'; Path = $Path; Server = $script:Target.host; Enabled = $false; PassThru = $true }
            if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }; if (Test-Value 'enabled') { $Arguments.Enabled = [bool]$script:Params.enabled }; if (Test-Value 'managed_password_interval_days') { $Arguments.ManagedPasswordIntervalInDays = Get-Integer 'managed_password_interval_days' 1 365 30 }
            $Created = New-ADServiceAccount @Arguments; $script:Params.object_id = $Created.ObjectGuid.ToString(); Write-Result (Convert-ServiceAccount (Resolve-ServiceAccount)) $true
        }
        'service_account_update' {
            $Account = Resolve-ServiceAccount; $Arguments = @{ Identity = $Account; Server = $script:Target.host }; if (Test-Value 'display_name') { $Arguments.DisplayName = [string]$script:Params.display_name }; if (Test-Value 'description') { $Arguments.Description = [string]$script:Params.description }
            Set-ADServiceAccount @Arguments; Write-Result (Convert-ServiceAccount (Resolve-ServiceAccount)) $true
        }
        'service_account_delete' { $Account = Resolve-ServiceAccount; $Deleted = Convert-ServiceAccount $Account; Remove-ADServiceAccount -Identity $Account -Confirm:$false -Server $script:Target.host; Write-Result ([ordered]@{ deleted = $true; service_account = $Deleted }) $true }
        'domain_get' {
            $Domain = $script:VerifiedDomain; Write-Result ([ordered]@{ dns_root = $Domain.DNSRoot; distinguished_name = $Domain.DistinguishedName; netbios_name = $Domain.NetBIOSName; domain_mode = $Domain.DomainMode.ToString(); forest = $Domain.Forest; pdc_emulator = $Domain.PDCEmulator; rid_master = $Domain.RIDMaster; infrastructure_master = $Domain.InfrastructureMaster; replica_directory_servers = @($Domain.ReplicaDirectoryServers); read_only_replica_directory_servers = @($Domain.ReadOnlyReplicaDirectoryServers) })
        }
        'forest_get' {
            $Forest = Get-ADForest -Server $script:Target.host; Write-Result ([ordered]@{ name = $Forest.Name; root_domain = $Forest.RootDomain; forest_mode = $Forest.ForestMode.ToString(); domains = @($Forest.Domains); global_catalogs = @($Forest.GlobalCatalogs); schema_master = $Forest.SchemaMaster; domain_naming_master = $Forest.DomainNamingMaster; sites = @($Forest.Sites) })
        }
        'default_password_policy_get' { Write-Result (Convert-PasswordPolicy (Get-ADDefaultDomainPasswordPolicy -Identity $script:VerifiedDomain -Server $script:Target.host)) }
        'fine_grained_password_policy_search' { $Limit = Get-Integer 'max_results' 1 500 100; Write-Result @(Get-ADFineGrainedPasswordPolicy -Filter * -ResultSetSize $Limit -Server $script:Target.host | Sort-Object Precedence,Name | ForEach-Object { Convert-PasswordPolicy $_ }) }
        'user_resultant_password_policy_get' {
            $User = Resolve-User; $Policy = Get-ADUserResultantPasswordPolicy -Identity $User -Server $script:Target.host
            Write-Result ([ordered]@{ user = Convert-User $User; fine_grained_policy = Convert-PasswordPolicy $Policy; default_domain_policy = Convert-PasswordPolicy (Get-ADDefaultDomainPasswordPolicy -Identity $script:VerifiedDomain -Server $script:Target.host) })
        }
        'principal_lookup' {
            $Principal = Assert-ResolvedObject (Get-ADObject -Identity (Get-Identity) -Properties ObjectGuid,ObjectClass,SamAccountName,UserPrincipalName -Server $script:Target.host); Write-Result (Convert-Principal $Principal)
        }
        'principal_group_memberships' {
            $Principal = Assert-ResolvedObject (Get-ADObject -Identity (Get-Identity) -Properties ObjectGuid,ObjectClass,SamAccountName,UserPrincipalName -Server $script:Target.host); $Limit = Get-Integer 'max_results' 1 500 100
            $Groups = @(Get-ADPrincipalGroupMembership -Identity $Principal -Server $script:Target.host | Select-Object -First $Limit); foreach ($Group in $Groups) { Assert-DnAllowed $Group.DistinguishedName }
            $Converted = @($Groups | Sort-Object DistinguishedName | ForEach-Object { Convert-Group (Get-ADGroup -Identity $_ -Properties DisplayName,Description,GroupCategory,GroupScope -Server $script:Target.host) })
            Write-Result ([ordered]@{ principal = Convert-Principal $Principal; groups = $Converted; recursive = $false; truncated_possible = $Groups.Count -eq $Limit })
        }
    }
} catch {
    [Console]::Error.WriteLine(('ACTIVEDIRECTORY_OPERATION_FAILED:{0}' -f $_.Exception.GetType().FullName))
    exit 1
}
