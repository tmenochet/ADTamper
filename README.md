# ADTamper

ADTamper is a PowerShell tool for Active Directory exploitation.

## Functions

```
New-UserAccount                 -   creates a new Active Directory user in a given Active Directory domain
New-ComputerAccount             -   creates a new Active Directory computer in a given Active Directory domain
New-RogueAccount                -   creates a new Active Directory account (user or computer) by exploiting CVE-2021-34470
Set-UserPassword                -   modifies the password of a given Active Directory account
Set-LdapObject                  -   modifies properties for a given Active Directory object (e.g. members of a group)
Set-LdapObjectOwner             -   modifies the owner for a given Active Directory object
Set-LdapObjectAcl               -   adds or removes an ACL for a given Active Directory object
```
