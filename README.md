# Spotlight

## Synopsis
This script was created to provide a full LDAP enumeration suite for use of penetration tests. It allows for the enumeration of users, groups, forests and computers from an Active Directory LDAP server over either LDAP or LDAPS. Unlike current tools, this tool will enumerate infinite nested members for groups.


## Options
```
  -h, --host=<s>          Domain Controller IP / Hostname
  -u, --username=<s>      Domain Username
  -p, --password=<s>      Domain Password
  -d, --domain=<s>        Domain Name
  -A, --all               Do Everything
  -e, --queryuser=<s>     Query a single user
  -q, --querygroup=<s>    Query a single group
  -t, --enumtrusts        Enumerate Active Directory trusts
  -b, --usersandgroups    Enumerate all users and groups in the domain
  -H, --hashdump          Dump the groups user hashes, requires privs
  -c, --computers=<s>     Find all the domain joined machines (options: all, workstations, servers, domaincontrollers)
  -o, --output            Output the datastores (Domain,Users,Groups,Computer) to excel
  -r, --restore=<s>       Restore from YAML log file
  -x, --external=<s>      List of usernames from external OSINT
  -k, --kerberoast        Kerberoast the domain
  -R, --noresolve         Don't Resolve DNS Names
  -a, --cracked=<s>       A list of cracked credentials from which to add to the users output
  --redacted              Redact the output AND YAML
  -l, --help              Show this message

```
## Highlights
- Infinite nested group enumeration
- Full user enumeration
- Targeted Hashdump
- Detailed CSV output
- Domain joined machine enumeration
- Domain forest enumeration
- SPEED

### Targeted Hashdump
This function will perform a hashdump using secretsdump (from Impacket: https://github.com/CoreSecurity/impacket) to perform a DCSYNC style hashdump.
Any function in the script which enumerates users (every function except: enumtrusts and domaincomputers) will allow for the dumping of hashes.

### External OSINT
This function allows you to provide a list of users which were found from OSINT, this can be useful when identifying which accounts could be easily compromised from an external perspective.

### Domain Computers
This will query the domain for ALL domain-joined machines, this can then be further filtered dependant on the machine type. The FQDN for the host will then be used to perform a DNS resolution.

### Restore
Whenever SpotLight is run a log file (YAML) is produced which contains all the information which was gathered. Using this it is possible to create the relevant Excel files based on the data which was collected.

### Cracked Input
This feature will take output from JohnTheRipper and parse cracked credentials back into a Excel file.


## Example Usage

```
ruby ./spotlight.rb -h 192.168.0.253 -u administrator -p Password1 -d test -q "domain admins" -H
```
The above will connect to the host over LDAPS and enumerate the domain admins group, then perform a hashdump of the users in that group. Note ruby at the start of the command as the shebang confuses Kali (but not MacOS).
