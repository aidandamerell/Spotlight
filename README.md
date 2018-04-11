# Spotlight

## Synopsis
This script was created to provide a full LDAP enumeration suite for use of penetration tests. It allows for the enumeration of users, groups, forests and computers from an Active Directory LDAP server over either LDAP or LDAPS. Unlike current tools, this tool will enumerate infinite nested members for groups.


## Options
```
  -a, --all                    Do everything
  -h, --host=<s>               LDAP Host
  -u, --username=<s>           Domain Username
  -p, --password=<s>           Domain Password
  -d, --domain=<s>             Domain Name
  -g, --groupname=<s>          Name of group to enumerate
  -e, --enumgroups             Enumerate groups and member count
  -n, --enumtrusts             Enumerate Active Directory trusts
  -o, --nonestedmembers        Do not perform Nested Member of
  -m, --enumallusers           Enumerate all users on the domain
  -f, --findadmins             Find users who are Admins
  -q, --queryuser=<s>          Query the membership of a single user
  -s, --dumphashes             Dump the groups user hashes, account requires domain administrative privilege
  -i, --domaincomputers=<s>    Find all the domain joined machines (options: all, workstations, servers, domaincontrollers)
  -c, --cracked=<s>            A list of cracked credentials from which to add to the users output
  -v, --csv                    CSV output
  -r, --restore=<s>            Restore from YAML log file
  -t, --redacted               Output to CSV without sensitive information
  -x, --external=<s>           List of usernames from external OSINT
  -l, --help                   Show this message

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
This will query the domain for ALL domain-joined machines, this can then be further filtered dependant on the machine type. A future release will include a DNS resolution module for the names returned.

### Restore
Whenever SpotLight is run a log file (YAML) is produced which contains all the information which was gatherd. Using this it is possible to create the relevant CSV files based on the data which was collected.

### Cracked Input
This feature will take output from JohnTheRipper and parse cracked credentials back into a csv file.


## Example Usage

```
ruby ./spotlight.rb -h 192.168.0.253 -u administrator -p Password1 -d test -g "domain admins" -m
```
The above will connect to the host over LDAPS and enumerate the domain admins group, then perform a hashdump of the users in that group. Note ruby at the start of the command as the shebang confuses Kali (but not MacOS).
