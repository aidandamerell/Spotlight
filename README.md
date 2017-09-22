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
  -t, --tld=<s>                Top Level Domain, or any other DN value which
                               exist - E.G. child.parent.local (default: local)
  -g, --groupname=<s>          Name of group to enumerate
  -l, --ldaptype               Use unecrypted LDAP
  -m, --dumphashes             Dump the groups user hashes, account requires
                               domain administrative privilege
  -e, --enumgroups             Enumerate groups and member count
  -n, --enumtrusts             Enumerate Active Directory trusts
  -s, --enumallusers           Enumerate all users on the domain
  -q, --queryuser=<s>          Query the membership of a single user
  -o, --domaincomputers=<s>    Find all the domain joined machines (options:
                               all, workstations, servers, domaincontrollers)
  -c, --cracked=<s>            A list of cracked credentials from which to add
                               to the users output
  -v, --csv                    CSV output
  -r, --restore=<s>            Restore from YAML log file
  --help                       Show this message
```
## Highlights
- Infinite nested group enumeration
- Full user enumeration
- Targeted Hashdump
- Detailed CSV output
- Restore functionality (not fully implemented)
- Domain joined machine enumeration
- Domain forest enumeration
- SPEED

### Targeted Hashdump
This function will perform a hashdump using secretsdump (from Impacket: https://github.com/CoreSecurity/impacket) to perform a DCSYNC style hashdump.
Any function in the script which enumerates users (every function except: enumtrusts and domaincomputers) will allow for the dumping of hashes.

