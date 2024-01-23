# Spotlight

## Synopsis
This script was created to provide a full LDAP enumeration suite for objects stored in Active Directory. It allows for the enumeration of users, groups, domain and computers from an Active Directory LDAP server over either LDAPS or LDAP. 
Unlike current tools, this tool will enumerate infinite nested members for groups which are considered administrative

## Installation

### Kali

```
$ cd /path/to/spotlight
$ apt-get install ruby-dev build-essentials patch zlib1g-dev
$ gem install bundler
$ bundle install
```

### MacOS

```
$ cd /path/to/spotlight
$ gem install bundler
$ bundle install
```

### Windows (without Hashdump / Kerberoast support)

Install Ruby: https://rubyinstaller.org/
```
$ gem install bundler
$ bundle install
```

## Options

```
  -h, --host=<s>              Domain Controller IP / Hostname
  -u, --username=<s>          Domain Username
  -s, --user-dn=<s>           Use a DN rather than username and domain
  -p, --password=<s>          Domain Password
  -d, --domain=<s>            Domain Name
  -A, --all                   Do Everything
  -e, --queryuser=<s>         Query a single user
  -q, --querygroup=<s>        Query a single group
  -a, --admingroups           Enumerate common administrative groups
  -t, --enumtrusts            Enumerate Active Directory trusts
  -b, --usersandgroups        Enumerate all users and groups in the domain
  -H, --hashdump              Dump the groups user hashes, requires privs
  -c, --computers=<s>         Dump all domain-joined machines (options: all, workstations, servers, domaincontrollers)
  -o, --output                Output the datastores (Domain,Users,Groups,Computer) to excel
  -r, --restore=<s>           Restore from YAML log file
  -x, --external=<s>          List of usernames from external OSINT
  -n, --externalformat=<s>    Attribute to use for external username matches (options: samaccountname, email_address, username)
  -k, --kerberoast            Kerberoast the domain
  -R, --noresolve             Don't Resolve DNS Names
  --cracked=<s>               A list of cracked credentials from which to add to the users output
  --redacted                  Redact the output AND YAML
  -f, --fqdn=<s>              Manually override the FQDN, E.G. DC=some,DC=domain,DC=com
  -w, --rawldap=<s>           Run a custom LDAP query
  -v, --verbose               Dump RAW LDAP Output
  -l, --help                  Show this message
```

## Highlights

- Infinite nested group enumeration
- Full user enumeration
- Targeted Hashdump
- Detailed CSV output
- Domain joined machine enumeration (including LAPS credential enumeration)
- Domain forest enumeration

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


# FAQ

## I get "Invalid Credentials" when I try and authenticate but I know they're valid.

I don't have a definitive answer as to what exactly causes this, but you can specify the user's DN using --user-dn=<s> and ommit the username which should allow you to authenticate. You may also need to specify the FQDN.
You could also try authenticate using the UPN, set the user-dn to the UPN such as `username@domain.com`.
